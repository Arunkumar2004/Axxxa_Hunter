#!/usr/bin/env python3
"""Tests for the 7-question validity gate (tools/hunter/validate_gate.py)."""
from tools.hunter.contract import Finding, V_CONFIRMED, V_ISOLATED, V_PUBLIC
from tools.hunter.validate_gate import apply, gate


def _strong_idor():
    """A fully-evidenced, confirmed cross-account read - should be kept."""
    return Finding(
        cls="idor-bola",
        title="Cross-account read of another user's product via /api/product/{id}",
        severity="high",
        confidence="confirmed",
        axis="read",
        technique="cross-account-read",
        method="GET",
        url="https://api.mock.local/api/product/2/",
        evidence={"a_status": 200, "b_status": 200, "anon_status": 403,
                  "b_sees_a": True, "a_len": 120, "b_len": 120, "snippet": "owner=B"},
        verdict=V_CONFIRMED,
        repro=["Login as A", "GET /api/product/2/ with A's token",
               "Observe B's product returned"],
    )


def _public_finding():
    """A public/unauthenticated resource masquerading as a bug - should be killed."""
    return Finding(
        cls="info-disclosure",
        title="Catalog info endpoint returns data to anonymous users",
        severity="medium",
        confidence="tentative",
        technique="unauthenticated-read",
        method="GET",
        url="https://api.mock.local/api/public/info",
        evidence={"anon_status": 200, "a_status": 200, "b_status": 200, "anon_sees": True},
        verdict=V_PUBLIC,
        repro=["GET /api/public/info with no auth"],
    )


def test_strong_finding_passes_all_seven_questions():
    result = gate(_strong_idor())
    assert result["passed"] is True
    assert result["kill_reasons"] == []
    assert all(q["passed"] for q in result["questions"].values())
    assert set(result["questions"]) == {
        "reachable_now", "real_impact", "reproducible", "auth_boundary_crossed",
        "not_public_by_design", "evidence_present", "severity_justified",
    }


def test_public_finding_is_killed_for_being_public():
    result = gate(_public_finding())
    assert result["passed"] is False
    assert result["questions"]["not_public_by_design"]["passed"] is False
    assert any("public" in r for r in result["kill_reasons"])


def test_by_design_missing_header_is_killed_via_rejection_gate():
    # Reuses tools/rejection_gate: "missing CSP" is on the never-submit list.
    f = Finding(
        cls="missing-headers",
        title="Missing Content-Security-Policy header",
        severity="low",
        confidence="firm",
        technique="header-scan",
        url="https://mock.local/",
        evidence={"note": "CSP header absent"},
        repro=["curl -I https://mock.local/"],
    )
    result = gate(f)
    assert result["passed"] is False
    assert result["questions"]["not_public_by_design"]["passed"] is False


def test_isolated_access_control_is_killed():
    # Order endpoint that correctly 403s a non-owner must NOT survive the gate.
    f = Finding(
        cls="idor-bola",
        title="Attempted cross-account read of an order",
        severity="high",
        confidence="tentative",
        axis="read",
        url="https://api.mock.local/api/order/10/",
        evidence={"a_status": 200, "b_status": 403, "anon_status": 401, "b_sees_a": False},
        verdict=V_ISOLATED,
    )
    result = gate(f)
    assert result["passed"] is False
    assert result["questions"]["auth_boundary_crossed"]["passed"] is False


def test_overclaimed_severity_is_flagged():
    # Tentative confidence cannot justify a critical rating.
    f = Finding(
        cls="xss",
        title="Reflected value",
        severity="critical",
        confidence="tentative",
        evidence={"snippet": "reflected"},
        repro=["GET /api/echo?q=..."],
    )
    result = gate(f)
    assert result["questions"]["severity_justified"]["passed"] is False


def test_apply_splits_kept_from_killed_and_records_reasons():
    strong, public = _strong_idor(), _public_finding()
    kept, killed = apply([strong, public])

    assert kept == [strong]
    assert killed == [public]
    # The gate's reasons are merged onto the killed finding.
    assert public.kill_reasons
    assert any("public" in r for r in public.kill_reasons)
    # The kept finding is returned untouched.
    assert strong.kill_reasons == []


def test_apply_is_deterministic_and_idempotent_on_reasons():
    public = _public_finding()
    apply([public])
    first = list(public.kill_reasons)
    apply([public])  # running twice must not duplicate reasons
    assert public.kill_reasons == first


def test_apply_tolerates_none_entries():
    kept, killed = apply([None, _strong_idor(), None])
    assert len(kept) == 1
    assert killed == []
