"""Tests for tools/feedback_loop.py — learning from real submission outcomes.

Storage is redirected to a tmp_path via the FEEDBACK_OUTCOMES_PATH env override
so these tests never touch real feedback memory.
"""

import json

import pytest

from tools import feedback_loop


@pytest.fixture
def outcomes_path(tmp_path, monkeypatch):
    """Redirect the outcomes store to a temp file for the duration of a test."""
    path = tmp_path / "feedback_outcomes.jsonl"
    monkeypatch.setenv(feedback_loop.OUTCOMES_ENV_VAR, str(path))
    # No BBHUNT_SESSION_ID unless a test opts in — keeps records deterministic.
    monkeypatch.delenv("BBHUNT_SESSION_ID", raising=False)
    return path


def test_record_then_load_round_trip(outcomes_path):
    assert feedback_loop.record_submission(
        "target.com", "idor", "two-account swap", "PAID",
        endpoint_pattern="/api/user/{id}/orders", severity="high",
        bounty=500, reason="v2 missing ownership check",
    ) is True

    records = feedback_loop.load_feedback(target="target.com")
    assert len(records) == 1
    rec = records[0]
    assert rec["target"] == "target.com"
    assert rec["vuln_class"] == "idor"
    assert rec["technique"] == "two-account swap"
    assert rec["outcome"] == "PAID"
    assert rec["endpoint_pattern"] == "/api/user/{id}/orders"
    assert rec["severity"] == "high"
    assert rec["bounty"] == 500
    assert rec["reason"] == "v2 missing ownership check"
    assert rec["schema_version"] == feedback_loop.CURRENT_SCHEMA_VERSION
    assert outcomes_path.exists()


def test_load_feedback_filters(outcomes_path):
    feedback_loop.record_submission("alpha.com", "idor", "id_swap", "PAID")
    feedback_loop.record_submission("beta.com", "idor", "uuid_brute", "REJECTED")
    feedback_loop.record_submission("beta.com", "ssrf", "dns_rebind", "DUPLICATE")

    assert len(feedback_loop.load_feedback()) == 3

    idor = feedback_loop.load_feedback(vuln_class="idor")
    assert len(idor) == 2
    assert {r["target"] for r in idor} == {"alpha.com", "beta.com"}

    beta = feedback_loop.load_feedback(target="beta.com")
    assert len(beta) == 2

    beta_ssrf = feedback_loop.load_feedback(vuln_class="ssrf", target="beta.com")
    assert len(beta_ssrf) == 1
    assert beta_ssrf[0]["technique"] == "dns_rebind"


def test_invalid_outcome_rejected_no_write(outcomes_path):
    assert feedback_loop.record_submission(
        "t.com", "idor", "id_swap", "ACCEPTED",  # not a valid outcome
    ) is False
    assert not outcomes_path.exists()
    assert feedback_loop.load_feedback() == []


def test_missing_required_fields_rejected(outcomes_path):
    assert feedback_loop.record_submission("", "idor", "id_swap", "PAID") is False
    assert feedback_loop.record_submission("t.com", "", "id_swap", "PAID") is False
    assert feedback_loop.record_submission("t.com", "idor", "", "PAID") is False
    assert not outcomes_path.exists()


def test_technique_scores_paid_beats_rejected(outcomes_path):
    # A technique that paid should outscore one that was rejected.
    feedback_loop.record_submission("t.com", "idor", "two-account swap", "PAID")
    feedback_loop.record_submission("t.com", "xss", "reflected param", "REJECTED")

    scores = feedback_loop.technique_scores()
    assert scores["idor"]["score"] > scores["xss"]["score"]
    assert "two-account swap" in scores["idor"]["paid"]
    assert "reflected param" in scores["xss"]["rejected"]
    # Formula: PAID*2 + INFORMATIVE - (REJECTED + DUPLICATE).
    assert scores["idor"]["score"] == 2
    assert scores["xss"]["score"] == -1


def test_technique_scores_formula_mixed(outcomes_path):
    feedback_loop.record_submission("t.com", "idor", "a", "PAID")
    feedback_loop.record_submission("t.com", "idor", "b", "INFORMATIVE")
    feedback_loop.record_submission("t.com", "idor", "c", "REJECTED")
    feedback_loop.record_submission("t.com", "idor", "d", "DUPLICATE")
    # 2 + 1 - 1 - 1 = 1
    assert feedback_loop.technique_scores()["idor"]["score"] == 1


def test_advise_for_hunt_boost_and_avoid(outcomes_path):
    feedback_loop.record_submission(
        "t.com", "idor", "two-account swap", "PAID", bounty=500,
    )
    feedback_loop.record_submission(
        "t.com", "xss", "reflected param", "REJECTED", reason="WAF blocks it",
    )
    feedback_loop.record_submission(
        "t.com", "ssrf", "dns_rebind", "DUPLICATE",
    )

    advice = feedback_loop.advise_for_hunt("t.com")
    assert set(advice.keys()) == {"boost", "avoid"}

    boost_techs = {b["technique"] for b in advice["boost"]}
    avoid_techs = {a["technique"] for a in advice["avoid"]}
    assert "two-account swap" in boost_techs
    assert "reflected param" in avoid_techs
    assert "dns_rebind" in avoid_techs

    # Boost advice carries the bounty signal; avoid advice carries the reason.
    paid = next(b for b in advice["boost"] if b["technique"] == "two-account swap")
    assert "500" in paid["why"]
    rej = next(a for a in advice["avoid"] if a["technique"] == "reflected param")
    assert "WAF blocks it" in rej["why"]


def test_advise_for_hunt_target_filter(outcomes_path):
    feedback_loop.record_submission("a.com", "idor", "id_swap", "PAID")
    feedback_loop.record_submission("b.com", "xss", "stored xss", "PAID")

    advice = feedback_loop.advise_for_hunt("a.com")
    boost_techs = {b["technique"] for b in advice["boost"]}
    assert boost_techs == {"id_swap"}


def test_paid_technique_not_also_avoided(outcomes_path):
    # Same technique paid once and rejected once — money wins, so it is boosted
    # and must NOT also appear under avoid.
    feedback_loop.record_submission("t.com", "idor", "id_swap", "PAID")
    feedback_loop.record_submission("t.com", "idor", "id_swap", "REJECTED")

    advice = feedback_loop.advise_for_hunt("t.com")
    assert any(b["technique"] == "id_swap" for b in advice["boost"])
    assert all(a["technique"] != "id_swap" for a in advice["avoid"])


def test_no_secrets_only_allowed_keys_persisted(outcomes_path):
    # Even if a caller stuffs a token-like value into a free-text field, the
    # stored record must only ever carry the allowed keys — no blob can widen it.
    token_like = "Bearer eyJhbGciOiJIUzI1NiJ9.aaaa.bbbb password=hunter2 sk_live_ABC"
    assert feedback_loop.record_submission(
        "t.com", "idor", token_like, "PAID", reason=token_like, severity=token_like,
    ) is True

    lines = outcomes_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    stored = json.loads(lines[0])
    assert set(stored.keys()) <= feedback_loop.ALLOWED_KEYS
    for forbidden in ("cookie", "token", "authorization", "password", "body",
                      "request", "response", "headers"):
        assert forbidden not in stored


def test_session_id_recorded_when_authenticated(outcomes_path, monkeypatch):
    monkeypatch.setenv("BBHUNT_SESSION_ID", "abc123def456")
    assert feedback_loop.record_submission("t.com", "idor", "id_swap", "PAID") is True
    rec = feedback_loop.load_feedback(target="t.com")[0]
    assert rec["session_id"] == "abc123def456"
    assert set(rec.keys()) <= feedback_loop.ALLOWED_KEYS


def test_load_missing_file_returns_empty(outcomes_path):
    assert not outcomes_path.exists()
    assert feedback_loop.load_feedback() == []
    assert feedback_loop.load_feedback(vuln_class="idor") == []
    assert feedback_loop.technique_scores() == {}
    assert feedback_loop.advise_for_hunt("t.com") == {"boost": [], "avoid": []}


def test_negative_bounty_coerced(outcomes_path):
    assert feedback_loop.record_submission(
        "t.com", "idor", "id_swap", "PAID", bounty=-100,
    ) is True
    assert feedback_loop.load_feedback(target="t.com")[0]["bounty"] == 0
