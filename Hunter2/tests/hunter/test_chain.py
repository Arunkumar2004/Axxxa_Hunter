#!/usr/bin/env python3
"""Tests for the chain builder (tools/hunter/chain.py)."""
from tools.hunter.chain import build_chains
from tools.hunter.contract import Finding, V_CONFIRMED


def _idor_finding():
    return Finding(
        cls="idor-bola",
        title="Cross-account read of another user's product",
        severity="high",
        confidence="confirmed",
        axis="read",
        technique="cross-account-read",
        method="GET",
        url="https://api.mock.local/api/product/2/",
        verdict=V_CONFIRMED,
    )


def _info_leak_finding():
    return Finding(
        cls="info-leak",
        title="User id and email disclosed in verbose error",
        severity="low",
        technique="verbose-error",
        url="https://api.mock.local/api/account/me",
    )


def test_single_idor_produces_next_steps_with_put_delete_followup():
    chains = build_chains([_idor_finding()])
    next_steps = [c for c in chains if c["kind"] == "next-steps"]
    assert next_steps, "every finding must yield a next-steps chain"

    ns = next_steps[0]
    assert ns["ranked_next"], "next-steps must list at least one concrete action"
    # chain_engine's idor table includes the PUT/DELETE follow-up.
    assert any("PUT/DELETE" in f["check"] for f in ns["ab_followups"])
    # Access-control class => sibling endpoints are derived and ranked first.
    assert ns["sibling_tests"]
    assert ns["ranked_next"][0].startswith("Test sibling endpoint")


def test_idor_has_named_escalation():
    chains = build_chains([_idor_finding()])
    escalations = [c for c in chains if c["kind"] == "escalation"]
    assert any(c["name"] == "idor-to-mass-enumeration" for c in escalations)


def test_two_findings_combine_into_ato_combo():
    chains = build_chains([_idor_finding(), _info_leak_finding()])
    combos = [c for c in chains if c["kind"] == "combo"]
    assert combos, "idor + info-leak must produce a cross-finding combo"

    combo = next(c for c in combos if c["name"] == "idor-plus-info-leak-to-ato")
    assert combo["impact"] == "Account takeover"
    assert combo["severity"] == "critical"
    assert len(combo["sources"]) == 2
    # Both source findings are referenced in the combo.
    classes = {s["cls"] for s in combo["sources"]}
    assert classes == {"idor-bola", "info-leak"}


def test_low_and_info_findings_are_still_chained():
    # Low/info findings are the glue of many chains - they must not be dropped.
    info = Finding(cls="info", title="Server banner discloses framework version",
                   severity="info")
    chains = build_chains([info])
    assert any(c["kind"] == "next-steps" for c in chains)


def test_open_redirect_escalates_to_oauth_token_theft():
    f = Finding(cls="open-redirect", title="Unvalidated next= parameter",
                severity="low", url="https://mock.local/api/redirect")
    chains = build_chains([f])
    assert any(c.get("name") == "open-redirect-to-oauth-token-theft"
               for c in chains if c["kind"] == "escalation")


def test_empty_and_none_inputs_are_safe():
    assert build_chains([]) == []
    assert build_chains(None) == []
    assert build_chains([None]) == []


def test_accepts_plain_dict_findings():
    # build_chains tolerates dicts as well as Finding dataclasses.
    chains = build_chains([{"cls": "idor", "url": "https://x.test/api/user/1/"}])
    assert any(c["kind"] == "next-steps" for c in chains)
