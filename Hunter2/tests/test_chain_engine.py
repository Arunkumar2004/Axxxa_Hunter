"""Tests for tools/chain_engine.py — auto-chain after a confirmed bug (A->B + Sibling Rule)."""
import pytest

from tools import chain_engine


# --------------------------------------------------------------------------- #
# sibling_endpoints
# --------------------------------------------------------------------------- #
def test_sibling_endpoints_swaps_last_segment():
    res = chain_engine.sibling_endpoints("https://t.com/api/user/123/orders")
    assert "https://t.com/api/user/123/export" in res
    assert "https://t.com/api/user/123/delete" in res


def test_sibling_endpoints_excludes_original_and_dedupes():
    url = "https://t.com/api/user/123/orders"
    res = chain_engine.sibling_endpoints(url)
    assert url not in res                 # original excluded
    assert len(res) == len(set(res))      # no duplicates


def test_sibling_endpoints_preserves_query():
    res = chain_engine.sibling_endpoints("https://t.com/api/user/1/orders?foo=1")
    assert "https://t.com/api/user/1/export?foo=1" in res


def test_sibling_endpoints_version_swap():
    res = chain_engine.sibling_endpoints("https://t.com/api/v1/users")
    assert any("/api/v2/" in u for u in res)


def test_sibling_endpoints_no_clear_last_segment_does_not_crash():
    # Root URL — no obvious "last segment" to swap.
    res = chain_engine.sibling_endpoints("https://t.com/")
    assert isinstance(res, list)
    # Empty / non-string input is handled too.
    assert chain_engine.sibling_endpoints("") == []
    assert chain_engine.sibling_endpoints(None) == []


# --------------------------------------------------------------------------- #
# ab_followups
# --------------------------------------------------------------------------- #
def test_ab_followups_idor_has_put_delete_check():
    fu = chain_engine.ab_followups("idor")
    assert fu  # non-empty
    assert all("check" in f and "rationale" in f for f in fu)
    assert any(("put" in f["check"].lower()) or ("delete" in f["check"].lower()) for f in fu)


def test_ab_followups_unknown_class_returns_generic_fallback():
    fu = chain_engine.ab_followups("totally-unknown-xyz")
    assert fu  # still non-empty (generic fallback)


def test_ab_followups_oauth_not_swallowed_by_auth():
    # "oauth" contains the "auth" substring; it must map to the OAuth entries.
    fu = chain_engine.ab_followups("oauth no pkce")
    assert any("code" in f["check"].lower() or "csrf" in f["check"].lower() for f in fu)


# --------------------------------------------------------------------------- #
# chain
# --------------------------------------------------------------------------- #
def test_chain_idor_has_siblings_and_ranked_next():
    plan = chain_engine.chain({"vuln_class": "idor", "url": "https://t.com/api/user/1/orders"})
    assert plan["source"]["class"] == "idor"
    assert plan["sibling_tests"]      # non-empty
    assert plan["ab_followups"]       # non-empty
    assert plan["ranked_next"]        # non-empty
    # Access-control class -> siblings ranked first.
    assert plan["ranked_next"][0].startswith("Test sibling endpoint:")


def test_chain_generic_fallback_for_unknown_class():
    plan = chain_engine.chain({"vuln_class": "mystery", "url": "https://t.com/api/thing/1"})
    assert plan["ranked_next"]  # unknown class still yields next actions


def test_chain_accepts_vuln_type_and_endpoint_aliases():
    plan = chain_engine.chain({"vuln_type": "ssrf", "endpoint": "/api/fetch/1"})
    assert plan["source"]["class"] == "ssrf"
    # Non access-control class -> A->B follow-ups ranked ahead of siblings.
    assert not plan["ranked_next"][0].startswith("Test sibling endpoint:")


def test_chain_never_raises_on_odd_input():
    # Missing fields, wrong type, empty url — must not raise, must return a dict.
    for bad in ({}, None, {"url": ""}, {"vuln_class": "idor"}):
        plan = chain_engine.chain(bad)
        assert isinstance(plan, dict)
        assert plan["ranked_next"]  # generic fallback keeps it non-empty


# --------------------------------------------------------------------------- #
# main / CLI
# --------------------------------------------------------------------------- #
def test_main_human_readable_exit_zero(capsys):
    rc = chain_engine.main(["--class", "idor", "--url", "https://t.com/api/user/123/orders"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Chain plan" in out
    assert "export" in out


def test_main_json_output_exit_zero(capsys):
    rc = chain_engine.main(["--class", "idor", "--url", "https://t.com/api/user/1/orders", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    import json
    data = json.loads(out)
    assert data["source"]["class"] == "idor"
    assert data["ranked_next"]
