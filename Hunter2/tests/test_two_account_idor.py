"""Tests for tools/two_account_idor.py — pure cross-account classification.

The HTTP layer is injected via a fake `fetch(url, headers) -> (status, body)`
so no network is touched. Each fake keys off the account marker in the auth
header to return canned responses for A, B, and anon.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.credential_store import CredentialStore
from tools.two_account_idor import (
    ISOLATED,
    POSSIBLE_IDOR,
    PUBLIC,
    run,
)
# Aliased so pytest does not collect the `test_endpoint` *function under test*
# as if it were a test case.
from tools.two_account_idor import test_endpoint as check_endpoint

URL = "https://api.target.com/users/123/orders"

# A's URL carries A's object id (123); these are the operator's own accounts.
A_HEADERS = {"Authorization": "Bearer TOKEN_A_SECRET"}
B_HEADERS = {"Authorization": "Bearer TOKEN_B_SECRET"}


def _account(headers):
    """Identify which account a request belongs to from its auth header."""
    auth = headers.get("Authorization", "")
    if "TOKEN_A" in auth:
        return "A"
    if "TOKEN_B" in auth:
        return "B"
    return "anon"


def _make_fetch(by_account):
    """Build a fake fetch returning canned (status, body) per account role."""
    def fetch(url, headers):
        return by_account[_account(headers)]
    return fetch


def test_cross_account_leak_is_possible_idor():
    # A id in url; B's auth returns A's exact body; anon is rejected.
    fetch = _make_fetch({
        "A": (200, '{"user":123,"orders":["a","b"]}'),
        "B": (200, '{"user":123,"orders":["a","b"]}'),
        "anon": (401, ""),
    })
    res = check_endpoint(URL, "GET", A_HEADERS, B_HEADERS, fetch=fetch)
    assert res["verdict"] == POSSIBLE_IDOR
    assert res["status_a"] == 200
    assert res["status_b"] == 200
    assert res["status_anon"] == 401


def test_proper_isolation_when_b_forbidden():
    fetch = _make_fetch({
        "A": (200, '{"user":123,"orders":["a","b"]}'),
        "B": (403, '{"error":"forbidden"}'),
        "anon": (401, ""),
    })
    res = check_endpoint(URL, "GET", A_HEADERS, B_HEADERS, fetch=fetch)
    assert res["verdict"] == ISOLATED


def test_public_resource_is_not_a_bug():
    # anon returns the same 200 body as A -> resource is public, not IDOR.
    body = "<html>public marketing page</html>"
    fetch = _make_fetch({
        "A": (200, body),
        "B": (200, body),
        "anon": (200, body),
    })
    res = check_endpoint(URL, "GET", A_HEADERS, B_HEADERS, fetch=fetch)
    assert res["verdict"] == PUBLIC


def test_length_ratio_similarity_still_flags_leak():
    # Bodies differ only by a rotating CSRF token (~few bytes) -> still a leak.
    fetch = _make_fetch({
        "A": (200, '{"user":123,"csrf":"aaaaaaaa","data":"secret-record-here"}'),
        "B": (200, '{"user":123,"csrf":"bbbbbbbb","data":"secret-record-here"}'),
        "anon": (401, ""),
    })
    res = check_endpoint(URL, "GET", A_HEADERS, B_HEADERS, fetch=fetch)
    assert res["verdict"] == POSSIBLE_IDOR


def test_raw_tokens_never_appear_in_result():
    fetch = _make_fetch({
        "A": (200, "AAAA"),
        "B": (200, "AAAA"),
        "anon": (401, ""),
    })
    res = check_endpoint(URL, "GET", A_HEADERS, B_HEADERS, fetch=fetch)
    blob = repr(res)
    assert "TOKEN_A_SECRET" not in blob
    assert "TOKEN_B_SECRET" not in blob
    # No header/auth material of any kind leaks into the finding.
    assert "Authorization" not in blob
    assert "Bearer" not in blob


def test_run_returns_empty_when_creds_absent(tmp_path):
    # Empty store (no .env file) -> harness cannot run, returns [].
    store = CredentialStore(tmp_path / "nonexistent.env")
    assert run([URL], store) == []


def test_run_iterates_endpoints_with_injected_fetch(tmp_path):
    env = tmp_path / ".env"
    env.write_text("ACCOUNT_A_TOKEN=TOKEN_A_SECRET\nACCOUNT_B_TOKEN=TOKEN_B_SECRET\n")
    store = CredentialStore(env)
    fetch = _make_fetch({
        "A": (200, "private-A"),
        "B": (200, "private-A"),
        "anon": (401, ""),
    })
    findings = run([URL], store, fetch=fetch, sleep=0)
    assert len(findings) == 1
    assert findings[0]["verdict"] == POSSIBLE_IDOR
    # Tokens from the store must not leak into findings either.
    assert "TOKEN_A_SECRET" not in repr(findings)


def test_run_skips_unsafe_methods_by_default(tmp_path):
    env = tmp_path / ".env"
    env.write_text("ACCOUNT_A_TOKEN=TOKEN_A_SECRET\nACCOUNT_B_TOKEN=TOKEN_B_SECRET\n")
    store = CredentialStore(env)
    fetch = _make_fetch({"A": (200, "x"), "B": (200, "x"), "anon": (401, "")})
    findings = run(["DELETE " + URL], store, fetch=fetch, sleep=0)
    assert len(findings) == 1
    assert findings[0]["verdict"] == "skipped_unsafe"
