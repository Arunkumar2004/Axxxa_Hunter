"""Tests for the AUTH depth kit (tools/hunter/kits/auth.py).

All offline: a tiny inline fake ``fetch`` returning ``Resp(...)`` stands in for
the network, so no sockets are touched. Covered:
  * offline JWT weak-secret + forgeable-claim detection (no network);
  * forged-token replay -> CONFIRMED only under allow_write, and
    needs-verification/BLOCKED (never confirmed) without it;
  * a false-positive guard (forged token rejected -> not confirmed);
  * a Set-Cookie missing HttpOnly/SameSite is flagged;
  * raw tokens / secrets never leak into a Finding.
"""
import os
import sys

# repo root is three levels up from tests/hunter/<file>
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter.contract import (  # noqa: E402
    Account,
    HuntContext,
    Resp,
    V_CONFIRMED,
)
from tools.hunter.kits.auth import AuthKit  # noqa: E402
from tools.jwt_scanner import forge_hs256_with_key, _encode_segment  # noqa: E402

# "changeme" is in the kit's built-in weak list and is not a substring of any
# evidence label, so a redaction assertion on it is meaningful.
WEAK_SECRET = "changeme"


def _make_hs256(payload, secret=WEAK_SECRET):
    unsigned = "{}.{}.".format(
        _encode_segment({"alg": "HS256", "typ": "JWT"}),
        _encode_segment(payload),
    )
    return forge_hs256_with_key(unsigned, secret.encode())


def _ctx(**kw):
    kw.setdefault("scope_hosts", ())
    return HuntContext(**kw)


def _jwt_finding(findings):
    return next(f for f in findings if f.cls == "jwt")


# --- applicable -------------------------------------------------------------
def test_applicable_true_with_token():
    tok = _make_hs256({"user_id": 7})
    ctx = _ctx(account_a=Account("A", {"Authorization": "Bearer " + tok}))
    assert AuthKit().applicable(ctx) is True


def test_applicable_true_with_auth_endpoint_only():
    ctx = _ctx(endpoints=[{"method": "POST", "url": "https://app.test/login"}])
    assert AuthKit().applicable(ctx) is True


def test_applicable_false_without_auth_surface():
    ctx = _ctx(endpoints=[{"method": "GET", "url": "https://app.test/products"}])
    assert AuthKit().applicable(ctx) is False


# --- JWT offline ------------------------------------------------------------
def test_jwt_weak_secret_and_forgeable_claim_offline_no_network():
    calls = []

    def fetch(method, url, headers=None, body=None):
        calls.append((method, url))        # must never fire in the offline path
        return None

    tok = _make_hs256({"user_id": 42, "role": "user"})
    ctx = _ctx(account_a=Account("A", {"Authorization": "Bearer " + tok}),
               fetch=fetch, allow_write=False)
    f = _jwt_finding(AuthKit().run(ctx))

    assert f.evidence["weak_secret_cracked"] is True
    assert "user_id" in f.evidence["forgeable_claim_keys"]
    assert "role" in f.evidence["forgeable_claim_keys"]
    # offline only -> not confirmed, and no network was touched
    assert f.verdict != V_CONFIRMED
    assert f.confidence != "confirmed"
    assert calls == []
    # neither the raw token nor the cracked secret may appear in the finding
    blob = repr(f.__dict__)
    assert tok not in blob
    assert WEAK_SECRET not in blob


# --- forged-token replay ----------------------------------------------------
def _enforcing_fetch(method, url, headers=None, body=None):
    """No token -> 401; any bearer token present -> 200 (endpoint enforces auth
    but does not verify the signature)."""
    headers = headers or {}
    has_auth = any(k.lower() == "authorization" and v for k, v in headers.items())
    return Resp(status=200, body='{"id":1}') if has_auth else Resp(status=401, body="no")


def test_forged_replay_confirmed_under_allow_write():
    tok = _make_hs256({"user_id": 42, "role": "user"})
    prot = {"method": "GET", "url": "https://app.test/api/me"}
    ctx = _ctx(account_a=Account("A", {"Authorization": "Bearer " + tok}),
               endpoints=[prot], fetch=_enforcing_fetch, allow_write=True)
    f = _jwt_finding(AuthKit().run(ctx))

    assert f.verdict == V_CONFIRMED
    assert f.confidence == "confirmed"
    assert f.evidence["replay_status"] == 200
    assert f.evidence["noauth_status"] == 401
    assert not f.kill_reasons
    assert tok not in repr(f.__dict__)


def test_forged_replay_needs_verification_without_allow_write():
    tok = _make_hs256({"user_id": 42, "role": "user"})
    prot = {"method": "GET", "url": "https://app.test/api/me"}
    ctx = _ctx(account_a=Account("A", {"Authorization": "Bearer " + tok}),
               endpoints=[prot], fetch=_enforcing_fetch, allow_write=False)
    f = _jwt_finding(AuthKit().run(ctx))

    assert f.verdict != V_CONFIRMED
    assert f.confidence != "confirmed"
    assert f.evidence.get("needs_verification") is True
    assert "allow_write" in f.evidence.get("replay", "")


def test_forged_replay_rejected_is_not_confirmed():
    # false-positive guard: a properly verifying server rejects the forgery
    def fetch(method, url, headers=None, body=None):
        return Resp(status=401, body="unauthorized")

    tok = _make_hs256({"user_id": 42})
    prot = {"method": "GET", "url": "https://app.test/api/me"}
    ctx = _ctx(account_a=Account("A", {"Authorization": "Bearer " + tok}),
               endpoints=[prot], fetch=fetch, allow_write=True)
    f = _jwt_finding(AuthKit().run(ctx))

    assert f.verdict != V_CONFIRMED
    assert f.confidence != "confirmed"
    assert f.evidence["replay_status"] == 401


# --- session cookies --------------------------------------------------------
def test_set_cookie_missing_flags_is_flagged():
    def fetch(method, url, headers=None, body=None):
        return Resp(status=200, body="ok",
                    headers={"Set-Cookie": "sessionid=abc123; Path=/"})

    ctx = _ctx(base_url="https://app.test",
               endpoints=[{"method": "POST", "url": "https://app.test/login"}],
               fetch=fetch, allow_write=False)
    cookie = [f for f in AuthKit().run(ctx)
              if f.cls == "auth-session" and f.axis == "cookie-flags"]
    assert cookie, "expected a cookie-flags finding"
    missing = cookie[0].evidence["missing"]
    assert "httponly" in missing
    assert "samesite" in missing
    assert cookie[0].evidence["cookie_name"] == "sessionid"
    # the cookie value must not leak into the finding
    assert "abc123" not in repr(cookie[0].__dict__)


def test_set_cookie_all_flags_present_is_not_flagged():
    def fetch(method, url, headers=None, body=None):
        return Resp(status=200, body="ok", headers={
            "Set-Cookie": "sid=xyz; HttpOnly; Secure; SameSite=Strict"})

    ctx = _ctx(base_url="https://app.test", fetch=fetch)
    cookie = [f for f in AuthKit().run(ctx) if f.axis == "cookie-flags"]
    assert cookie == []
