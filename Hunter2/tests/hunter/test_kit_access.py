"""Unit tests for the access-control depth kit (IDOR / BOLA / BFLA).

Every test drives the kit through an inline fake ``fetch`` (a function returning
``contract.Resp``), so nothing touches the network. Coverage:

  * true-positive cross-account read (B gets A's body)        -> one idor-bola
  * true-negative isolated endpoint (B denied)                -> no finding
  * public endpoint (anon == A)                               -> no finding
  * write-BOLA under allow_write, mutate + auto-revert         -> write, reverted
  * BFLA where a GET endpoint also exposes DELETE             -> bfla, DELETE
  * applicability gating, id-mutation enumeration, siblings    (extra coverage)
"""
import json
import os
import sys
from dataclasses import asdict

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tools.hunter.contract import (  # noqa: E402
    Account,
    HuntContext,
    Resp,
    V_CONFIRMED,
    V_POSSIBLE,
)
from tools.hunter.kits import access_control  # noqa: E402

KIT = access_control.AccessControlKit()

BASE = "https://api.target.com"
TARGET = BASE + "/users/1001/profile"
A_BODY = ('{"id":1001,"name":"alice","email":"alice@corp.example",'
          '"balance":4200}')

A = Account("A", {"Authorization": "Bearer secret-tokenA"})
B = Account("B", {"Authorization": "Bearer secret-tokenB"})


def _who(headers):
    """Identify the caller from the fake auth header (A / B / anon)."""
    auth = (headers or {}).get("Authorization", "")
    if auth.endswith("A"):
        return "A"
    if auth.endswith("B"):
        return "B"
    return "anon"


def make_ctx(fetch, allow_write=False, account_a=A, account_b=B, endpoints=None):
    return HuntContext(
        base_url=BASE,
        account_a=account_a,
        account_b=account_b,
        endpoints=endpoints if endpoints is not None else [{"method": "GET", "url": TARGET}],
        allow_write=allow_write,
        baseline=None,
        fetch=fetch,
    )


def _blob(findings):
    """Serialise findings so we can assert no secrets leaked into them."""
    return json.dumps([asdict(f) for f in findings])


# --------------------------------------------------------------------------- #
# 1. True-positive cross-account read.
# --------------------------------------------------------------------------- #
def test_cross_account_read_true_positive():
    def fetch(method, url, headers=None, body=None):
        who = _who(headers)
        if method == "GET" and url == TARGET:
            if who in ("A", "B"):
                return Resp(200, A_BODY)           # B reads A's object -> leak
            return Resp(403, '{"error":"forbidden"}')   # anon denied -> not public
        if method == "OPTIONS":
            return Resp(200, "")                   # no Allow header -> no BFLA noise
        return Resp(404, '{"error":"not found"}')  # id-variants / siblings

    ctx = make_ctx(fetch)
    assert KIT.applicable(ctx) is True

    findings = KIT.run(ctx)
    assert len(findings) == 1

    f = findings[0]
    assert f.cls == "idor-bola"
    assert f.axis == "read"
    assert f.verdict == V_POSSIBLE
    assert f.evidence["status_a"] == 200
    assert f.evidence["status_b"] == 200
    assert f.evidence["status_anon"] == 403

    # No raw auth tokens or oversized bodies ever reach a finding.
    blob = _blob(findings)
    assert "tokenA" not in blob and "tokenB" not in blob and "Bearer" not in blob
    assert len(f.evidence["snippet"]) <= 120


# --------------------------------------------------------------------------- #
# 2. True-negative: access control holds (B is denied).
# --------------------------------------------------------------------------- #
def test_isolated_endpoint_no_finding():
    def fetch(method, url, headers=None, body=None):
        who = _who(headers)
        if method == "GET" and url == TARGET:
            return Resp(200, A_BODY) if who == "A" else Resp(403, '{"error":"forbidden"}')
        if method == "OPTIONS":
            return Resp(200, "")
        return Resp(404, "{}")

    findings = KIT.run(make_ctx(fetch))
    assert findings == []


# --------------------------------------------------------------------------- #
# 3. Public resource (anon sees the same body as A) -> killed, not a bug.
# --------------------------------------------------------------------------- #
def test_public_resource_killed():
    def fetch(method, url, headers=None, body=None):
        if method == "GET" and url == TARGET:
            return Resp(200, A_BODY)               # everyone, including anon
        if method == "OPTIONS":
            return Resp(200, "")
        return Resp(404, "{}")

    findings = KIT.run(make_ctx(fetch))
    assert findings == []


# --------------------------------------------------------------------------- #
# 4. Cross-account WRITE/tamper under allow_write, with auto-revert.
# --------------------------------------------------------------------------- #
def test_write_bola_mutates_and_reverts():
    obj = {"id": 1001, "name": "alice-note", "owner": "A"}

    def fetch(method, url, headers=None, body=None):
        who = _who(headers)
        if url != TARGET:
            return Resp(404, "{}")
        if method == "GET":
            if who == "A":
                return Resp(200, json.dumps(obj))
            return Resp(403, "{}")                 # read is isolated; only write leaks
        if method == "PATCH":                      # the vulnerable verb: B may tamper
            if isinstance(body, dict):
                obj.update(body)
            return Resp(200, json.dumps(obj))
        if method == "PUT":
            return Resp(405, "{}")                 # PUT not allowed -> no extra finding
        if method == "OPTIONS":
            return Resp(200, "")
        return Resp(404, "{}")

    ctx = make_ctx(fetch, allow_write=True)
    findings = KIT.run(ctx)

    writes = [f for f in findings if f.axis == "write"]
    assert len(writes) == 1
    w = writes[0]
    assert w.cls == "idor-bola"
    assert w.severity == "critical"
    assert w.method == "PATCH"
    assert w.evidence["field"] == "name"
    assert w.evidence["changed"] is True
    assert w.evidence["reverted"] is True
    assert w.verdict == V_CONFIRMED
    assert w.kill_reasons == []

    # The target was restored to its original value.
    assert obj["name"] == "alice-note"
    # The canary marker is benign; no body/token content leaks.
    blob = _blob(findings)
    assert "tokenA" not in blob and "tokenB" not in blob


def test_write_bola_revert_failure_is_flagged():
    """If the kit cannot restore the original value, it records reverted=False
    and raises a kill reason rather than silently leaving the canary behind."""
    state = {"name": "alice-note"}

    def fetch(method, url, headers=None, body=None):
        who = _who(headers)
        if url != TARGET:
            return Resp(404, "{}")
        if method == "GET":
            if who == "A":
                return Resp(200, json.dumps(state))
            return Resp(403, "{}")
        if method == "PATCH":
            # Only the canary write "sticks"; any restore attempt is ignored.
            if isinstance(body, dict) and body.get("name", "").startswith("hunter-canary"):
                state["name"] = body["name"]
            return Resp(200, json.dumps(state))
        if method == "OPTIONS":
            return Resp(200, "")
        return Resp(404, "{}")

    findings = KIT.run(make_ctx(fetch, allow_write=True))
    writes = [f for f in findings if f.axis == "write"]
    assert len(writes) == 1
    assert writes[0].evidence["changed"] is True
    assert writes[0].evidence["reverted"] is False
    assert writes[0].kill_reasons  # non-empty: manual cleanup required


# --------------------------------------------------------------------------- #
# 5. BFLA: a GET endpoint also exposes DELETE (function-level auth gap).
# --------------------------------------------------------------------------- #
def test_bfla_get_endpoint_exposes_delete():
    def fetch(method, url, headers=None, body=None):
        who = _who(headers)
        if method == "OPTIONS" and url == TARGET:
            return Resp(204, "", {"Allow": "GET, HEAD, OPTIONS, DELETE"})
        if method == "GET" and url == TARGET:
            return Resp(200, A_BODY) if who == "A" else Resp(403, "{}")
        return Resp(404, "{}")

    ctx = make_ctx(fetch, allow_write=False)
    assert KIT.applicable(ctx) is True

    findings = KIT.run(ctx)
    bfla = [f for f in findings if f.cls == "bfla"]
    deletes = [f for f in bfla if f.method == "DELETE"]
    assert len(deletes) == 1

    d = deletes[0]
    assert d.axis == "bfla"
    assert d.technique == "options-allow-enumeration"
    assert "DELETE" in d.evidence["allow"]
    # DELETE was surfaced non-destructively; it must never have been fired.
    assert d.kill_reasons


# --------------------------------------------------------------------------- #
# Extra coverage: applicability gating.
# --------------------------------------------------------------------------- #
def test_applicable_requires_ids_and_account():
    dead = lambda *a, **k: Resp(404, "{}")  # noqa: E731

    # No id-bearing endpoint -> not applicable.
    ctx_no_id = make_ctx(dead, endpoints=[{"method": "POST", "url": BASE + "/login"}])
    assert KIT.applicable(ctx_no_id) is False

    # Id-bearing but no account A -> not applicable.
    ctx_no_a = make_ctx(dead, account_a=Account("A"), account_b=Account("B"))
    assert KIT.applicable(ctx_no_a) is False

    # Id-bearing + account A only (anon-vs-A) -> applicable.
    ctx_a_only = make_ctx(dead, account_a=A, account_b=Account("B"))
    assert KIT.applicable(ctx_a_only) is True


# --------------------------------------------------------------------------- #
# Extra coverage: id-mutation horizontal enumeration (as A).
# --------------------------------------------------------------------------- #
def test_idmut_enumeration_detects_foreign_object():
    neighbour = BASE + "/users/1002/profile"

    def fetch(method, url, headers=None, body=None):
        who = _who(headers)
        if method == "GET" and url == TARGET and who == "A":
            return Resp(200, A_BODY)
        if method == "GET" and url == neighbour and who == "A":
            return Resp(200, '{"id":1002,"name":"bob","email":"bob@corp.example"}')
        if method == "OPTIONS":
            return Resp(200, "")
        return Resp(404, "{}")

    findings = KIT.run(make_ctx(fetch))
    idmut = [f for f in findings if f.axis == "idmut"]
    assert len(idmut) == 1
    assert "numeric_plus1" in idmut[0].technique
    assert idmut[0].cls == "idor-bola"
    assert idmut[0].kill_reasons  # tentative: ownership must be confirmed


# --------------------------------------------------------------------------- #
# Extra coverage: sibling expansion + cross-account read.
# --------------------------------------------------------------------------- #
def test_sibling_cross_account_read():
    sibling = BASE + "/users/1001/export"

    def fetch(method, url, headers=None, body=None):
        who = _who(headers)
        if method == "GET" and url == TARGET:
            return Resp(200, A_BODY) if who == "A" else Resp(403, "{}")
        if method == "GET" and url == sibling:
            if who in ("A", "B"):
                return Resp(200, A_BODY)           # the sibling leaks to B
            return Resp(403, "{}")
        if method == "OPTIONS":
            return Resp(200, "")
        return Resp(404, "{}")

    findings = KIT.run(make_ctx(fetch))
    sib = [f for f in findings if f.axis == "sibling"]
    assert len(sib) == 1
    assert sib[0].url == sibling
    assert sib[0].cls == "idor-bola"
