"""Unit tests for the business-logic + race depth kit (kits/logic_race.py).

Every test drives the kit with an inline, dict-backed fake ``fetch`` that
returns ``contract.Resp`` objects, so the whole thing runs offline with no
network and no threads touching a real socket.  The fakes model just enough
server state to exercise the kit's real response-diff / state reasoning:

* an orders endpoint that trusts the client ``price``        -> price tamper
* the same endpoint recomputing the total server-side        -> no finding (FP)
* a cart endpoint where a negative quantity credits the user -> quantity tamper
* a coupon-redeem endpoint that only checks the limit before
  a (simulated) write window                                 -> race double-spend
* the same endpoint with an atomic check-and-increment       -> no finding (FP)
* a profile PUT that mass-assigns a client ``role``          -> role injection
* a checkout whose final step ignores its prerequisite       -> step-skip
"""
import json
import threading
import time
from urllib.parse import urlparse

import pytest

from tools.hunter import contract
from tools.hunter.contract import Account, HuntContext
from tools.hunter.kits import logic_race


def _ctx(endpoints, fetch, allow_write=False, **kw):
    return HuntContext(base_url="https://shop.test", endpoints=list(endpoints),
                       fetch=fetch, allow_write=allow_write, **kw)


# --------------------------------------------------------------------------
# inline fake targets
# --------------------------------------------------------------------------
def make_orders_fake(trust=True):
    """POST /api/orders. ``trust`` = the server uses the client-supplied price."""
    calls = []
    store = {}

    def fetch(method, url, headers=None, body=None):
        calls.append((method, url, body))
        path = urlparse(url).path
        if method == "POST" and path == "/api/orders":
            price = (body or {}).get("price")
            total = price if trust else 999      # untrusting server recomputes
            store["o1"] = {"price": price}
            return contract.Resp(200, json.dumps(
                {"order_id": "o1", "status": "created", "total": total}))
        if method == "DELETE" and path.startswith("/api/orders/"):
            store.pop(path.rsplit("/", 1)[-1], None)   # revert the created order
            return contract.Resp(204, "")
        return contract.Resp(404, "{}")

    fetch.calls = calls
    fetch.store = store
    return fetch


def make_cart_fake():
    """POST /api/cart/add. A negative quantity yields a negative total (credit)."""
    calls = []

    def fetch(method, url, headers=None, body=None):
        calls.append((method, url, body))
        path = urlparse(url).path
        if method == "POST" and path == "/api/cart/add":
            qty = (body or {}).get("quantity")
            total = (qty if isinstance(qty, (int, float)) else 0) * 200
            return contract.Resp(200, json.dumps(
                {"line_id": "l1", "quantity": qty, "total_paise": total}))
        if method == "DELETE" and path.startswith("/api/cart/add/"):
            return contract.Resp(204, "")
        return contract.Resp(404, "{}")

    fetch.calls = calls
    return fetch


def make_profile_fake():
    """PUT /api/users/me that mass-assigns a client-supplied ``role`` (the bug)."""
    calls = []
    store = {"name": None, "email": None, "role": "user", "is_verified": False}

    def fetch(method, url, headers=None, body=None):
        calls.append((method, url, body))
        if method == "PUT" and urlparse(url).path == "/api/users/me":
            b = body or {}
            store["name"] = b.get("name")
            store["email"] = b.get("email")
            store["role"] = b.get("role", "user")             # BUG: trusts client
            store["is_verified"] = bool(b.get("is_verified", False))
            return contract.Resp(200, json.dumps(dict(store)))
        return contract.Resp(404, "{}")

    fetch.calls = calls
    fetch.store = store
    return fetch


def make_checkout_fake():
    """A two-step checkout whose /confirm ignores the /address prerequisite."""
    calls = []

    def fetch(method, url, headers=None, body=None):
        calls.append((method, url, body))
        path = urlparse(url).path
        if method == "POST" and path == "/checkout/confirm":
            return contract.Resp(200, json.dumps(
                {"status": "confirmed", "order_id": "c9"}))   # BUG: no precondition
        if method == "POST" and path == "/checkout/address":
            return contract.Resp(200, json.dumps({"status": "address_saved"}))
        if method == "DELETE" and path.startswith("/checkout/confirm/"):
            return contract.Resp(204, "")
        return contract.Resp(404, "{}")

    fetch.calls = calls
    return fetch


class RacyRedeem:
    """Coupon redeem that checks the limit, then (after a window) writes it.

    No lock around the check-then-act, so parallel callers all read
    ``redeemed < limit`` before any increment lands -> double-spend.
    """

    def __init__(self, limit=1):
        self.redeemed = 0
        self.limit = limit
        self.calls = []
        self._calls_lock = threading.Lock()

    def __call__(self, method, url, headers=None, body=None):
        with self._calls_lock:
            self.calls.append((method, url))
        if method == "POST" and urlparse(url).path.endswith("/redeem"):
            seen = self.redeemed                 # time-of-check
            if seen < self.limit:
                time.sleep(0.05)                 # window the other workers slip through
                self.redeemed = seen + 1         # time-of-use (lost update)
                return contract.Resp(200, json.dumps({"ok": True, "reward_paise": 10000}))
            return contract.Resp(409, json.dumps({"error": "coupon already redeemed"}))
        return contract.Resp(404, "{}")


class LockedRedeem:
    """The fixed version: check-and-increment under a lock, so only one wins."""

    def __init__(self, limit=1):
        self.redeemed = 0
        self.limit = limit
        self.calls = []
        self._lock = threading.Lock()

    def __call__(self, method, url, headers=None, body=None):
        if method == "POST" and urlparse(url).path.endswith("/redeem"):
            with self._lock:
                self.calls.append((method, url))
                if self.redeemed < self.limit:
                    self.redeemed += 1
                    return contract.Resp(200, json.dumps({"ok": True}))
                return contract.Resp(409, json.dumps({"error": "already redeemed"}))
        return contract.Resp(404, "{}")


# --------------------------------------------------------------------------
# registration + applicability
# --------------------------------------------------------------------------
def test_kit_registers_itself():
    reg = contract.registry()
    assert "logic-race" in reg
    assert reg["logic-race"].classes == ("business-logic", "race-condition")


def test_applicable_true_on_post_or_workflow_surface():
    kit = logic_race.LogicRaceKit()
    assert kit.applicable(_ctx(
        [{"method": "POST", "url": "https://shop.test/api/orders"}], None)) is True
    assert kit.applicable(_ctx(                         # GET-only, but a cart surface
        [{"method": "GET", "url": "https://shop.test/cart/checkout"}], None)) is True


def test_applicable_false_without_mutating_or_workflow_surface():
    kit = logic_race.LogicRaceKit()
    assert kit.applicable(_ctx(
        [{"method": "GET", "url": "https://shop.test/api/items"}], None)) is False
    assert kit.applicable(_ctx([], None)) is False


# --------------------------------------------------------------------------
# price tampering: confirmed under allow_write, and auto-reverted
# --------------------------------------------------------------------------
def test_price_tamper_to_one_confirmed_and_reverted_under_allow_write():
    fetch = make_orders_fake(trust=True)
    ep = {"method": "POST", "url": "https://shop.test/api/orders",
          "body": {"sku": "ABC", "price": 999}}
    findings = logic_race.LogicRaceKit().run(_ctx([ep], fetch, allow_write=True))

    bl = [f for f in findings if f.cls == "business-logic"
          and f.technique == "price-tamper"]
    assert len(bl) == 1, findings
    f = bl[0]
    assert f.verdict == contract.V_CONFIRMED
    assert f.confidence == "confirmed"
    assert f.evidence["tampered_value"] == 1          # order total became 1
    assert f.evidence["expected"] == 999
    assert f.evidence["observed"] == {"total": 1}
    assert f.evidence["reverted"] is True
    assert f.kill_reasons == []
    # the revert actually issued a DELETE on the object the kit created
    assert any(m == "DELETE" for m, _u, _b in fetch.calls)


# --------------------------------------------------------------------------
# without allow_write: a POSSIBLE hypothesis, and NOT a single request sent
# --------------------------------------------------------------------------
def test_price_tamper_hypothesis_without_allow_write_makes_no_request():
    fetch = make_orders_fake(trust=True)
    ep = {"method": "POST", "url": "https://shop.test/api/orders",
          "body": {"sku": "ABC", "price": 999}}
    findings = logic_race.LogicRaceKit().run(_ctx([ep], fetch, allow_write=False))

    h = [f for f in findings if f.technique == "price-tamper"]
    assert len(h) == 1
    assert h[0].verdict == contract.V_POSSIBLE
    assert h[0].confidence == "tentative"
    assert h[0].kill_reasons                 # non-empty: needs allow_write
    assert fetch.calls == []                 # no mutation (indeed no request) performed


# --------------------------------------------------------------------------
# negative quantity -> store credit
# --------------------------------------------------------------------------
def test_negative_quantity_yields_credit_finding():
    fetch = make_cart_fake()
    ep = {"method": "POST", "url": "https://shop.test/api/cart/add",
          "body": {"product": "P1", "quantity": 3}}
    findings = logic_race.LogicRaceKit().run(_ctx([ep], fetch, allow_write=True))

    q = [f for f in findings if f.cls == "business-logic"
         and f.technique == "quantity-negative-credit"]
    assert len(q) == 1, findings
    f = q[0]
    assert f.verdict == contract.V_CONFIRMED
    assert f.evidence["tampered_value"] == -5
    observed = f.evidence["observed"]
    assert observed and list(observed.values())[0] < 0      # negative total (credit)
    assert f.evidence["reverted"] is True


# --------------------------------------------------------------------------
# race: parallel redeem double-spends under allow_write
# --------------------------------------------------------------------------
def test_race_parallel_redeem_double_spends_under_allow_write():
    fetch = RacyRedeem(limit=1)
    ep = {"method": "POST", "url": "https://shop.test/api/coupon/redeem",
          "body": {"code": "SAVE100"}}
    findings = logic_race.LogicRaceKit().run(_ctx([ep], fetch, allow_write=True))

    race = [f for f in findings if f.cls == "race-condition"]
    assert len(race) == 1, findings
    f = race[0]
    assert f.verdict == contract.V_CONFIRMED
    assert f.evidence["observed_successes"] > 1
    assert f.evidence["expected_successes"] == 1
    assert fetch.redeemed == 1        # lost update: counter says 1 though many won


def test_race_without_allow_write_is_a_hypothesis_only():
    fetch = RacyRedeem(limit=1)
    ep = {"method": "POST", "url": "https://shop.test/api/coupon/redeem",
          "body": {"code": "SAVE100"}}
    findings = logic_race.LogicRaceKit().run(_ctx([ep], fetch, allow_write=False))

    race = [f for f in findings if f.cls == "race-condition"]
    assert len(race) == 1
    assert race[0].verdict == contract.V_POSSIBLE
    assert race[0].confidence == "tentative"
    assert race[0].kill_reasons
    assert fetch.calls == []          # no burst fired without allow_write


# --------------------------------------------------------------------------
# false-positive guards
# --------------------------------------------------------------------------
def test_price_tamper_rejected_when_server_recomputes():
    fetch = make_orders_fake(trust=False)       # total is always 999, ignores client
    ep = {"method": "POST", "url": "https://shop.test/api/orders",
          "body": {"sku": "ABC", "price": 999}}
    findings = logic_race.LogicRaceKit().run(_ctx([ep], fetch, allow_write=True))

    assert [f for f in findings if f.technique == "price-tamper"] == []
    # it still probed (and reverted) rather than silently skipping
    assert any(m == "POST" for m, _u, _b in fetch.calls)
    assert any(m == "DELETE" for m, _u, _b in fetch.calls)


def test_race_properly_locked_endpoint_is_not_flagged():
    fetch = LockedRedeem(limit=1)
    ep = {"method": "POST", "url": "https://shop.test/api/coupon/redeem",
          "body": {"code": "X"}}
    findings = logic_race.LogicRaceKit().run(_ctx([ep], fetch, allow_write=True))

    assert [f for f in findings if f.cls == "race-condition"] == []
    assert fetch.redeemed == 1        # exactly one succeeded despite the burst


# --------------------------------------------------------------------------
# role/ownership field injection (mass assignment)
# --------------------------------------------------------------------------
def test_role_field_injection_confirmed_and_reverted():
    fetch = make_profile_fake()
    ep = {"method": "PUT", "url": "https://app.test/api/users/me",
          "body": {"name": "Bob", "email": "bob@x.test"}}
    findings = logic_race.LogicRaceKit().run(
        _ctx([ep], fetch, allow_write=True, scope_hosts=()))

    rf = [f for f in findings if f.technique == "role-field-injection"]
    assert len(rf) == 1, findings
    f = rf[0]
    assert f.verdict == contract.V_CONFIRMED
    assert f.evidence["reflected"]            # an elevated field took effect
    assert f.evidence["reverted"] is True
    # revert restored the original (non-privileged) state
    assert fetch.store["role"] == "user"
    assert fetch.store["is_verified"] is False


# --------------------------------------------------------------------------
# workflow step-skip / forced browsing
# --------------------------------------------------------------------------
def test_step_skip_forced_browsing_confirmed():
    fetch = make_checkout_fake()
    endpoints = [
        {"method": "POST", "url": "https://shop.test/checkout/address",
         "workflow": "checkout", "step": 1},
        {"method": "POST", "url": "https://shop.test/checkout/confirm",
         "workflow": "checkout", "step": 3, "body": {}},
    ]
    findings = logic_race.LogicRaceKit().run(_ctx(endpoints, fetch, allow_write=True))

    ss = [f for f in findings if f.technique == "step-skip-forced-browse"]
    assert len(ss) == 1, findings
    f = ss[0]
    assert f.verdict == contract.V_CONFIRMED
    assert f.evidence["prerequisite_skipped"] == "/checkout/address"
    # the prerequisite step was never called - only the final step was hit
    assert all(urlparse(u).path != "/checkout/address" for _m, u, _b in fetch.calls)


# --------------------------------------------------------------------------
# safety: auth headers are used for fetch but never leak into a Finding;
# a dead host (fetch -> None) must not crash the run
# --------------------------------------------------------------------------
def test_auth_headers_never_leak_into_findings():
    fetch = make_orders_fake(trust=True)
    ep = {"method": "POST", "url": "https://shop.test/api/orders",
          "body": {"sku": "ABC", "price": 999}}
    ctx = _ctx([ep], fetch, allow_write=True,
               account_a=Account("A", {"Authorization": "Bearer SECRET-TOKEN-123"}))
    findings = logic_race.LogicRaceKit().run(ctx)
    assert findings, "sanity: the probe should still fire with auth set"
    blob = json.dumps([f.__dict__ for f in findings], default=str)
    assert "SECRET-TOKEN-123" not in blob
    assert "Authorization" not in blob


def test_fetch_returning_none_does_not_crash():
    ep = {"method": "POST", "url": "https://shop.test/api/orders",
          "body": {"sku": "ABC", "price": 999}}
    ctx = _ctx([ep], lambda *a, **k: None, allow_write=True)
    assert logic_race.LogicRaceKit().run(ctx) == []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
