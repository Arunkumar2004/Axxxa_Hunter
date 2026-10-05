"""Unit tests for the injection depth kit (tools/hunter/kits/injection.py).

Every test drives the kit with an inline fake ``fetch`` that returns
``contract.Resp`` objects, so the whole thing runs offline with no network and
no browser. The fake target below routes by path and reacts to the *decoded*
payload the kit injects, exercising the real detection/diff logic:

* ``/search`` reflects a parameter un-escaped   -> reflected XSS
* ``/safe``   reflects it HTML-escaped          -> no finding (FP guard)
* ``/item``   emits a MySQL error on a quote    -> error-based SQLi
* ``/clean``  never errors                       -> no finding (FP guard)
* ``/blind``  sleeps when a sleep payload lands  -> time-based blind (OOB-flagged)
* ``/login``  flips on a Mongo operator object   -> NoSQL operator injection
"""
import json
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from tools.hunter import contract
from tools.hunter.contract import Account, HuntContext
from tools.hunter.kits import injection


# --------------------------------------------------------------------------
# inline fake target
# --------------------------------------------------------------------------
def _resp(status, body, elapsed_ms=50.0):
    return contract.Resp(status=status, body=body, headers={}, elapsed_ms=elapsed_ms)


def _has_operator(body):
    """True when a JSON body smuggles a Mongo operator object (e.g. {"$ne": ...})."""
    if isinstance(body, dict):
        for v in body.values():
            if isinstance(v, dict) and any(str(k).startswith("$") for k in v):
                return True
            if _has_operator(v):
                return True
    return False


def router_fetch(method, url, headers=None, body=None):
    """A deliberately small vulnerable/clean fake target."""
    parsed = urlparse(url)
    path = parsed.path
    q = parse_qs(parsed.query, keep_blank_values=True)
    decoded = unquote(url).lower()

    if path == "/search":                       # reflected XSS (vulnerable)
        val = q.get("q", [""])[0]
        return _resp(200, f"<html><body><div>Results for: {val}</div></body></html>")

    if path == "/safe":                         # reflected but HTML-escaped (safe)
        val = q.get("q", [""])[0]
        esc = (val.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                  .replace('"', "&quot;").replace("'", "&#39;"))
        return _resp(200, f"<html><body><div>Results for: {esc}</div></body></html>")

    if path == "/item":                         # error-based SQLi (vulnerable)
        val = q.get("id", [""])[0]
        if any(ch in val for ch in ("'", '"', "\\")):
            return _resp(200, "Database error: You have an error in your SQL syntax; "
                              "check the manual that corresponds to your MySQL server "
                              "version for the right syntax near \"'\"")
        return _resp(200, "Item #1: Widget")

    if path == "/clean":                        # never errors (true negative)
        return _resp(200, "Item #1: Widget")

    if path == "/blind":                        # time-based blind (vulnerable)
        slow = any(tok in decoded for tok in ("sleep", "waitfor", "pg_sleep"))
        return _resp(200, "Item #1: Widget", elapsed_ms=6000.0 if slow else 40.0)

    if path == "/login":                        # NoSQL operator injection
        if _has_operator(body):
            return _resp(200, json.dumps({"token": "x", "user": {"id": 1}}) + " " * 400, 60.0)
        return _resp(401, '{"error":"invalid credentials"}', 55.0)

    return _resp(404, "not found")


def _run(endpoints, **ctx_kwargs):
    ctx = HuntContext(base_url="https://t.test", endpoints=list(endpoints),
                      fetch=router_fetch, **ctx_kwargs)
    return injection.InjectionKit().run(ctx)


# --------------------------------------------------------------------------
# applicability
# --------------------------------------------------------------------------
def test_applicable_true_when_params_present():
    kit = injection.InjectionKit()
    ctx = HuntContext(endpoints=[{"method": "GET", "url": "https://t.test/search?q=1"}],
                      fetch=router_fetch)
    assert kit.applicable(ctx) is True


def test_applicable_false_without_params():
    kit = injection.InjectionKit()
    ctx = HuntContext(endpoints=[{"method": "GET", "url": "https://t.test/health"}],
                      fetch=router_fetch)
    assert kit.applicable(ctx) is False
    assert kit.applicable(HuntContext(endpoints=[], fetch=router_fetch)) is False


def test_kit_registers_itself():
    reg = contract.registry()
    assert "injection" in reg
    assert reg["injection"].classes == ("sqli", "nosqli", "ssti", "xss", "cmdi", "xxe", "ldap")


# --------------------------------------------------------------------------
# XSS: reflected (unescaped) -> finding; escaped -> none
# --------------------------------------------------------------------------
def test_reflected_xss_unescaped_is_flagged():
    findings = _run([{"method": "GET", "url": "https://t.test/search?q=hello"}])
    xss = [f for f in findings if f.cls == "xss"]
    assert xss, "expected a reflected XSS finding when the payload echoes un-escaped"
    f = xss[0]
    assert "reflected" in f.technique
    assert "html" in f.evidence.get("contexts", [])
    assert f.evidence.get("payload")


def test_escaped_reflection_is_not_flagged():
    findings = _run([{"method": "GET", "url": "https://t.test/safe?q=hello"}])
    assert [f for f in findings if f.cls == "xss"] == []


# --------------------------------------------------------------------------
# SQLi: DB error -> finding; clean -> none
# --------------------------------------------------------------------------
def test_sqli_error_string_is_flagged():
    findings = _run([{"method": "GET", "url": "https://t.test/item?id=1"}])
    sqli = [f for f in findings if f.cls == "sqli"]
    assert sqli, "expected a SQLi finding on a response that leaks a DB error"
    err = [f for f in sqli if f.technique.startswith("error-based")]
    assert err and err[0].verdict == contract.V_CONFIRMED
    assert err[0].confidence == "confirmed"


def test_sqli_clean_response_is_not_flagged():
    findings = _run([{"method": "GET", "url": "https://t.test/clean?id=1"}])
    assert [f for f in findings if f.cls == "sqli"] == []


# --------------------------------------------------------------------------
# Time-based blind -> finding flagged for OOB confirmation
# --------------------------------------------------------------------------
def test_time_based_blind_is_flagged_for_oob():
    findings = _run([{"method": "GET", "url": "https://t.test/blind?id=1"}])
    blind = [f for f in findings if f.evidence.get("needs_oob")]
    assert blind, "expected a blind (time-based) finding needing OOB confirmation"
    for f in blind:
        assert f.kill_reasons, "a blind finding must not be report-ready (needs kill_reason)"
        assert f.evidence.get("delta_ms", 0) >= injection.SLEEP_MS * 0.7
    assert any(f.cls in ("sqli", "cmdi") and "time-blind" in f.technique for f in blind)


# --------------------------------------------------------------------------
# NoSQLi: operator-injection differential -> finding
# --------------------------------------------------------------------------
def test_nosqli_operator_injection_is_flagged():
    ep = {"method": "POST", "url": "https://t.test/login",
          "body": {"user": "a", "pass": "b"}}
    findings = _run([ep])
    nosqli = [f for f in findings if f.cls == "nosqli"]
    assert nosqli, "expected a NoSQL operator-injection finding on the login differential"
    assert any("operator" in f.technique for f in nosqli)


# --------------------------------------------------------------------------
# safety: auth headers are used for fetch but never leak into a Finding;
# destructive methods are never probed
# --------------------------------------------------------------------------
def test_auth_headers_never_leak_into_findings():
    ep = {"method": "GET", "url": "https://t.test/search?q=hello"}
    ctx = HuntContext(endpoints=[ep], fetch=router_fetch,
                      account_a=Account("A", {"Authorization": "Bearer SECRET-TOKEN-123"}))
    findings = injection.InjectionKit().run(ctx)
    assert findings, "sanity: the probe should still fire with auth set"
    blob = json.dumps([f.__dict__ for f in findings], default=str)
    assert "SECRET-TOKEN-123" not in blob
    assert "Authorization" not in blob


def test_destructive_method_is_skipped():
    ep = {"method": "DELETE", "url": "https://t.test/item?id=1"}
    kit = injection.InjectionKit()
    assert kit.applicable(HuntContext(endpoints=[ep], fetch=router_fetch)) is False
    assert kit.run(HuntContext(endpoints=[ep], fetch=router_fetch)) == []


def test_fetch_returning_none_does_not_crash():
    ep = {"method": "GET", "url": "https://t.test/search?q=1"}
    ctx = HuntContext(endpoints=[ep], fetch=lambda *a, **k: None)
    assert injection.InjectionKit().run(ctx) == []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
