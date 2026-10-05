"""Tests for tools/hunter/kits/client_side.py (the client-side depth kit).

Every test drives the kit through an INLINE fake ``fetch`` returning
``contract.Resp`` objects, so nothing touches the network. The fakes branch on
the presence of an ``Origin`` header to tell a CORS probe apart from a plain
page GET, and on an ``Upgrade`` header for the WebSocket handshake.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools.hunter import contract
from tools.hunter.contract import Account, Finding, HuntContext, Resp
from tools.hunter.kits.client_side import KIT, classify_clickjacking
from tools.spa_baseline import Baseline


def mkctx(fetch, endpoints=None, base_url="", account=None,
          baseline=None, allow_write=False, tech=None, scope=()):
    return HuntContext(
        base_url=base_url,
        scope_hosts=scope,
        endpoints=endpoints or [],
        account_a=account or Account("A"),
        fetch=fetch,
        baseline=baseline,
        allow_write=allow_write,
        tech=tech or {},
    )


def _valid_findings(findings):
    assert all(isinstance(f, Finding) for f in findings)
    assert all(f.severity in contract.SEVERITIES for f in findings)
    return findings


# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #
def test_cors_credentialed_reflection_is_high():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        origin = headers.get("Origin")
        if origin is not None:
            if origin == "https://evil.example":  # reflects attacker origin + creds
                return Resp(200, "{}", {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                })
            return Resp(200, "{}", {"Access-Control-Allow-Origin": "https://app.target.com"})
        return Resp(200, "ok", {"X-Frame-Options": "DENY"})

    ctx = mkctx(fetch, endpoints=[{"method": "GET", "url": "https://api.target.com/data"}])
    findings = _valid_findings(KIT.run(ctx))

    cors = [f for f in findings if f.cls == "cors"]
    highs = [f for f in cors if f.severity == "high"]
    assert highs, "expected a high CORS finding for credentialed arbitrary-origin reflection"
    ev = highs[0].evidence
    assert ev["access_control_allow_origin"] == "https://evil.example"
    assert ev["access_control_allow_credentials"] is True
    assert highs[0].verdict == contract.V_CONFIRMED
    # task spec: credentialed arbitrary-origin is HIGH, never surfaced as critical
    assert not any(f.severity == "critical" for f in cors)


def test_cors_wildcard_without_credentials_is_low_or_info():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if "Origin" in headers:
            return Resp(200, "{}", {"Access-Control-Allow-Origin": "*"})  # no ACAC
        return Resp(200, "ok", {"X-Frame-Options": "DENY"})

    ctx = mkctx(fetch, endpoints=[{"method": "GET", "url": "https://api.target.com/public"}])
    findings = _valid_findings(KIT.run(ctx))

    cors = [f for f in findings if f.cls == "cors"]
    assert cors, "ACAO:* should still be reported"
    assert all(f.severity in ("low", "info") for f in cors)
    assert not any(f.severity in ("high", "critical", "medium") for f in cors)


def test_cors_non_reflected_origin_is_not_a_finding():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if "Origin" in headers:  # server returns its own fixed allow-list origin
            return Resp(200, "{}", {"Access-Control-Allow-Origin": "https://app.target.com"})
        return Resp(200, "ok", {"X-Frame-Options": "DENY"})

    ctx = mkctx(fetch, endpoints=[{"method": "GET", "url": "https://api.target.com/data"}])
    findings = KIT.run(ctx)
    assert not [f for f in findings if f.cls == "cors"]


# --------------------------------------------------------------------------- #
# Clickjacking
# --------------------------------------------------------------------------- #
def test_clickjacking_missing_headers_on_sensitive_page():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if "Origin" in headers:
            return Resp(200, "{}", {})  # no ACAO -> no CORS finding
        return Resp(200, "<h1>Account</h1>", {})  # no XFO, no CSP

    ctx = mkctx(fetch, endpoints=[{"method": "GET", "url": "https://target.com/account"}])
    findings = _valid_findings(KIT.run(ctx))

    cj = [f for f in findings if f.cls == "clickjacking"]
    assert cj, "sensitive page with no X-Frame-Options and no frame-ancestors should be flagged"
    assert cj[0].severity == "medium"


def test_clickjacking_denied_page_is_not_flagged():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if "Origin" in headers:
            return Resp(200, "{}", {})
        return Resp(200, "<h1>Account</h1>", {"X-Frame-Options": "DENY"})

    ctx = mkctx(fetch, endpoints=[{"method": "GET", "url": "https://target.com/account"}])
    findings = KIT.run(ctx)
    assert not [f for f in findings if f.cls == "clickjacking"]


def test_classify_clickjacking_pure():
    assert classify_clickjacking(None, None) == "framable"
    assert classify_clickjacking("DENY", None) is None
    assert classify_clickjacking("SAMEORIGIN", None) is None
    assert classify_clickjacking(None, "frame-ancestors 'none'") is None
    assert classify_clickjacking(None, "frame-ancestors 'self'") is None
    assert classify_clickjacking(None, "frame-ancestors *") == "framable"      # permissive
    assert classify_clickjacking(None, "default-src 'self'") == "framable"     # no directive


# --------------------------------------------------------------------------- #
# CSRF
# --------------------------------------------------------------------------- #
_FORM_NO_TOKEN = (
    '<form method="post" action="/pay">'
    '<input name="amount"><input name="to"></form>'
)
_FORM_PROTECTED = (
    '<form method="post" action="/pay"><input name="amount">'
    '<input type="hidden" name="csrf_token" value="a1b2c3d4e5f6a7b8"></form>'
)


def test_csrf_state_changing_form_without_token_or_samesite():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if "Origin" in headers:
            return Resp(200, "{}", {})
        # X-Frame-Options:DENY keeps the sensitive-page clickjacking check quiet
        return Resp(200, _FORM_NO_TOKEN, {"X-Frame-Options": "DENY"})

    ctx = mkctx(fetch, endpoints=[{"method": "GET", "url": "https://target.com/account"}])
    findings = _valid_findings(KIT.run(ctx))

    csrf = [f for f in findings if f.cls == "csrf"]
    assert csrf, "form with no token and no SameSite should be flagged"
    assert csrf[0].severity == "high"
    assert csrf[0].axis == "write"


def test_csrf_protected_form_is_not_flagged():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if "Origin" in headers:
            return Resp(200, "{}", {})
        return Resp(200, _FORM_PROTECTED,
                    {"X-Frame-Options": "DENY", "Set-Cookie": "sid=1; SameSite=Lax; HttpOnly"})

    ctx = mkctx(fetch, endpoints=[{"method": "GET", "url": "https://target.com/account"}])
    findings = KIT.run(ctx)
    assert not [f for f in findings if f.cls == "csrf"]


# --------------------------------------------------------------------------- #
# postMessage  (declared class slug "hpp")
# --------------------------------------------------------------------------- #
def test_postmessage_listener_without_origin_check():
    page = ('<html><script>window.addEventListener("message", function(e){'
            ' document.getElementById("x").innerHTML = e.data; });</script></html>')

    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if "Origin" in headers:
            return Resp(200, "{}", {})
        return Resp(200, page, {"X-Frame-Options": "DENY"})

    ctx = mkctx(fetch, endpoints=[{"method": "GET", "url": "https://target.com/app"}])
    findings = _valid_findings(KIT.run(ctx))

    pm = [f for f in findings if f.cls == "hpp"]
    assert pm, "message listener with a dangerous sink and no origin check should be flagged"
    assert pm[0].severity == "high"
    assert pm[0].technique == "postmessage-missing-origin-check"


# --------------------------------------------------------------------------- #
# Prototype pollution (server-side, active)
# --------------------------------------------------------------------------- #
def test_prototype_pollution_server_reflection_is_high():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if "Origin" in headers:
            return Resp(200, "{}", {})
        m = re.search(r"__proto__\[([^\]]+)\]", url)
        if m:  # server reflects the injected canary property
            c = m.group(1)
            return Resp(200, '{"ok":true,"%s":"%s"}' % (c, c), {})
        return Resp(200, '{"ok":true}', {"X-Frame-Options": "DENY"})

    ctx = mkctx(fetch, endpoints=[{"method": "GET", "url": "https://api.target.com/profile"}])
    findings = _valid_findings(KIT.run(ctx))

    pp = [f for f in findings if f.cls == "prototype-pollution"]
    assert pp, "reflected __proto__ canary should be a server-side PP finding"
    assert pp[0].severity == "high"
    assert pp[0].method == "GET"  # read-only query-param probe, no write gate needed


def test_prototype_pollution_clean_endpoint_is_not_flagged():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if "Origin" in headers:
            return Resp(200, "{}", {})
        return Resp(200, '{"ok":true}', {"X-Frame-Options": "DENY"})

    ctx = mkctx(fetch, endpoints=[{"method": "GET", "url": "https://api.target.com/profile"}])
    findings = KIT.run(ctx)
    assert not [f for f in findings if f.cls == "prototype-pollution"]


# --------------------------------------------------------------------------- #
# CSWSH
# --------------------------------------------------------------------------- #
def test_cswsh_forged_origin_accepted_on_authenticated_socket():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if headers.get("Upgrade") == "websocket":  # accepts any Origin
            return Resp(101, "", {})
        return Resp(200, "ok", {})

    ctx = mkctx(
        fetch,
        endpoints=[{"method": "GET", "url": "wss://target.com/socket"}],
        account=Account("A", {"Cookie": "sid=supersecretvalue"}),
    )
    findings = _valid_findings(KIT.run(ctx))

    ws = [f for f in findings if f.cls == "websocket-cswsh"]
    assert ws, "forged-Origin handshake accepted on an authenticated socket is CSWSH"
    assert ws[0].severity == "high"
    assert ws[0].evidence["authenticated"] is True
    # the session cookie value must never be copied into a finding
    assert "supersecretvalue" not in str(ws[0].evidence)
    assert "supersecretvalue" not in str(ws[0].repro)


def test_cswsh_validated_origin_is_not_high():
    def fetch(method, url, headers=None, body=None):
        headers = headers or {}
        if headers.get("Upgrade") == "websocket":
            # forged Origin rejected, same-origin accepted
            return Resp(101 if headers.get("Origin") == "https://target.com" else 403, "", {})
        return Resp(200, "ok", {})

    ctx = mkctx(
        fetch,
        endpoints=[{"method": "GET", "url": "wss://target.com/socket"}],
        account=Account("A", {"Cookie": "sid=x"}),
    )
    findings = KIT.run(ctx)
    ws = [f for f in findings if f.cls == "websocket-cswsh"]
    assert all(f.severity != "high" for f in ws)


# --------------------------------------------------------------------------- #
# applicable / registry / baseline
# --------------------------------------------------------------------------- #
def test_applicable():
    assert KIT.applicable(mkctx(None, endpoints=[{"url": "https://x.test"}]))
    assert KIT.applicable(mkctx(None, base_url="https://x.test"))
    assert not KIT.applicable(mkctx(None))


def test_kit_is_registered_with_declared_classes():
    reg = contract.registry()
    assert "client-side" in reg
    kit = reg["client-side"]
    assert kit.name == "client-side"
    assert kit.classes == (
        "cors", "csrf", "clickjacking", "prototype-pollution", "hpp", "websocket-cswsh",
    )


def test_baseline_catchall_is_treated_as_noise():
    shell = "<html><body>application shell - not an endpoint</body></html>"
    baseline = Baseline([(200, shell)])

    def fetch(method, url, headers=None, body=None):
        return Resp(200, shell, {})  # every path returns the same catch-all shell

    ctx = mkctx(
        fetch,
        endpoints=[{"method": "GET", "url": "https://target.com/account"}],
        baseline=baseline,
    )
    assert KIT.run(ctx) == [], "catch-all responses must not produce findings"


def test_run_without_fetch_returns_empty():
    assert KIT.run(mkctx(None, endpoints=[{"url": "https://x.test"}])) == []


def test_no_state_changing_request_without_allow_write():
    # Record every method/url the kit issues; nothing may be a write when
    # allow_write is False (detection-only default).
    calls = []

    def fetch(method, url, headers=None, body=None):
        calls.append((method, url))
        headers = headers or {}
        if "Origin" in headers:
            return Resp(200, "{}", {})
        return Resp(200, "ok", {"X-Frame-Options": "DENY"})

    ctx = mkctx(fetch, endpoints=[
        {"method": "POST", "url": "https://api.target.com/profile"},
        {"method": "GET", "url": "https://api.target.com/data"},
    ])
    KIT.run(ctx)
    assert calls, "expected the kit to issue probes"
    assert all(method == "GET" for method, _url in calls), \
        "no state-changing request may be sent while allow_write is False"
