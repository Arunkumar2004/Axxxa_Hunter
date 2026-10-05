"""client_side.py - the client-side depth kit for the Hunter Engine.

Covers the browser-trust family: CORS, CSRF, clickjacking, prototype pollution,
postMessage, and cross-site WebSocket hijacking (CSWSH).

It *drives the existing scanners' pure classifiers* rather than re-implementing
them (hard rule: reuse, don't re-implement):

  * tools.cors_scanner                 - generate_tests / classify
  * tools.csrf_scanner                 - parse_forms / samesite_strength / classify_form
  * tools.prototype_pollution_scanner  - analyze_js / classify_active
  * tools.hpp_postmessage_scanner      - analyze_postmessage
  * tools.websocket_scanner            - classify

Every request goes through ``ctx.fetch`` (the injected, SSRF-safe, mockable
fetcher) so the whole kit is unit-testable offline. The kit is detection-only:
no state-changing request is sent unless ``ctx.allow_write`` is True, and the
only method that is ever gated there is the prototype-pollution JSON ``POST``
probe - every other probe is a read (``GET``). No secrets (cookies/tokens) are
copied into findings.

The declared class slug ``hpp`` is realised here by the postMessage detector
from ``hpp_postmessage_scanner`` (missing-origin message listeners); that module
is the shared home of both checks.
"""
from __future__ import annotations

import base64
import os
import re
import sys
from urllib.parse import urljoin, urlparse, urlunparse

# Ensure the repo root is importable when the engine loads this module by path,
# before the `tools.*` imports below run (matches the other tools' bootstrap).
_REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter.contract import (  # noqa: E402
    Finding,
    V_CONFIRMED,
    V_INCONCLUSIVE,
    V_POSSIBLE,
    register,
)
from tools import cors_scanner  # noqa: E402
from tools import csrf_scanner  # noqa: E402
from tools import hpp_postmessage_scanner as hpp  # noqa: E402
from tools import prototype_pollution_scanner as pp  # noqa: E402
from tools import websocket_scanner as wss  # noqa: E402

# Bounds so a real run cannot fan out without limit (tests stay well under).
_MAX_APIS = 30
_MAX_PAGES = 20
_MAX_JS = 25
_MAX_WS = 10

# --- severity mapping: each reused scanner's own scale -> contract severity ---
# Task spec is explicit: a credentialed arbitrary-origin reflection is HIGH
# (not critical), so cors_scanner's CRITICAL maps down to "high".
_CORS_SEV = {
    cors_scanner.CRITICAL: "high",   # reflected attacker origin + ACAC:true
    cors_scanner.HIGH: "high",       # null-origin trusted with credentials, etc.
    cors_scanner.MEDIUM: "medium",   # reflected origin w/o creds; wildcard+creds misconfig
    cors_scanner.LOW: "low",         # cors_scanner.LOW == "MEDIUM_LOW"
    cors_scanner.INFO: "info",       # ACAO:* without credentials (public CORS)
}
_CSRF_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
_PP_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_HPP_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_WS_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_SCRIPT_SRC = re.compile(r"<script[^>]+src\s*=\s*['\"]([^'\"]+)['\"]", re.I)
_FRAME_ANCESTORS = re.compile(r"frame-ancestors\s+([^;]+)", re.I)
_PASSWORD_INPUT = re.compile(r"type\s*=\s*['\"]?password", re.I)
_SENSITIVE_PATH = re.compile(
    r"(login|signin|sign-in|logout|account|admin|settings|profile|password|"
    r"passwd|transfer|payment|checkout|billing|security|session|email|"
    r"dashboard|delete|withdraw|api[-_]?key|wallet|fund)",
    re.I,
)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _meta(sev: str):
    """Confidence + verdict suited to a contract severity."""
    if sev in ("high", "critical"):
        return "confirmed", V_CONFIRMED
    if sev == "medium":
        return "firm", V_POSSIBLE
    if sev == "low":
        return "tentative", V_POSSIBLE
    return "tentative", V_INCONCLUSIVE


def _auth(ctx) -> dict:
    a = getattr(ctx, "account_a", None)
    hdrs = getattr(a, "headers", None) if a is not None else None
    return dict(hdrs) if hdrs else {}


def _as_entry(e):
    if isinstance(e, str):
        return "GET", e
    if isinstance(e, dict):
        return (str(e.get("method") or "GET")).upper(), str(e.get("url") or e.get("path") or "")
    return "GET", ""


def _resolve(ctx, url: str) -> str:
    if not url:
        return ""
    if url.startswith(("http://", "https://", "ws://", "wss://")):
        return url
    base = getattr(ctx, "base_url", "") or ""
    return urljoin(base, url) if base else url


def _iter_entries(ctx):
    for e in (getattr(ctx, "endpoints", None) or []):
        method, raw = _as_entry(e)
        url = _resolve(ctx, raw)
        if url:
            yield method, url


def _http_endpoints(ctx):
    """All http(s) surfaces (base + every endpoint) - CORS and PP active."""
    out = []
    base = getattr(ctx, "base_url", "") or ""
    if base.startswith(("http://", "https://")):
        out.append(base)
    for _method, url in _iter_entries(ctx):
        if url.startswith(("http://", "https://")) and url not in out:
            out.append(url)
    return out


def _pages(ctx):
    """http(s) GET surfaces - CSRF forms, clickjacking, postMessage, PP static."""
    out = []
    base = getattr(ctx, "base_url", "") or ""
    if base.startswith(("http://", "https://")):
        out.append(base)
    for method, url in _iter_entries(ctx):
        if url.startswith(("http://", "https://")) and method in ("GET", "") and url not in out:
            out.append(url)
    return out


def _ws_endpoints(ctx):
    out = []
    for _method, url in _iter_entries(ctx):
        if url.startswith(("ws://", "wss://")) and url not in out:
            out.append(url)
    tech = getattr(ctx, "tech", None)
    if isinstance(tech, dict):
        for key in ("ws_endpoints", "websockets", "websocket_endpoints"):
            for url in (tech.get(key) or []):
                if isinstance(url, str) and url.startswith(("ws://", "wss://")) and url not in out:
                    out.append(url)
    return out


def _is_catchall(ctx, resp) -> bool:
    base = getattr(ctx, "baseline", None)
    if not base or not getattr(base, "active", False) or resp is None:
        return False
    try:
        return bool(base.is_catchall(resp.status, resp.body))
    except Exception:
        return False


def _get(ctx, url, auth, cache):
    """Plain (non-origin-varying) GET, memoised per URL."""
    if url in cache:
        return cache[url]
    resp = ctx.fetch("GET", url, headers=dict(auth) if auth else None)
    cache[url] = resp
    return resp


def _set_cookie_list(resp):
    out = []
    headers = getattr(resp, "headers", None) or {}
    for key, val in headers.items():
        if str(key).lower() == "set-cookie":
            if isinstance(val, (list, tuple)):
                out.extend(str(x) for x in val)
            else:
                out.append(str(val))
    return out


def _script_srcs(ctx, page_url, body):
    out = []
    for m in _SCRIPT_SRC.finditer(body or ""):
        src = m.group(1).strip()
        if not src or src.startswith(("data:", "javascript:")):
            continue
        full = urljoin(page_url, src)
        if not full.startswith(("http://", "https://")):
            continue
        host = urlparse(full).hostname or ""
        if not ctx.in_scope(host):
            continue
        if full not in out:
            out.append(full)
    return out


def _is_sensitive_page(url, body):
    if _SENSITIVE_PATH.search(urlparse(url).path or ""):
        return True
    if body and _PASSWORD_INPUT.search(body):
        return True
    return False


# --------------------------------------------------------------------------- #
# pure classifier for clickjacking (no reusable scanner exists for it)
# --------------------------------------------------------------------------- #
def classify_clickjacking(xfo, csp):
    """Pure: 'framable' when neither X-Frame-Options nor a restrictive CSP
    frame-ancestors directive protects the page, else None.

    DENY / SAMEORIGIN protect; a frame-ancestors directive protects when it has
    a value that is not the permissive ``*``.
    """
    xfo_ok = bool(xfo) and xfo.strip().upper() in ("DENY", "SAMEORIGIN")
    fa_ok = False
    if csp:
        m = _FRAME_ANCESTORS.search(csp)
        if m:
            val = m.group(1).strip()
            fa_ok = bool(val) and val != "*"
    if xfo_ok or fa_ok:
        return None
    return "framable"


# --------------------------------------------------------------------------- #
# per-class probes (each returns a list[Finding])
# --------------------------------------------------------------------------- #
def _cors(ctx, url, auth):
    out, seen, checked_catchall = [], set(), False
    for test in cors_scanner.generate_tests(url):
        headers = dict(auth)
        headers["Origin"] = test.origin
        resp = ctx.fetch("GET", url, headers=headers)
        if resp is None:
            continue
        if not checked_catchall:
            checked_catchall = True
            if _is_catchall(ctx, resp):
                return out  # not a real endpoint - do not reason over the shell
        acao = resp.header("Access-Control-Allow-Origin")
        acac = resp.header("Access-Control-Allow-Credentials")
        cf = cors_scanner.classify(url, test, acao, acac)
        if cf is None:
            continue
        key = (cf.severity, cf.title)
        if key in seen:
            continue
        seen.add(key)
        out.append(_cors_finding(url, test, cf))
    return out


def _cors_finding(url, test, cf):
    sev = _CORS_SEV.get(cf.severity, "info")
    conf, verdict = _meta(sev)
    if sev in ("low", "info"):
        kill = ["ACAO:* without credentials is public CORS; only a risk if the "
                "endpoint returns sensitive data without authentication"]
    elif sev == "medium":
        kill = ["exploitable only if the endpoint is authorised by a non-cookie "
                "token the attacker page can set, or returns sensitive data "
                "without authentication"]
    else:
        kill = []
    hints = (["read authenticated JSON cross-origin -> exfiltrate PII/tokens -> "
              "account takeover"] if sev == "high" else [])
    return Finding(
        cls="cors",
        title=cf.title,
        severity=sev,
        confidence=conf,
        axis="read",
        technique="origin-reflection:" + test.weakness,
        method="GET",
        url=url,
        evidence={
            "origin_sent": cf.origin_sent,
            "access_control_allow_origin": cf.acao,
            "access_control_allow_credentials": cf.acac,
            "note": cf.note,
        },
        verdict=verdict,
        repro=[
            "Send GET %s with header 'Origin: %s'%s"
            % (url, cf.origin_sent, " plus the victim's session cookie" if cf.acac else ""),
            "Observe 'Access-Control-Allow-Origin: %s'%s"
            % (cf.acao, " with 'Access-Control-Allow-Credentials: true'" if cf.acac else ""),
            "A page on the attacker origin issues the same request and reads the response",
        ],
        kill_reasons=kill,
        chain_hints=hints,
    )


def _csrf_page(ctx, url, resp):
    out = []
    body = resp.body or ""
    samesite = csrf_scanner.samesite_strength(_set_cookie_list(resp))
    for form in csrf_scanner.parse_forms(body):
        cf = csrf_scanner.classify_form(form, samesite, url)
        if cf is None or cf.severity == "INFO":
            continue
        out.append(_csrf_finding(url, cf, samesite))
    return out


def _csrf_finding(url, cf, samesite):
    sev = _CSRF_SEV.get(cf.severity, "low")
    conf, verdict = _meta(sev)
    technique = {"HIGH": "missing-csrf-token", "MEDIUM": "missing-csrf-token",
                 "LOW": "weak-csrf-token"}.get(cf.severity, "csrf")
    return Finding(
        cls="csrf",
        title="State-changing form without CSRF defence",
        severity=sev,
        confidence=conf,
        axis="write",
        technique=technique,
        method=cf.method or "POST",
        url=url,
        evidence={
            "form_action": cf.form_action or "(self)",
            "form_method": cf.method,
            "samesite": samesite,
            "reason": cf.reason,
        },
        verdict=verdict,
        repro=[
            "Load %s and locate the form posting to '%s'" % (url, cf.form_action or url),
            "Host an attacker page that auto-submits the same fields cross-site",
            "With the victim authenticated, confirm the state change occurs without a valid token",
        ],
        kill_reasons=["modern browsers default cookies to SameSite=Lax; confirm the "
                      "auth cookie is actually sent on a genuine cross-site "
                      "state-changing request"],
        chain_hints=["chain with a stored/reflected value or clickjacking to deliver the forged request"],
    )


def _csrf_json(ctx, cache):
    """Read-only JSON-endpoint CSRF signal (reuses samesite_strength).

    Fires only when a session cookie with an explicitly weak SameSite was
    observed AND the target exposes a state-changing JSON endpoint - i.e. the
    ambient cookie would ride a cross-site write. Sending the write itself would
    confirm it, so this is tentative by design.
    """
    if not any(method in _STATE_METHODS for method, _url in _iter_entries(ctx)):
        return []
    order = {"none": 0, "lax": 1, "strict": 2}
    worst, saw_cookie = None, False
    for resp in list(cache.values()):
        if resp is None:
            continue
        ss = csrf_scanner.samesite_strength(_set_cookie_list(resp))
        if ss is not None:
            saw_cookie = True
            if worst is None or order[ss] < order[worst]:
                worst = ss
    if not saw_cookie or worst != "none":
        return []
    target = getattr(ctx, "base_url", "") or next((u for _m, u in _iter_entries(ctx)), "")
    return [Finding(
        cls="csrf",
        title="Cookie-authenticated JSON API with weak SameSite and no double-submit token",
        severity="medium",
        confidence="tentative",
        axis="write",
        technique="json-endpoint-samesite",
        method="POST",
        url=target,
        evidence={
            "samesite": worst,
            "note": "state-changing JSON endpoint(s) present; session cookie lacks SameSite=Lax/Strict",
        },
        verdict=V_POSSIBLE,
        kill_reasons=["confirm the API accepts a cross-site request carrying the "
                      "cookie and without a CSRF token / custom header"],
        chain_hints=["forge a cross-site fetch/XHR to the JSON endpoint relying on the ambient cookie"],
    )]


def _clickjacking(ctx, url, resp):
    body = resp.body or ""
    if not _is_sensitive_page(url, body):
        return []
    xfo = resp.header("X-Frame-Options")
    csp = resp.header("Content-Security-Policy")
    if classify_clickjacking(xfo, csp) is None:
        return []
    return [Finding(
        cls="clickjacking",
        title="Sensitive page is framable (clickjacking)",
        severity="medium",
        confidence="firm",
        axis="",
        technique="missing-x-frame-options-and-frame-ancestors",
        method="GET",
        url=url,
        evidence={
            "x_frame_options": xfo,
            "content_security_policy": (csp[:200] if csp else None),
            "frame_ancestors": "absent-or-permissive",
        },
        verdict=V_POSSIBLE,
        repro=[
            "Create an attacker page with <iframe src='%s'> under a reduced-opacity overlay" % url,
            "Position a decoy control over a sensitive action in the framed page",
            "Confirm the victim's click reaches the framed action (UI redress)",
        ],
        kill_reasons=["confirm there is no client-side frame-busting and that the "
                      "framed action is genuinely state-changing / sensitive"],
        chain_hints=["combine with CSRF so the redressed click performs a state change"],
    )]


def _client_js(url, text):
    """postMessage (cls 'hpp') + client-side prototype-pollution (static)."""
    out = []
    for pm in hpp.analyze_postmessage(text, url):
        out.append(_pm_finding(url, pm))
    for pf in pp.analyze_js(text, url):
        out.append(_pp_static_finding(url, pf))
    return out


def _pm_finding(url, pm):
    sev = _HPP_SEV.get(pm.severity, "medium")
    conf, verdict = _meta(sev)
    kill = ([] if sev == "high"
            else ["listener lacks an origin check; confirm event.data reaches a sensitive sink"])
    return Finding(
        cls="hpp",
        title="postMessage listener without origin validation",
        severity=sev,
        confidence=conf,
        axis="",
        technique="postmessage-missing-origin-check",
        method="GET",
        url=url,
        evidence={"detail": pm.reason, "kind": pm.kind},
        verdict=verdict,
        repro=[
            "Review the message event listener in %s" % url,
            "From an attacker frame, call targetWindow.postMessage(payload, '*')",
            "Confirm event.data flows to the sink without an event.origin allow-list check",
        ],
        kill_reasons=kill,
        chain_hints=["spoof postMessage from an attacker frame -> DOM XSS / token theft / state tamper"],
    )


def _pp_static_finding(url, pf):
    sev = _PP_SEV.get(pf.severity, "low")
    return Finding(
        cls="prototype-pollution",
        title="Client-side prototype pollution gadget",
        severity=sev,
        confidence="tentative",
        axis="",
        technique="client-source-sink",
        method="GET",
        url=url,
        evidence={"detail": pf.reason, "kind": pf.kind},
        verdict=V_POSSIBLE,
        repro=[
            "Review %s for the flagged pollution source/sink" % url,
            "Craft a URL/JSON that sets __proto__ through the source and reaches the merge sink",
            "Confirm a polluted property appears on a plain object at runtime",
        ],
        kill_reasons=["static signal only; needs a reachable sink and a working gadget to weaponise"],
        chain_hints=["chain a pollution primitive with a DOM gadget for client-side XSS/RCE"],
    )


def _pp_active(ctx, url, auth, cache):
    out = []
    canary = "pp" + os.urandom(4).hex()
    base = _get(ctx, url, auth, cache)
    if base is None or _is_catchall(ctx, base):
        return out
    base_status = base.status
    sep = "&" if "?" in url else "?"
    qurl = "%s%s__proto__[%s]=%s" % (url, sep, canary, canary)
    rq = ctx.fetch("GET", qurl, headers=dict(auth) if auth else None)
    if rq is not None:
        v = pp.classify_active(canary, rq.body or "", rq.status, base_status)
        if v:
            out.append(_pp_active_finding(url, v, "GET", "server-query-__proto__"))
    # The JSON body probe is a POST - only under an explicit write gate.
    if getattr(ctx, "allow_write", False) and not out:
        jheaders = dict(auth)
        jheaders["Content-Type"] = "application/json"
        payload = {"__proto__": {canary: canary},
                   "constructor": {"prototype": {canary: canary}}}
        rp = ctx.fetch("POST", url, headers=jheaders, body=payload)
        if rp is not None:
            v2 = pp.classify_active(canary, rp.body or "", rp.status, base_status)
            if v2:
                out.append(_pp_active_finding(url, v2, "POST", "server-json-__proto__"))
    return out


def _pp_active_finding(url, v, method, technique):
    sev = _PP_SEV.get(v.severity, "medium")
    conf, verdict = _meta(sev)
    kill = (["a 500 vs baseline may be generic input validation; confirm it is prototype traversal"]
            if v.severity == "MEDIUM" else [])
    return Finding(
        cls="prototype-pollution",
        title="Server-side prototype pollution",
        severity=sev,
        confidence=conf,
        axis="write" if method == "POST" else "read",
        technique=technique,
        method=method,
        url=url,
        evidence={"detail": v.reason},
        verdict=verdict,
        repro=[
            "Send %s %s with a __proto__ canary payload" % (method, url),
            "Observe the canary on an object field it should not exist on, or a prototype-traversal 500",
        ],
        kill_reasons=kill,
        chain_hints=["escalate pollution to DoS, auth bypass, or RCE via a known server gadget"],
    )


def _ws_handshake(ctx, url, origin, auth):
    u = urlparse(url)
    scheme = "https" if u.scheme == "wss" else "http"
    http_url = urlunparse((scheme, u.netloc, u.path or "/", "", u.query, ""))
    headers = dict(auth) if auth else {}
    headers.update({
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
        "Sec-WebSocket-Version": "13",
        "Origin": origin,
    })
    resp = ctx.fetch("GET", http_url, headers=headers)
    return resp.status if resp is not None else 0


def _cswsh(ctx, url, auth):
    u = urlparse(url)
    same_origin = "%s://%s" % ("https" if u.scheme == "wss" else "http", u.hostname)
    forged_origin = "https://evil-cswsh-test.example"
    forged_status = _ws_handshake(ctx, url, forged_origin, auth)
    legit_status = _ws_handshake(ctx, url, same_origin, auth)
    authed = bool(auth)
    v = wss.classify(forged_status, legit_status, authed)
    if v is None:
        return None
    sev = _WS_SEV.get(v.severity, "low")
    if v.severity == "LOW":   # forged rejected, same-origin accepted: Origin validated
        sev, conf, verdict = "info", "tentative", V_INCONCLUSIVE
        kill = ["forged Origin rejected; the socket appears to validate Origin - "
                "not a finding, recorded for completeness"]
    else:
        conf, verdict = _meta(sev)
        kill = ([] if sev == "high"
                else ["socket accepts any Origin; confirm it carries auth/session "
                      "data to make it hijackable"])
    return Finding(
        cls="websocket-cswsh",
        title="Cross-Site WebSocket Hijacking",
        severity=sev,
        confidence=conf,
        axis="",
        technique="origin-forgery-handshake",
        method="GET",
        url=url,
        evidence={
            "forged_status": forged_status,
            "legit_status": legit_status,
            "authenticated": authed,
            "detail": v.reason,
        },
        verdict=verdict,
        repro=[
            "From attacker JS, open a WebSocket to %s (browser sends the attacker "
            "Origin and the victim's cookies)" % url,
            "Forged-Origin handshake returned HTTP %s (same-origin: %s)" % (forged_status, legit_status),
            "If 101, drive the victim's authenticated socket cross-origin",
        ],
        kill_reasons=kill,
        chain_hints=["read/stream the victim's socket data or send privileged messages as the victim"],
    )


# --------------------------------------------------------------------------- #
# the kit
# --------------------------------------------------------------------------- #
class ClientSideKit:
    """Depth kit for the browser-trust family of client-side vulnerabilities."""

    name = "client-side"
    classes = ("cors", "csrf", "clickjacking", "prototype-pollution", "hpp", "websocket-cswsh")

    def applicable(self, ctx) -> bool:
        # Client-side trust checks apply to essentially any reachable web surface.
        return bool(getattr(ctx, "base_url", "") or getattr(ctx, "endpoints", None))

    def run(self, ctx):
        findings = []
        if getattr(ctx, "fetch", None) is None:
            return findings

        auth = _auth(ctx)
        cache = {}
        apis = _http_endpoints(ctx)[:_MAX_APIS]
        pages = _pages(ctx)[:_MAX_PAGES]
        wsurls = _ws_endpoints(ctx)[:_MAX_WS]

        # CORS - per http(s) surface, varied Origins.
        for url in apis:
            findings += _cors(ctx, url, auth)

        # Page-driven checks: CSRF forms, clickjacking, postMessage + PP static
        # (inline scripts and in-scope external JS).
        js_seen = set()
        for url in pages:
            resp = _get(ctx, url, auth, cache)
            if resp is None or _is_catchall(ctx, resp):
                continue
            findings += _csrf_page(ctx, url, resp)
            findings += _clickjacking(ctx, url, resp)
            body = resp.body or ""
            findings += _client_js(url, body)
            for jsurl in _script_srcs(ctx, url, body):
                if jsurl in js_seen or len(js_seen) >= _MAX_JS:
                    continue
                js_seen.add(jsurl)
                jr = _get(ctx, jsurl, auth, cache)
                if jr is None or _is_catchall(ctx, jr):
                    continue
                findings += _client_js(jsurl, jr.body or "")

        # JSON-endpoint CSRF signal (uses the cookies already observed above).
        findings += _csrf_json(ctx, cache)

        # Server-side prototype pollution - per http(s) surface.
        for url in apis:
            findings += _pp_active(ctx, url, auth, cache)

        # CSWSH - per ws(s) endpoint.
        for url in wsurls:
            f = _cswsh(ctx, url, auth)
            if f is not None:
                findings.append(f)

        return findings


KIT = ClientSideKit()
register(KIT)
