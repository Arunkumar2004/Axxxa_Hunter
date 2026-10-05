#!/usr/bin/env python3
"""Recon feed — gather the endpoints the engine will hunt over.

The depth kits are only as strong as the attack surface they are handed, so this
module assembles ``ctx.endpoints`` for a target from every source that is cheap
and already available, in priority order:

  1. an explicit OpenAPI/Swagger spec (local file or URL) — the richest source;
  2. an existing recon directory for the host (``recon/<host>/*.txt`` — e.g.
     ``with_params.txt`` / ``all.txt`` produced by the shell recon pipeline);
  3. a ``surface_graph.json`` if one is present;
  4. a light, in-scope crawl via ``fetch`` (the base page + a few linked JS
     bundles), mining hrefs / fetch()/axios URLs / ``/api/...`` string literals.

Everything is best-effort: a missing source is skipped, never fatal. Results are
scope-filtered, de-duplicated and capped. All network I/O goes through the
injected ``fetch`` (so this is unit-testable offline).
"""
from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import urljoin, urlparse

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# Endpoint-ish string patterns mined from HTML/JS.
_HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'<>]+)["']""", re.I)
_CALL_RE = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|\.open|url|baseURL|endpoint)\s*"""
    r"""[:(]\s*["']([^"'<>\s]+)["']""",
    re.I,
)
_APIPATH_RE = re.compile(r"""["'](/(?:api|v\d|graphql|rest|internal)/[^"'<>\s]*)["']""", re.I)
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)

_MAX_JS = 6                 # how many linked JS bundles to mine
_DEFAULT_CAP = 300          # endpoint cap


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _in_scope(url: str, scope_hosts) -> bool:
    if not scope_hosts:
        return True
    h = _host(url)
    if not h:
        return False
    for s in scope_hosts:
        s = str(s).lower().lstrip("*.").rstrip(".")
        if h == s or h.endswith("." + s):
            return True
    return False


def _ep(method: str, url: str) -> dict:
    return {"method": (method or "GET").upper(), "url": url}


# --- source 1: OpenAPI / Swagger -------------------------------------------
def _from_spec(base_url: str, spec_arg: str, fetch) -> list:
    """Parse a spec (local file or URL) into endpoints rooted at base_url."""
    try:
        from tools import api_security_scanner as api
    except Exception:
        return []
    text = None
    if os.path.isfile(spec_arg):
        try:
            with open(spec_arg, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            return []
    else:
        parsed = urlparse(spec_arg)
        if parsed.scheme in ("http", "https") and fetch is not None:
            r = fetch("GET", spec_arg)
            text = getattr(r, "body", None) if r is not None else None
    spec = api._parse_spec_text(text) if text else None
    if not spec:
        return []
    out = []
    # Prefer servers[].url from the spec; else the given base.
    root = base_url
    try:
        servers = spec.get("servers") if isinstance(spec, dict) else None
        if servers and isinstance(servers, list):
            u = servers[0].get("url")
            if u and urlparse(u).scheme:
                root = u
    except Exception:
        pass
    for p in api.extract_paths(spec):
        out.append(_ep(p["method"], urljoin(root.rstrip("/") + "/", p["path"].lstrip("/"))))
    return out


# --- source 2/3: recon dir + surface graph ---------------------------------
def _from_recon_dir(base_url: str, recon_dir: str) -> list:
    if not recon_dir or not os.path.isdir(recon_dir):
        return []
    out = []
    for fname in ("with_params.txt", "all.txt", "urls.txt", "endpoints.txt"):
        path = os.path.join(recon_dir, fname)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith(("http://", "https://")):
                        out.append(_ep("GET", line))
        except OSError:
            continue
    return out


def _from_surface_graph(path: str) -> list:
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except Exception:
        return []
    out = []
    items = data.get("endpoints") or data.get("nodes") or []
    for it in items if isinstance(items, list) else []:
        url = it.get("url") if isinstance(it, dict) else (it if isinstance(it, str) else None)
        if url and str(url).startswith(("http://", "https://")):
            out.append(_ep((it.get("method") if isinstance(it, dict) else "GET") or "GET", url))
    return out


# --- source 4: light crawl --------------------------------------------------
def _mine(text: str, base_url: str) -> set:
    found = set()
    for rx in (_HREF_RE, _CALL_RE, _APIPATH_RE):
        for m in rx.findall(text or ""):
            cand = m.strip()
            if not cand or cand.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
                continue
            if cand.startswith(("http://", "https://")):
                found.add(cand)
            elif cand.startswith("/"):
                found.add(urljoin(base_url, cand))
    return found


def _light_crawl(base_url: str, fetch, scope_hosts) -> list:
    if fetch is None:
        return []
    root = fetch("GET", base_url)
    body = getattr(root, "body", "") if root is not None else ""
    urls = _mine(body, base_url)
    # mine a few linked JS bundles too
    for src in _SCRIPT_SRC_RE.findall(body or "")[:_MAX_JS]:
        js_url = src if src.startswith(("http://", "https://")) else urljoin(base_url, src)
        if not _in_scope(js_url, scope_hosts):
            continue
        r = fetch("GET", js_url)
        if r is not None:
            urls |= _mine(getattr(r, "body", "") or "", base_url)
    return [_ep("GET", u) for u in urls]


# --- the public API ---------------------------------------------------------
def collect(base_url: str, scope_hosts=(), swagger: str | None = None,
            recon_dir: str | None = None, surface_graph: str | None = None,
            fetch=None, cap: int = _DEFAULT_CAP) -> list:
    """Assemble a de-duplicated, scope-filtered endpoint list for ``base_url``."""
    endpoints: list = []
    if swagger:
        endpoints += _from_spec(base_url, swagger, fetch)
    if recon_dir:
        endpoints += _from_recon_dir(base_url, recon_dir)
    if surface_graph:
        endpoints += _from_surface_graph(surface_graph)
    endpoints += _light_crawl(base_url, fetch, scope_hosts)

    seen, out = set(), []
    for ep in endpoints:
        url = ep.get("url", "")
        if not url or not _in_scope(url, scope_hosts):
            continue
        key = (ep["method"], url)
        if key in seen:
            continue
        seen.add(key)
        out.append(ep)
        if len(out) >= cap:
            break
    return out
