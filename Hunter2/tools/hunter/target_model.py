"""Target model — the "understand the target" step of the expert loop.

``build(ctx)`` probes ``ctx.base_url`` *only through* ``ctx.fetch`` and fills in
``ctx.tech`` (is it an SPA, what server/stack, is it a JSON API, which tech
markers showed up). When the caller supplied no endpoints it also does a light
sniff of common API prefixes so the kits have something to chew on. Finally it
sets ``ctx.baseline`` (the SPA catch-all fingerprint) by reusing
``tools/spa_baseline.py`` through a thin adapter.

Everything here is deterministic given the responses ``ctx.fetch`` returns, so
it is unit-tested offline with a fake fetch.
"""
from __future__ import annotations

import json
import os
import sys
from urllib.parse import urljoin, urlparse

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools import spa_baseline  # noqa: E402

# Body substrings that flag a particular stack. Compared case-insensitively.
_BODY_MARKERS = (
    ("__next_data__", "next.js"),
    ("/_next/", "next.js"),
    ("data-reactroot", "react"),
    ('id="root"', "react"),
    ("ng-version", "angular"),
    ("<app-root", "angular"),
    ("__nuxt__", "nuxt"),
    ("data-v-", "vue"),
    ("wp-content", "wordpress"),
    ("wp-includes", "wordpress"),
    ("csrfmiddlewaretoken", "django"),
    ("window.__remixcontext", "remix"),
    ("/cdn-cgi/", "cloudflare"),
    ("graphql", "graphql"),
)

# Header (name, needle, tech). An empty needle means "presence is enough".
_HEADER_MARKERS = (
    ("server", "nginx", "nginx"),
    ("server", "apache", "apache"),
    ("server", "cloudflare", "cloudflare"),
    ("server", "vercel", "vercel"),
    ("server", "netlify", "netlify"),
    ("server", "envoy", "envoy"),
    ("server", "gunicorn", "gunicorn"),
    ("server", "werkzeug", "flask"),
    ("server", "kestrel", "asp.net"),
    ("server", "microsoft-iis", "iis"),
    ("server", "openresty", "openresty"),
    ("x-powered-by", "express", "express"),
    ("x-powered-by", "php", "php"),
    ("x-powered-by", "asp.net", "asp.net"),
    ("x-powered-by", "next.js", "next.js"),
    ("x-aspnet-version", "", "asp.net"),
    ("x-drupal-cache", "", "drupal"),
    ("x-generator", "drupal", "drupal"),
)

# Body substrings that specifically indicate a single-page-app shell.
_SPA_HINTS = (
    "__next_data__",
    "/_next/",
    "data-reactroot",
    'id="root"',
    "id=root",
    "ng-version",
    "<app-root",
    "__nuxt__",
    "window.__remixcontext",
    "data-v-",
    'id="app"',
)

# Light endpoint sniff list — common API/entry prefixes, probed only when the
# caller handed us no endpoints of their own.
_COMMON_PREFIXES = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/graphql",
    "/rest",
    "/health",
    "/healthz",
    "/status",
    "/openapi.json",
    "/swagger.json",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/metrics",
    "/api/docs",
)


def _join(base: str, path: str) -> str:
    """Join a base URL and a path, tolerant of trailing/leading slashes."""
    if not base:
        return path
    if not base.endswith("/"):
        base = base + "/"
    return urljoin(base, (path or "").lstrip("/"))


def _safe_call(fetch, method: str, url: str):
    """Call the injected fetch, swallowing any exception into None.

    The contract says fetch returns None on a network error; this also shields
    ``build`` from a fake/real fetch that raises, so a dead host or a buggy
    adapter never aborts target modelling.
    """
    try:
        return fetch(method, url)
    except Exception:
        return None


def _looks_json(body: str) -> bool:
    if not body:
        return False
    s = body.lstrip()
    if not s or s[0] not in "{[":
        return False
    try:
        json.loads(s)
        return True
    except Exception:
        return False


def _add(items: list, value: str) -> None:
    if value and value not in items:
        items.append(value)


def build(ctx):
    """Probe ``ctx.base_url`` through ``ctx.fetch`` and populate the model.

    Mutates and returns ``ctx``:
      * ``ctx.tech`` gains ``is_spa`` (bool), ``server`` / ``powered_by``
        (strings from headers), ``json_api`` (bool) and ``detected`` (a list of
        tech markers).
      * ``ctx.baseline`` is set to an :class:`spa_baseline.Baseline` when one is
        not already present.
      * ``ctx.endpoints`` is filled with a light prefix sniff only when empty.
    """
    fetch = getattr(ctx, "fetch", None)

    tech = dict(ctx.tech) if isinstance(ctx.tech, dict) else {}
    detected = list(tech.get("detected") or [])

    if fetch is None:
        tech.update({
            "is_spa": bool(tech.get("is_spa", False)),
            "server": tech.get("server", "") or "",
            "powered_by": tech.get("powered_by", "") or "",
            "json_api": bool(tech.get("json_api", False)),
            "detected": detected,
        })
        ctx.tech = tech
        return ctx

    base = ctx.base_url or ""
    root = _safe_call(fetch, "GET", base) if base else None

    # Baseline first, so is_spa and the sniff can treat the catch-all as noise.
    if ctx.baseline is None:
        def _adapter(path, _f=fetch, _b=base):
            r = _safe_call(_f, "GET", _join(_b, path))
            return None if r is None else (r.status, r.body or "")

        try:
            ctx.baseline = spa_baseline.probe(_adapter)
        except Exception:
            ctx.baseline = None

    server = ""
    powered = ""
    is_spa = False
    json_api = False

    if root is not None:
        server = (root.header("Server") or "").strip()
        powered = (root.header("X-Powered-By") or "").strip()
        ctype = (root.header("Content-Type") or "").lower()
        body = root.body or ""
        low = body.lower()

        for hname, needle, name in _HEADER_MARKERS:
            val = (root.header(hname) or "").lower()
            if val and (not needle or needle in val):
                _add(detected, name)

        for needle, name in _BODY_MARKERS:
            if needle in low:
                _add(detected, name)

        is_html = ("text/html" in ctype) or body.lstrip()[:1] == "<"
        spa_hint = any(h in low for h in _SPA_HINTS)
        catchall = False
        try:
            catchall = bool(
                ctx.baseline
                and getattr(ctx.baseline, "active", False)
                and ctx.baseline.is_catchall(root.status, body)
            )
        except Exception:
            catchall = False
        is_spa = bool(is_html and (spa_hint or catchall))

        json_api = ("application/json" in ctype) or ("+json" in ctype) or _looks_json(body)

    # Light endpoint sniff — only when the caller gave us nothing.
    if base and not ctx.endpoints:
        sniffed = []
        for path in _COMMON_PREFIXES:
            url = _join(base, path)
            r = _safe_call(fetch, "GET", url)
            if r is None or r.status == 404:
                continue
            try:
                if (
                    ctx.baseline
                    and getattr(ctx.baseline, "active", False)
                    and ctx.baseline.is_catchall(r.status, r.body or "")
                ):
                    continue
            except Exception:
                pass
            ep_ctype = (r.header("Content-Type") or "").lower()
            ep_json = ("application/json" in ep_ctype) or ("+json" in ep_ctype) or _looks_json(r.body or "")
            if ep_json:
                json_api = True
            sniffed.append({
                "method": "GET",
                "url": url,
                "path": urlparse(url).path,
                "status": r.status,
                "content_type": ep_ctype,
                "source": "sniff",
            })
        if sniffed:
            ctx.endpoints = sniffed

    tech["is_spa"] = is_spa
    tech["server"] = server
    tech["powered_by"] = powered
    tech["json_api"] = json_api
    tech["detected"] = detected
    ctx.tech = tech
    return ctx
