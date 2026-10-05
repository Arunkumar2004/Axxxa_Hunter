"""Unit tests for the target model builder.

Driven entirely by an inline fake ``fetch`` that returns :class:`Resp` objects,
so nothing here touches the network. Two surfaces are modelled: an SPA shell
(every path returns the same HTML) and a JSON API.
"""
from urllib.parse import urlparse

from tools.hunter import target_model
from tools.hunter.contract import HuntContext, Resp

SHELL = (
    '<!doctype html><html><head><title>App</title>'
    '<link rel="stylesheet" href="/static/app.css"></head>'
    '<body><div id="root"></div>'
    '<script src="/static/main.js"></script>'
    '<script>window.__NEXT_DATA__ = {"props":{}}</script>'
    "</body></html>"
)


def _spa_fetch(method, url, headers=None, body=None):
    # Classic SPA edge host: every path returns the same 200 HTML shell.
    return Resp(
        status=200,
        body=SHELL,
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Server": "Vercel",
            "X-Powered-By": "Next.js",
        },
    )


_ROOT = '{"service":"api","version":"v2","status":"ok"}'
_LIST = '{"ok":true,"data":[]}'
_HEALTH = '{"status":"up"}'
_NF = '{"error":"not found"}'


def _api_fetch(method, url, headers=None, body=None):
    path = urlparse(url).path.rstrip("/") or "/"
    if path == "/":
        return Resp(200, _ROOT, {"Content-Type": "application/json",
                                 "Server": "nginx", "X-Powered-By": "Express"})
    if path in ("/api", "/api/v1", "/api/v2"):
        return Resp(200, _LIST, {"Content-Type": "application/json", "Server": "nginx"})
    if path == "/health":
        return Resp(200, _HEALTH, {"Content-Type": "application/json", "Server": "nginx"})
    # Unknown/random paths (incl. the baseline probes) are a real 404 — so the
    # host is NOT a catch-all SPA.
    return Resp(404, _NF, {"Content-Type": "application/json", "Server": "nginx"})


def test_spa_surface_is_detected():
    ctx = HuntContext(base_url="https://web.target.test/", fetch=_spa_fetch)
    target_model.build(ctx)

    assert ctx.tech["is_spa"] is True
    assert ctx.tech["json_api"] is False
    assert ctx.tech["server"] == "Vercel"
    assert ctx.tech["powered_by"] == "Next.js"
    for marker in ("next.js", "react", "vercel"):
        assert marker in ctx.tech["detected"]

    # Baseline fingerprinted and recognises the shell as the catch-all.
    assert ctx.baseline is not None
    assert ctx.baseline.active is True
    assert ctx.baseline.is_catchall(200, SHELL) is True

    # Every sniffed prefix returns the catch-all, so none is recorded as a
    # live endpoint (the whole point of the SPA baseline).
    assert ctx.endpoints == []


def test_json_api_surface_is_detected():
    ctx = HuntContext(base_url="https://api.target.test/", fetch=_api_fetch)
    target_model.build(ctx)

    assert ctx.tech["is_spa"] is False
    assert ctx.tech["json_api"] is True
    assert ctx.tech["server"] == "nginx"
    assert "express" in ctx.tech["detected"]
    assert "nginx" in ctx.tech["detected"]
    assert ctx.baseline is not None

    # The light sniff finds the real JSON endpoints and skips the 404s.
    assert ctx.endpoints, "expected sniffed endpoints on a JSON API"
    paths = {e["path"] for e in ctx.endpoints}
    assert "/api" in paths
    assert all(e["status"] != 404 for e in ctx.endpoints)
    assert all(e["source"] == "sniff" for e in ctx.endpoints)


def test_build_is_deterministic():
    ctx1 = HuntContext(base_url="https://api.target.test/", fetch=_api_fetch)
    ctx2 = HuntContext(base_url="https://api.target.test/", fetch=_api_fetch)
    target_model.build(ctx1)
    target_model.build(ctx2)
    for key in ("is_spa", "json_api", "server", "powered_by"):
        assert ctx1.tech[key] == ctx2.tech[key]
    assert sorted(ctx1.tech["detected"]) == sorted(ctx2.tech["detected"])
    assert {e["path"] for e in ctx1.endpoints} == {e["path"] for e in ctx2.endpoints}


def test_preexisting_endpoints_are_not_overwritten():
    given = [{"method": "GET", "url": "https://api.target.test/orders"}]
    ctx = HuntContext(base_url="https://api.target.test/", fetch=_api_fetch, endpoints=given)
    target_model.build(ctx)
    # The caller's endpoints are left untouched (no sniff when already supplied).
    assert ctx.endpoints == given


def test_only_uses_injected_fetch():
    calls = {"n": 0}

    def counting_fetch(method, url, headers=None, body=None):
        calls["n"] += 1
        return _api_fetch(method, url, headers, body)

    ctx = HuntContext(base_url="https://api.target.test/", fetch=counting_fetch)
    target_model.build(ctx)
    assert calls["n"] > 0  # probed only through ctx.fetch


def test_no_fetch_degrades_gracefully():
    ctx = HuntContext(base_url="https://api.target.test/", fetch=None)
    target_model.build(ctx)
    assert ctx.tech["is_spa"] is False
    assert ctx.tech["json_api"] is False
    assert ctx.tech["detected"] == []
