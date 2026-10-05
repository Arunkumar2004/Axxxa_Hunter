"""Tests for the autonomous orchestrator (tools/hunter/autohunt.py) and the
recon feed (tools/hunter/recon_feed.py). Everything is offline: the browser
login step is injected, so no Chromium ever opens here.
"""
import json
import os
import sys

import pytest

from tools.hunter import autohunt, recon_feed
from tools.hunter.contract import Resp
from tests.hunter.mock_target import MockApp

MOCK_ENDPOINTS = [
    {"method": "GET", "url": "https://mock.test/api/product/1/"},
    {"method": "GET", "url": "https://mock.test/api/order/10/"},
    {"method": "GET", "url": "https://mock.test/api/profile/500/"},
    {"method": "GET", "url": "https://mock.test/api/echo?q=hi"},
    {"method": "GET", "url": "https://mock.test/api/account/me"},
]


# --- recon_feed -------------------------------------------------------------
def test_recon_feed_light_crawl_mines_and_scopes():
    pages = {
        "https://t.test/": Resp(200, (
            '<html><body><a href="/api/users/1">u</a>'
            '<a href="https://evil.com/x">out</a>'
            '<script src="/static/app.js"></script></body></html>'),
            {"Content-Type": "text/html"}),
        "https://t.test/static/app.js": Resp(200,
            'const u="/api/orders/5"; fetch("/api/cart");', {"Content-Type": "text/javascript"}),
    }

    def fetch(method, url, headers=None, body=None):
        return pages.get(url)

    eps = recon_feed.collect("https://t.test/", scope_hosts=("t.test",), fetch=fetch)
    urls = {e["url"] for e in eps}
    assert "https://t.test/api/users/1" in urls
    assert "https://t.test/api/orders/5" in urls
    assert "https://t.test/api/cart" in urls
    assert not any("evil.com" in u for u in urls)   # out-of-scope dropped


def test_recon_feed_parses_local_swagger(tmp_path):
    spec = {"openapi": "3.0.0", "paths": {"/users/{id}": {"get": {}}, "/pay": {"post": {}}}}
    f = tmp_path / "swagger.json"
    f.write_text(json.dumps(spec), encoding="utf-8")
    eps = recon_feed.collect("https://api.test/", scope_hosts=("api.test",),
                             swagger=str(f), fetch=None)
    pairs = {(e["method"], e["url"]) for e in eps}
    assert ("GET", "https://api.test/users/{id}") in pairs
    assert ("POST", "https://api.test/pay") in pairs


# --- account resolution (the browser-gating logic) --------------------------
def _boom_login(*a, **k):
    raise AssertionError("login_fn must not be called (no browser should open)")


def test_env_credentials_skip_the_browser(tmp_path):
    env = tmp_path / ".env"
    env.write_text("ACCOUNT_A_TOKEN=aaa\nACCOUNT_B_TOKEN=bbb\n", encoding="utf-8")
    a, b = autohunt.resolve_accounts(
        "https://t.test/", "t.test", auth=True, two_accounts=True,
        env=str(env), login_fn=_boom_login, log=lambda m: None)
    assert a.headers.get("Authorization") == "Bearer aaa"
    assert b.headers.get("Authorization") == "Bearer bbb"


def test_no_auth_never_opens_the_browser(tmp_path):
    env = tmp_path / ".env"   # empty / nonexistent
    a, b = autohunt.resolve_accounts(
        "https://t.test/", "t.test", auth=False, two_accounts=True,
        env=str(env), login_fn=_boom_login, log=lambda m: None)
    assert a.headers == {} and b.headers == {}


def test_missing_creds_trigger_the_login_handoff(tmp_path):
    env = tmp_path / ".env"
    calls = []

    def fake_login(login_url, name, out_dir=".private"):
        calls.append(name)
        return {"bearer": "A" if name.endswith("-A") else "B"}

    a, b = autohunt.resolve_accounts(
        "https://t.test/", "t.test", auth=True, two_accounts=True,
        env=str(env), login_fn=fake_login, log=lambda m: None)
    assert len(calls) == 2                      # A and B logins
    assert a.headers.get("Authorization") == "Bearer A"
    assert b.headers.get("Authorization") == "Bearer B"


# --- full orchestration against the mock (no browser, injected login) -------
def test_autohunt_run_end_to_end(tmp_path, monkeypatch):
    mock = MockApp()
    monkeypatch.setattr(autohunt.recon_feed, "collect",
                        lambda *a, **k: [dict(e) for e in MOCK_ENDPOINTS])
    logins = []

    def fake_login(login_url, name, out_dir=".private"):
        logins.append(name)
        return {"bearer": "A" if name.endswith("-A") else "B"}

    env = tmp_path / ".env"           # no creds -> login hand-off exercised
    out = tmp_path / "out"
    report = autohunt.run(
        "https://mock.test/", scope_hosts=("mock.test",),
        allow_write=True, auth=True, two_accounts=True,
        env=str(env), out_dir=str(out), fetch=mock.fetch,
        login_fn=fake_login, logger=lambda m: None,
    )

    assert logins == ["mock.test-A", "mock.test-B"]           # browser hand-off happened
    assert "idor-bola" in {f.cls for f in report["findings"]}  # it actually hunted
    assert report["ledger_summary"].get("complete") is True
    # report files written
    files = os.listdir(out)
    assert any(f.endswith(".json") for f in files)
    assert any(f.endswith(".md") for f in files)


def test_autohunt_cli_help_runs():
    # --help must exit cleanly (no traceback / no browser).
    with pytest.raises(SystemExit) as e:
        autohunt.main(["--help"])
    assert e.value.code == 0
