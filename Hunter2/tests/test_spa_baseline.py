"""Tests for tools/spa_baseline.py — the SPA catch-all detector.

This is the piece that was missing when every mydukaan.io path returned the
same 200 HTML shell and the scanners read it as "live endpoints".
"""
from tools import spa_baseline as spa

SHELL = (
    "<!doctype html><html><head><title>App</title>"
    "<link rel=stylesheet href=/static/app.css></head>"
    "<body><div id=root></div><script src=/static/main.js></script></body></html>"
)


def test_identical_shell_is_catchall():
    base = spa.Baseline([(200, SHELL), (200, SHELL)])
    assert base.active is True
    assert base.is_catchall(200, SHELL) is True


def test_shell_with_changing_nonce_still_catchall():
    # Real SPA shells differ only by a per-request nonce/build id; the
    # normaliser strips digits and long hex so the match still holds.
    a = SHELL + "<meta name=csrf content=abcdef0123456789>"
    b = SHELL + "<meta name=csrf content=99887766deadc0de>"
    base = spa.Baseline([(200, a)])
    assert base.is_catchall(200, b) is True


def test_real_json_response_is_not_catchall():
    base = spa.Baseline([(200, SHELL), (200, SHELL)])
    api_body = ('{"id": 42, "name": "widget", "price": 999, '
                '"sku": "ABC-123", "inventory": 7, "owner": "seller-9"}')
    assert base.is_catchall(200, api_body) is False


def test_different_status_is_not_catchall():
    base = spa.Baseline([(200, SHELL)])
    assert base.is_catchall(404, SHELL) is False


def test_inactive_baseline_never_flags():
    base = spa.Baseline([])
    assert base.active is False
    assert base.is_catchall(200, SHELL) is False
    assert base.is_catchall(200, None) is False


def test_probe_builds_baseline_from_fetcher():
    seen = []

    def fetch(path):
        seen.append(path)
        return (200, SHELL)

    base = spa.probe(fetch, samples=2)
    assert len(seen) == 2
    # probe should hit two DIFFERENT random non-existent paths
    assert seen[0] != seen[1]
    assert base.is_catchall(200, SHELL) is True


def test_probe_tolerates_fetch_errors():
    def fetch(path):
        raise RuntimeError("network down")

    base = spa.probe(fetch, samples=2)
    assert base.active is False  # no samples collected, but no crash
