#!/usr/bin/env python3
"""Tests for the mock target's planted behaviours.

These pin the fixtures the engine's end-to-end tests rely on: if a behaviour
here regresses, the engine tests would silently stop exercising that class.
"""
import json

from mock_target import SHELL, MockApp

AUTH_A = {"Authorization": "Bearer A"}
AUTH_B = {"Authorization": "Bearer B"}
BASE = "https://mock.local"


def _body(resp):
    return json.loads(resp.body)


def test_cross_account_read_bola_returns_b_data_to_a():
    app = MockApp()
    # Product 2 belongs to B; A must still get it back (the BOLA).
    resp = app.fetch("GET", f"{BASE}/api/product/2/", AUTH_A)
    assert resp.status == 200
    assert _body(resp)["owner"] == "B"
    assert _body(resp)["name"] == "Bravo Gadget"


def test_product_requires_authentication():
    # Anonymous must be blocked - the bug is cross-account, not public.
    app = MockApp()
    resp = app.fetch("GET", f"{BASE}/api/product/2/")
    assert resp.status == 401


def test_isolated_order_403s_non_owner_but_serves_owner():
    app = MockApp()
    # Order 10 belongs to A: B is correctly forbidden, A is served.
    assert app.fetch("GET", f"{BASE}/api/order/10/", AUTH_B).status == 403
    owner = app.fetch("GET", f"{BASE}/api/order/10/", AUTH_A)
    assert owner.status == 200
    assert _body(owner)["owner"] == "A"


def test_write_bola_patch_mutates_and_can_be_reverted():
    app = MockApp()
    # Coupon 101 belongs to B; A mutates it (write BOLA), then reverts.
    original = _body(app.fetch("GET", f"{BASE}/api/coupon/101/", AUTH_B))["percent"]
    assert original == 15

    patched = app.fetch("PATCH", f"{BASE}/api/coupon/101/", AUTH_A, {"percent": 90})
    assert patched.status == 200
    assert _body(patched)["percent"] == 90
    # The mutation persists for the owner's own read.
    assert _body(app.fetch("GET", f"{BASE}/api/coupon/101/", AUTH_B))["percent"] == 90

    # Revert and confirm the original value is restored.
    app.fetch("PATCH", f"{BASE}/api/coupon/101/", AUTH_A, {"percent": original})
    assert _body(app.fetch("GET", f"{BASE}/api/coupon/101/", AUTH_B))["percent"] == original


def test_write_bola_requires_auth():
    app = MockApp()
    assert app.fetch("PATCH", f"{BASE}/api/coupon/101/", None, {"percent": 1}).status == 401


def test_catch_all_is_stable_shell_for_unknown_paths():
    app = MockApp()
    a = app.fetch("GET", f"{BASE}/totally/unknown/path")
    b = app.fetch("GET", f"{BASE}/another/missing/thing-9173")
    assert a.status == b.status == 200
    assert a.body == b.body == SHELL          # byte-for-byte identical shell
    assert "<div id=root>" in a.body


def test_public_endpoint_is_identical_to_anon_and_authed():
    app = MockApp()
    anon = app.fetch("GET", f"{BASE}/api/public/info")
    as_a = app.fetch("GET", f"{BASE}/api/public/info", AUTH_A)
    as_b = app.fetch("GET", f"{BASE}/api/public/info", AUTH_B)
    assert anon.status == 200
    # Same body to everyone => a two-account scanner must call this PUBLIC.
    assert anon.body == as_a.body == as_b.body


def test_bfla_get_endpoint_wrongly_accepts_delete():
    app = MockApp()
    assert app.fetch("GET", f"{BASE}/api/report/1000/", AUTH_A).status == 200
    # Method-swap: DELETE is wrongly accepted and mutates state.
    deleted = app.fetch("DELETE", f"{BASE}/api/report/1000/", AUTH_B)
    assert deleted.status == 200
    assert app.fetch("GET", f"{BASE}/api/report/1000/", AUTH_A).status == 404
    app.reset()  # restore for any later use
    assert app.fetch("GET", f"{BASE}/api/report/1000/", AUTH_A).status == 200


def test_reflected_xss_param_is_unescaped():
    app = MockApp()
    resp = app.fetch("GET", f"{BASE}/api/echo?q=<script>alert(1)</script>")
    assert resp.status == 200
    assert "<script>alert(1)</script>" in resp.body


def test_open_redirect_param_is_trusted_verbatim():
    app = MockApp()
    resp = app.fetch("GET", f"{BASE}/api/redirect?next=https://evil.example/")
    assert resp.status == 302
    assert resp.header("Location") == "https://evil.example/"


def test_cors_wildcard_on_authed_json_endpoint():
    app = MockApp()
    anon = app.fetch("GET", f"{BASE}/api/account/me")
    assert anon.status == 401
    resp = app.fetch("GET", f"{BASE}/api/account/me", AUTH_A)
    assert resp.status == 200
    assert resp.header("Access-Control-Allow-Origin") == "*"
    assert _body(resp)["user_id"] == "A"
