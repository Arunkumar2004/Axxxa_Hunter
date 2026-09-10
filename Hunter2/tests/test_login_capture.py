"""Unit tests for login_capture pure logic (detection + AuthSession JSON).
No browser / network."""
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from tools.login_capture import detect_login_success, build_auth_json

JWT = "eyJhbGciOiJI.eyJzdWIiOiIxMjM.SflKxwRJSMeKKF2QT4"


class TestDetectLoginSuccess:
    def test_left_login_with_session_cookie(self):
        ok, b = detect_login_success("https://t.com/dashboard", "https://t.com/login",
                                     [{"name": "sessionid", "value": "abc"}], {})
        assert ok is True and b is None

    def test_spa_jwt_in_localstorage_same_url(self):
        ok, b = detect_login_success("https://t.com/login", "https://t.com/login", [], {"access_token": JWT})
        assert ok is True and b == JWT

    def test_still_on_login_no_material(self):
        ok, b = detect_login_success("https://t.com/login", "https://t.com/login", [], {})
        assert ok is False and b is None

    def test_returns_plain_bool(self):
        ok, _ = detect_login_success("https://t.com/login", "https://t.com/login", [], {"token": JWT})
        assert isinstance(ok, bool)

    def test_non_jwt_long_token_key(self):
        ok, b = detect_login_success("https://t.com/app", "https://t.com/login",
                                     [], {"auth_token": "abcdef0123456789abcdef"})
        assert b == "abcdef0123456789abcdef"


class TestBuildAuthJson:
    def test_cookie_join_and_scope(self):
        p = build_auth_json([{"name": "sid", "value": "x", "domain": "t.com"},
                             {"name": "csrf", "value": "y", "domain": "t.com"}], JWT, "t.com")
        assert p["cookie"] == "sid=x; csrf=y"
        assert p["bearer"] == JWT
        assert p["_captured"]["n_cookies"] == 2

    def test_bearer_only_when_no_cookie(self):
        p = build_auth_json([], JWT, "t.com")
        assert "cookie" not in p and p["bearer"] == JWT

    def test_is_authsession_loadable_shape(self):
        p = build_auth_json([{"name": "sid", "value": "x", "domain": "t.com"}], None, "t.com")
        # AuthSession consumes {"cookie": ...} / {"bearer": ...} / {"headers": [...]}
        assert set(p) <= {"cookie", "bearer", "headers", "api_key", "api_key_header", "_captured"}
        json.dumps(p)  # serialisable
