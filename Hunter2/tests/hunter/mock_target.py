#!/usr/bin/env python3
"""A deterministic, socket-free mock target for end-to-end engine testing.

:class:`MockApp` exposes ``.fetch(method, url, headers=None, body=None) -> Resp``
with the same shape the engine injects as ``ctx.fetch``, so the whole hunt loop
can be driven offline against a realistic SPA + authenticated API. Identity is
taken from the ``Authorization: Bearer A`` / ``Bearer B`` header - the two
accounts the operator "owns". Any other/absent token is anonymous.

Planted behaviours (each is a deliberate fixture for one class of test):

* **SPA catch-all** - any unknown path returns the same 200 HTML shell, so
  ``tools/spa_baseline.py`` can fingerprint it and kits can treat it as noise.
* **Public bait** - ``/api/public/info`` returns the same body to anon and to
  A and B: a two-account scanner must classify this PUBLIC, not a bug.
* **Cross-account READ BOLA** - ``GET /api/product/<id>/`` returns the object to
  *any* authenticated token, so A can read B's product.
* **Properly isolated** - ``GET /api/order/<id>/`` returns 403 to a non-owner;
  a kit must NOT flag it.
* **Cross-account WRITE BOLA** - ``PATCH /api/coupon/<id>/`` is accepted from any
  token and mutates stored state, so a write test can confirm then revert.
* **BFLA** - ``/api/report/<id>/`` serves GET but *wrongly* also accepts DELETE.
* **Reflected XSS** - ``GET /api/echo?q=`` reflects ``q`` unescaped.
* **Open redirect** - ``GET /api/redirect?next=`` 302s to ``next`` unvalidated.
* **CORS** - ``GET /api/account/me`` is authed JSON with
  ``Access-Control-Allow-Origin: *``.

All mutable state lives in plain dicts, so writes are observable and revertible;
:meth:`reset` restores the seed. Nothing here opens a socket.
"""
from __future__ import annotations

import copy
import json
import os
import re
import sys
from urllib.parse import parse_qs, urlparse

# Make ``tools`` importable when this file is imported by a test (the test-suite
# conftest also does this) or run on its own.
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter.contract import Resp  # noqa: E402

# One fixed SPA shell, returned byte-for-byte for every unknown path.
SHELL = (
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<title>Mock SPA</title></head><body><div id=root></div>"
    "<script src=\"/static/app.js\"></script></body></html>"
)

# The public endpoint's body - identical for anon, A and B (false-positive bait).
_PUBLIC_BODY = {"service": "catalog", "version": "1.0", "public": True}

_PRODUCT_RE = re.compile(r"^/api/product/([^/]+)/?$")
_ORDER_RE = re.compile(r"^/api/order/([^/]+)/?$")
_COUPON_RE = re.compile(r"^/api/coupon/([^/]+)/?$")
_REPORT_RE = re.compile(r"^/api/report/([^/]+)/?$")
_PROFILE_RE = re.compile(r"^/api/profile/([^/]+)/?$")


def _seed_state() -> dict:
    """The initial owned-object graph. A owns the low ids; B the high ones."""
    return {
        "products": {
            "1": {"id": "1", "owner": "A", "name": "Alpha Widget", "price_paise": 10000},
            "2": {"id": "2", "owner": "B", "name": "Bravo Gadget", "price_paise": 25000},
        },
        "orders": {
            "10": {"id": "10", "owner": "A", "total_paise": 10000, "status": "paid"},
            "11": {"id": "11", "owner": "B", "total_paise": 25000, "status": "paid"},
        },
        "coupons": {
            "100": {"id": "100", "owner": "A", "code": "ALPHA10", "percent": 10},
            "101": {"id": "101", "owner": "B", "code": "BRAVO15", "percent": 15},
        },
        "reports": {
            "1000": {"id": "1000", "owner": "A", "title": "Alpha report"},
            "1001": {"id": "1001", "owner": "B", "title": "Bravo report"},
        },
        # Profiles carry a benign, revertible string field ("description"), so a
        # cross-account WRITE BOLA can be confirmed-then-reverted end-to-end.
        "profiles": {
            "500": {"id": "500", "owner": "A", "display_name": "Alice",
                    "description": "Alpha owner bio"},
            "501": {"id": "501", "owner": "B", "display_name": "Bob",
                    "description": "Bravo owner bio"},
        },
    }


class MockApp:
    """An in-memory SPA + authed API. See the module docstring for the fixtures."""

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        """Restore all mutable state to the seed (handy between test cases)."""
        state = _seed_state()
        self.products = state["products"]
        self.orders = state["orders"]
        self.coupons = state["coupons"]
        self.reports = state["reports"]
        self.profiles = state["profiles"]
        self._seed = copy.deepcopy(state)

    # --- helpers -------------------------------------------------------------

    @staticmethod
    def _auth(headers) -> "str | None":
        """Return 'A' / 'B' for a recognised bearer token, else None (anon)."""
        for key, value in (headers or {}).items():
            if key.lower() == "authorization":
                token = str(value).strip()
                if token.lower().startswith("bearer "):
                    token = token[7:].strip()
                return token if token in ("A", "B") else None
        return None

    @staticmethod
    def _json(status: int, obj, extra_headers: "dict | None" = None) -> Resp:
        headers = {"Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        return Resp(status=status, body=json.dumps(obj), headers=headers)

    @staticmethod
    def _html(status: int, html: str, extra_headers: "dict | None" = None) -> Resp:
        headers = {"Content-Type": "text/html; charset=utf-8"}
        if extra_headers:
            headers.update(extra_headers)
        return Resp(status=status, body=html, headers=headers)

    @staticmethod
    def _as_dict(body) -> "dict | None":
        if isinstance(body, dict):
            return body
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8", "replace")
        if isinstance(body, str) and body.strip():
            try:
                parsed = json.loads(body)
                return parsed if isinstance(parsed, dict) else None
            except ValueError:
                return None
        return None

    # --- the router ----------------------------------------------------------

    def fetch(self, method, url, headers=None, body=None) -> Resp:
        method = (method or "GET").upper()
        parsed = urlparse(url)
        path = parsed.path or "/"
        query = parse_qs(parsed.query)
        who = self._auth(headers)

        # Public bait: same body to everyone, no auth required.
        if path == "/api/public/info":
            return self._json(200, dict(_PUBLIC_BODY))

        # Reflected XSS (pre-auth): q is echoed into HTML without encoding.
        if path == "/api/echo":
            q = (query.get("q") or [""])[0]
            return self._html(
                200, f"<!doctype html><html><body><div>Search: {q}</div></body></html>")

        # Open redirect (pre-auth): next is trusted verbatim in Location.
        if path == "/api/redirect":
            nxt = (query.get("next") or [""])[0]
            return Resp(status=302, body="", headers={"Location": nxt})

        # CORS on an authed JSON endpoint: ACAO:* + credentials.
        if path == "/api/account/me":
            if who is None:
                return self._json(401, {"error": "authentication required"})
            return self._json(
                200,
                {"user_id": who, "email": f"{who.lower()}@mock.local"},
                extra_headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                },
            )

        # Cross-account READ BOLA: any authenticated token gets any product.
        m = _PRODUCT_RE.match(path)
        if m:
            if who is None:
                return self._json(401, {"error": "authentication required"})
            obj = self.products.get(m.group(1))
            if obj is None:
                return self._json(404, {"error": "not found"})
            return self._json(200, dict(obj))  # BUG: no ownership check

        # Properly isolated: order is returned only to its owner.
        m = _ORDER_RE.match(path)
        if m:
            if who is None:
                return self._json(401, {"error": "authentication required"})
            obj = self.orders.get(m.group(1))
            if obj is None:
                return self._json(404, {"error": "not found"})
            if obj["owner"] != who:
                return self._json(403, {"error": "forbidden"})  # correct isolation
            return self._json(200, dict(obj))

        # Coupon: GET readable to any auth; PATCH/PUT is the cross-account WRITE
        # BOLA and mutates stored state (so a test can confirm then revert).
        m = _COUPON_RE.match(path)
        if m:
            cid = m.group(1)
            if who is None:
                return self._json(401, {"error": "authentication required"})
            obj = self.coupons.get(cid)
            if obj is None:
                return self._json(404, {"error": "not found"})
            if method == "GET":
                return self._json(200, dict(obj))
            if method in ("PATCH", "PUT"):
                patch = self._as_dict(body)
                if patch is None:
                    return self._json(400, {"error": "invalid body"})
                for field in ("code", "percent"):
                    if field in patch:
                        obj[field] = patch[field]  # BUG: any token may mutate
                self.coupons[cid] = obj
                return self._json(200, dict(obj))
            return self._json(405, {"error": "method not allowed"})

        # BFLA: GET is fine, but DELETE is wrongly accepted from any user.
        m = _REPORT_RE.match(path)
        if m:
            rid = m.group(1)
            if who is None:
                return self._json(401, {"error": "authentication required"})
            obj = self.reports.get(rid)
            if method == "GET":
                if obj is None:
                    return self._json(404, {"error": "not found"})
                return self._json(200, dict(obj))
            if method == "DELETE":
                if obj is None:
                    return self._json(404, {"error": "not found"})
                del self.reports[rid]  # BUG: BFLA via method swap
                return self._json(200, {"deleted": rid})
            return self._json(405, {"error": "method not allowed"})

        # Profile: GET readable to any auth; PATCH/PUT is a cross-account WRITE
        # BOLA that mutates a benign string field ("description"/"display_name"),
        # so the write axis can confirm the change then auto-revert it.
        m = _PROFILE_RE.match(path)
        if m:
            pid = m.group(1)
            if who is None:
                return self._json(401, {"error": "authentication required"})
            obj = self.profiles.get(pid)
            if obj is None:
                return self._json(404, {"error": "not found"})
            if method == "GET":
                return self._json(200, dict(obj))  # BUG: no ownership check
            if method in ("PATCH", "PUT"):
                patch = self._as_dict(body)
                if patch is None:
                    return self._json(400, {"error": "invalid body"})
                for field in ("description", "display_name"):
                    if field in patch:
                        obj[field] = patch[field]  # BUG: any token may mutate
                self.profiles[pid] = obj
                return self._json(200, dict(obj))
            return self._json(405, {"error": "method not allowed"})

        # Everything else is the SPA catch-all shell.
        return self._html(200, SHELL)
