#!/usr/bin/env python3
"""Default SSRF-safe fetch for the Hunter Engine.

The engine injects ``ctx.fetch``; in a live run that fetcher is the one built
here by :func:`default_fetch`. Every kit makes its requests through it, so a
single implementation enforces, for the whole engine:

* **SSRF-safety** - it wraps :func:`tools.safe_http.safe_urlopen`, which refuses
  to follow a redirect hop into private / loopback / link-local / metadata
  address space (see that module's header and SECURITY-REVIEW-2026-08-22).
* **In-scope-host policy** - when ``scope_hosts`` is given, a request whose host
  is out of scope returns ``None`` without touching the network, and any
  redirect that would leave scope is refused by ``safe_urlopen`` too.

Nothing here is exercised in the offline test-suite: kits are unit-tested with
an injected fake ``fetch`` (and the engine's own tests with the mock target).
This module is the real-network adapter the engine reaches for in production.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urlparse

# Make the repo importable whether this file is imported as
# ``tools.hunter.net`` or executed directly as a script (mirrors the pattern
# used by tools/two_account_idor.py and tools/validate.py).
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.safe_http import safe_urlopen  # noqa: E402
from tools.hunter.contract import Resp  # noqa: E402

USER_AGENT = "agentic-bug-hunter/hunter-net"

# Cap the number of body bytes read, so a hostile or accidentally huge response
# can never exhaust memory. Kits reason over statuses, lengths and short
# snippets, not multi-megabyte bodies.
_BODY_CAP = 1_000_000


def _host_in_scope(host: Optional[str], scope_hosts: tuple) -> bool:
    """Mirror :meth:`HuntContext.in_scope`.

    An empty ``scope_hosts`` means "no scope gate" (everything allowed).
    Otherwise the host must equal, or be a sub-domain of, one of the in-scope
    hosts (a leading ``*.`` on a scope entry is stripped first).
    """
    if not scope_hosts:
        return True
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for raw in scope_hosts:
        h = str(raw).lower().lstrip("*.").rstrip(".")
        if not h:
            continue
        if host == h or host.endswith("." + h):
            return True
    return False


def _encode_body(body, headers: dict):
    """Return the request body as bytes (or ``None``).

    A dict/list is serialised to JSON and, unless the caller already set one, a
    ``Content-Type: application/json`` header is added. A str is UTF-8 encoded;
    bytes are sent unchanged.
    """
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        data = json.dumps(body).encode("utf-8")
        if not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/json"
        return data
    if isinstance(body, bytes):
        return body
    return str(body).encode("utf-8")


def _read_response(resp) -> Resp:
    """Turn a urllib response (or an HTTPError, which doubles as one) into a
    :class:`Resp`. ``elapsed_ms`` is filled in by the caller."""
    status = getattr(resp, "status", None)
    if status is None:
        status = getattr(resp, "code", 0) or 0
    try:
        raw = resp.read(_BODY_CAP)
    except Exception:
        raw = b""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    try:
        headers = {k: v for k, v in resp.headers.items()}
    except Exception:
        headers = {}
    return Resp(status=int(status), body=text, headers=headers)


def default_fetch(timeout: int = 15, scope_hosts: tuple = ()):
    """Build the engine's real fetch callable.

    Returns ``fetch(method, url, headers=None, body=None) -> Resp | None``:

    * Returns ``None`` on a network/DNS error, so a dead host never aborts a
      run; an HTTP error *status* (4xx/5xx) comes back as a normal ``Resp``.
    * Returns ``None`` for an out-of-scope host when ``scope_hosts`` is set,
      without issuing any request.
    * ``body`` may be a dict/list (sent as JSON) or a str.
    """
    scope_hosts = tuple(scope_hosts or ())

    def fetch(method, url, headers=None, body=None) -> Optional[Resp]:
        hdrs = dict(headers or {})
        hdrs.setdefault("User-Agent", USER_AGENT)

        # Scope gate: never issue a request to an out-of-scope host.
        if not _host_in_scope(urlparse(url).hostname, scope_hosts):
            return None

        data = _encode_body(body, hdrs)
        method_u = (method or "GET").upper()

        # Enforce scope on every redirect hop too (closes the "in-scope host
        # 302s us out of scope" gap). safe_urlopen raises URLError on a blocked
        # hop, which the except below turns into a None result.
        scope_check = None
        if scope_hosts:
            scope_check = lambda h: _host_in_scope(h, scope_hosts)  # noqa: E731

        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method_u)
            resp = safe_urlopen(req, timeout=timeout, scope_check=scope_check)
            out = _read_response(resp)
        except urllib.error.HTTPError as exc:
            # HTTPError is itself a readable response object (.code/.headers).
            out = _read_response(exc)
        except (urllib.error.URLError, OSError, ValueError):
            # DNS failure, connection refused/reset, blocked redirect, bad URL:
            # a dead or disallowed host must never abort the hunt.
            return None
        out.elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return out

    return fetch


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        description="Default SSRF-safe fetch for the Hunter Engine (the real "
                    "ctx.fetch used in a live run).")
    ap.add_argument("url", nargs="?",
                    help="optional URL to fetch once, as a live smoke test")
    ap.add_argument("--method", default="GET", help="HTTP method (default GET)")
    ap.add_argument("--timeout", type=int, default=15, help="timeout seconds (default 15)")
    ap.add_argument("--scope", action="append", default=[], metavar="HOST",
                    help="in-scope host; repeatable. Out-of-scope URLs return None.")
    args = ap.parse_args(argv)

    if not args.url:
        print("hunter.net.default_fetch(timeout=15, scope_hosts=()) -> "
              "fetch(method, url, headers=None, body=None) -> Resp | None")
        print("Pass a URL to perform a single live smoke fetch.")
        return 0

    fetch = default_fetch(timeout=args.timeout, scope_hosts=tuple(args.scope))
    resp = fetch(args.method, args.url)
    if resp is None:
        print("-> None (out of scope, or a network/DNS error)")
        return 0
    print(f"-> status={resp.status} bytes={len(resp.body)} elapsed_ms={resp.elapsed_ms}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
