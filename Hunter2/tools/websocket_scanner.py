#!/usr/bin/env python3
"""
Cross-Site WebSocket Hijacking (CSWSH) scanner.

A WebSocket that (a) authenticates via cookies and (b) does not validate the
`Origin` header on the handshake can be opened by an attacker's page in the
victim's browser — the attacker then reads/sends messages as the victim.

This tool performs the raw WebSocket handshake twice: once with a *forged*
cross-site Origin and once with the site's own Origin, and compares. It sends
the caller-supplied cookie so the "authenticated socket" condition is realistic.

The verdict logic is pure and unit-tested; only `scan()` opens a socket.

Severity model:
  HIGH    forged Origin handshake succeeds (101) AND a session cookie was sent
          — classic CSWSH: cross-origin JS can drive the victim's socket.
  MEDIUM  forged Origin succeeds with no cookie (still hijackable if the socket
          later authenticates, or leaks data to any origin).
  LOW     forged Origin rejected but same-origin accepted — Origin is validated
          (report for completeness / to confirm the check can't be bypassed).

Usage:
  tools/websocket_scanner.py wss://target.com/socket --cookie "session=..."
  tools/websocket_scanner.py ws://target.com/ws --origin https://evil.example --json
  tools/websocket_scanner.py -l ws_urls.txt --cookie "s=..."
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import sys
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class WsFinding:
    url: str
    severity: str
    reason: str
    forged_status: int
    legit_status: int


def classify(forged_status: int, legit_status: int, has_cookie: bool) -> WsFinding | None:
    """Pure: decide CSWSH verdict from the two handshake status codes."""
    forged_ok = forged_status == 101
    legit_ok = legit_status == 101
    if forged_ok and has_cookie:
        return WsFinding("", "HIGH",
                         "handshake accepted with a forged cross-site Origin while authenticated — CSWSH",
                         forged_status, legit_status)
    if forged_ok and not has_cookie:
        return WsFinding("", "MEDIUM",
                         "handshake accepts any Origin — hijackable if the socket carries auth; retest with a session cookie",
                         forged_status, legit_status)
    if not forged_ok and legit_ok:
        return WsFinding("", "LOW",
                         "forged Origin rejected but same-origin accepted — Origin appears validated",
                         forged_status, legit_status)
    return None


def _handshake(url: str, origin: str, cookie: str | None, timeout: int) -> int:
    """Open a raw WS handshake and return the HTTP status code (0 on failure)."""
    u = urlparse(url)
    secure = u.scheme == "wss"
    host = u.hostname or ""
    port = u.port or (443 if secure else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}" if u.port else f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        f"Origin: {origin}",
        "User-Agent: Mozilla/5.0 (BugHunter CSWSH scanner)",
    ]
    if cookie:
        lines.append(f"Cookie: {cookie}")
    request = "\r\n".join(lines) + "\r\n\r\n"

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if secure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request.encode())
        data = sock.recv(4096).decode("latin-1", "replace")
        first = data.split("\r\n", 1)[0]  # e.g. "HTTP/1.1 101 Switching Protocols"
        parts = first.split(" ")
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    except (OSError, ssl.SSLError, ValueError, IndexError):
        return 0
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def scan(url: str, forged_origin: str | None = None, cookie: str | None = None, timeout: int = 15) -> list[WsFinding]:
    u = urlparse(url)
    same_origin = f"{'https' if u.scheme == 'wss' else 'http'}://{u.hostname}"
    forged = forged_origin or "https://evil-cswsh-test.example"
    forged_status = _handshake(url, forged, cookie, timeout)
    legit_status = _handshake(url, same_origin, cookie, timeout)
    v = classify(forged_status, legit_status, bool(cookie))
    if v:
        v.url = url
        return [v]
    return []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Cross-Site WebSocket Hijacking (CSWSH) scanner")
    ap.add_argument("url", nargs="?", help="ws:// or wss:// URL")
    ap.add_argument("-l", "--list", help="file of WS URLs (one per line)")
    ap.add_argument("--origin", help="forged Origin header (default: an attacker-style origin)")
    ap.add_argument("--cookie", help="Cookie header (test the authenticated-socket case)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    urls = []
    if args.list:
        with open(args.list) as fh:
            urls = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    elif args.url:
        urls = [args.url]
    else:
        ap.error("provide a URL or -l <file>")

    findings = []
    for u in urls:
        if not u.startswith(("ws://", "wss://")):
            print(f"[skip] not a ws(s) URL: {u}", file=sys.stderr)
            continue
        findings.extend(scan(u, forged_origin=args.origin, cookie=args.cookie, timeout=args.timeout))

    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        if not findings:
            print("[cswsh] nothing flagged")
        for f in findings:
            print(f"[{f.severity}] {f.url} (forged={f.forged_status} legit={f.legit_status}): {f.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
