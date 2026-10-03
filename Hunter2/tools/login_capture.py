#!/usr/bin/env python3
"""
Interactive login capture.

Opens a REAL browser at the target's login page. The human logs in manually —
email, password, OTP, MFA, SSO — all typed into the actual site, never into this
tool or any chat. The tool watches the session, detects a successful login, and
writes the captured cookies + SPA auth tokens to `.private/<target>.json` in the
`AuthSession` format the rest of the toolkit already consumes.

This is how the hunt gets behind the login wall: run this once, then every
downstream tool loads `--auth-file .private/<target>.json`.

SECURITY: credentials are entered into the browser only. This tool reads the
resulting session cookies/tokens (which is the whole point) and stores them in a
gitignored `.private/` file. It never captures keystrokes or passwords.

Detection of "logged in" (any one is sufficient):
  - the URL leaves the login/sign-in path, AND
  - a session-looking cookie appears, OR a JWT/token appears in localStorage.
A manual "press Enter when done" fallback always works.

Usage:
  tools/login_capture.py https://target.com/login
  tools/login_capture.py https://target.com/login --name target --out .private/
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from urllib.parse import urlparse

_LOGIN_PATH = re.compile(r"(login|signin|sign-in|auth|sso|account/login|session/new)", re.I)
_SESSION_COOKIE = re.compile(r"(session|sess|sid|auth|token|jwt|csrf|_ga_auth|connect\.sid|laravel_session|phpsessid)", re.I)
_JWT = re.compile(r"^[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}$")
_TOKEN_KEY = re.compile(r"(token|jwt|auth|access|bearer|id_token|session)", re.I)


def detect_login_success(current_url: str, start_url: str, cookies: list[dict], storage: dict) -> tuple[bool, str | None]:
    """Pure: decide if login succeeded and return (ok, bearer_token_or_None).

    cookies: list of {name, value, ...}. storage: {key: value} from localStorage.
    """
    left_login = bool(_LOGIN_PATH.search(urlparse(start_url).path)) and not _LOGIN_PATH.search(urlparse(current_url).path)
    has_session_cookie = any(_SESSION_COOKIE.search(c.get("name", "")) for c in cookies)

    bearer = None
    for k, v in (storage or {}).items():
        if not isinstance(v, str):
            continue
        if _JWT.match(v.strip()):
            bearer = v.strip()
            break
        if _TOKEN_KEY.search(k) and len(v) >= 16 and " " not in v:
            bearer = v.strip()
    # Success if we moved off login and have *some* credential material,
    # or (SPA that stays on same URL) we found a JWT/token.
    ok = bool((left_login and (has_session_cookie or bearer is not None)) or (bearer is not None and _JWT.match(bearer or "")))
    return ok, bearer


def build_auth_json(cookies: list[dict], bearer: str | None, domain: str) -> dict:
    """Pure: build the AuthSession JSON payload from captured material."""
    host = (domain or "").lower().lstrip(".").rstrip(".")
    scoped = []
    for cookie in cookies:
        cookie_domain = (cookie.get("domain") or "").lower().lstrip(".").rstrip(".")
        if host and cookie_domain and (host == cookie_domain or host.endswith("." + cookie_domain)):
            scoped.append(cookie)
    # Never fall back to unrelated browser cookies. An empty scoped set is safer
    # than sending credentials belonging to another origin.
    cookie_pairs = [f"{c['name']}={c['value']}" for c in scoped if c.get("name")]
    payload: dict = {}
    if cookie_pairs:
        payload["cookie"] = "; ".join(cookie_pairs)
    if bearer:
        payload["bearer"] = bearer
    payload["_captured"] = {"domain": domain, "n_cookies": len(cookie_pairs), "ts": int(time.time())}
    return payload


def _write(payload: dict, out_dir: str, name: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{name}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    try:
        os.chmod(path, 0o600)  # no-op on Windows, enforced on POSIX
    except OSError:
        pass
    return path


def capture(login_url: str, name: str, out_dir: str, timeout_s: int = 600) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[login-capture] Playwright not installed.", file=sys.stderr)
        print("  Install:  pip install playwright && playwright install chromium", file=sys.stderr)
        print("  Or capture a cookie manually from your browser devtools and write:", file=sys.stderr)
        print(f'    {os.path.join(out_dir, name + ".json")}  ->  {{"cookie": "session=..."}}', file=sys.stderr)
        return 2

    domain = urlparse(login_url).hostname or name
    print(f"[login-capture] Opening browser at {login_url}")
    print("[login-capture] Log in manually in the browser window (email/password/OTP/MFA).")
    print("[login-capture] Auto-detecting success; or press Enter here once you are logged in.\n")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        page.goto(login_url, wait_until="domcontentloaded")

        # Poll for auto-detection while the human logs in.
        import threading
        done = {"enter": False}

        def _waiter():
            try:
                input()
                done["enter"] = True
            except EOFError:
                pass
        threading.Thread(target=_waiter, daemon=True).start()

        deadline = time.time() + timeout_s
        bearer = None
        while time.time() < deadline:
            try:
                cookies = context.cookies()
                storage = page.evaluate("() => { const o={}; for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i); o[k]=localStorage.getItem(k);} return o; }")
            except Exception:
                cookies, storage = [], {}
            ok, bearer = detect_login_success(page.url, login_url, cookies, storage)
            if ok or done["enter"]:
                # If the user hit Enter, capture whatever exists now.
                if done["enter"] and not ok:
                    print("[login-capture] Manual confirm — capturing current session.")
                break
            time.sleep(2)
        else:
            print("[login-capture] Timed out waiting for login.", file=sys.stderr)

        cookies = context.cookies()
        payload = build_auth_json(cookies, bearer, domain)
        browser.close()

    if not payload.get("cookie") and not payload.get("bearer"):
        print("[login-capture] No session material captured — did login complete?", file=sys.stderr)
        return 1
    path = _write(payload, out_dir, name)
    print(f"\n[login-capture] Saved session -> {path}")
    print(f"[login-capture] Captured: {'cookie ' if payload.get('cookie') else ''}"
          f"{'bearer' if payload.get('bearer') else ''}".strip())
    print(f"[login-capture] Use it:  --auth-file {path}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Interactive login capture -> .private/<target>.json")
    ap.add_argument("login_url", nargs="?", help="the target's login page URL")
    ap.add_argument("--name", help="output file basename (default: the hostname)")
    ap.add_argument("--out", default=".private", help="output directory (default: .private/)")
    ap.add_argument("--timeout", type=int, default=600, help="seconds to wait for login (default 600)")
    args = ap.parse_args(argv)
    if not args.login_url:
        ap.error("provide the login page URL")
    name = args.name or (urlparse(args.login_url).hostname or "target").replace(":", "_")
    return capture(args.login_url, name, args.out, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
