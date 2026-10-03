#!/usr/bin/env python3
"""
Two-account IDOR / BOLA harness — the #1 expert move for cross-tenant bugs.

Given a list of endpoints and TWO authenticated account contexts (A and B —
the operator's *own* accounts), this replays account A's request using account
B's credentials (and confirms with no auth at all) to detect when one account
can read the other's data. That cross-account read is the signature of an
Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization
(BOLA) / privilege-escalation bug.

Workflow: the operator collects URLs that return *account A's* private data
(e.g. https://api.target.com/users/<A-id>/orders), stores both accounts' auth
in a .env, and points this tool at those URLs. For each one:

  1. request with A's auth   -> baseline (should be 200 + A's data)
  2. request with B's auth   -> if it *also* returns A's data => cross-account read
  3. request with NO auth    -> if anon already returns it, the resource is public
                                (NOT a bug) and the "leak" is a false positive.

Safety (mirrors the repo's SafeMethodPolicy philosophy):
  - Only SAFE, non-state-changing methods run by default: GET / HEAD / OPTIONS.
  - State-changing methods (POST/PUT/PATCH/DELETE) are SKIPPED unless --unsafe
    is passed, so a detection run never mutates the target's data.
  - Requests go through safe_urlopen (SSRF-safe: validates every redirect hop).
  - The returned findings NEVER contain raw auth tokens or full response bodies
    — only statuses, body lengths, and a short redacted snippet.

The detection/classification logic is pure and injectable (pass a fake `fetch`)
so it is unit-tested without touching the network.

Usage:
  tools/two_account_idor.py https://api.target.com/users/123/orders
  tools/two_account_idor.py -l endpoints.txt --json
  tools/two_account_idor.py -l endpoints.txt --unsafe        # also test POST/PUT/...
  # endpoints.txt lines may be "URL" or "METHOD URL", e.g. "GET https://.../1"

.env keys (see tools/credential_store.py):
  ACCOUNT_A_TOKEN=<bearer>     and/or  ACCOUNT_A_COOKIE=<cookie header value>
  ACCOUNT_B_TOKEN=<bearer>     and/or  ACCOUNT_B_COOKIE=<cookie header value>
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Callable

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
from tools.credential_store import CredentialStore  # noqa: E402
from tools.safe_http import safe_urlopen  # noqa: E402

USER_AGENT = "agentic-bug-hunter/two_account_idor"

log = logging.getLogger("two_account_idor")

# Safe, non-state-changing methods — allowed without --unsafe.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Verdict constants.
PUBLIC = "public"
POSSIBLE_IDOR = "POSSIBLE_IDOR"
ISOLATED = "properly_isolated"
INCONCLUSIVE = "inconclusive"
SKIPPED = "skipped_unsafe"

# Bodies count as "the same data" when identical, or when their lengths are
# within 5% of each other (dynamic timestamps/CSRF tokens shift a few bytes but
# the leaked record is otherwise the same).
_LEN_RATIO_THRESHOLD = 0.95

# fetch(url, headers) -> (status:int, body:str)
Fetch = Callable[[str, dict], tuple]


def _snippet(body: str, limit: int = 120) -> str:
    """A short, single-line, length-capped excerpt of a response body.

    Response *bodies* are the leaked data, not credentials — auth tokens live
    in request headers, which are never placed in a finding. Still capped hard
    so a finding stays terse and never carries a full body around.
    """
    if not body:
        return ""
    flat = " ".join(body.split())
    return flat[:limit]


def _similar(body_a: str, body_b: str) -> bool:
    """True if two bodies represent the same underlying data.

    Exact match, OR a length ratio above the threshold (small dynamic diffs).
    """
    if body_a == body_b:
        return True
    la, lb = len(body_a), len(body_b)
    if la == 0 or lb == 0:
        return la == lb
    return (min(la, lb) / max(la, lb)) > _LEN_RATIO_THRESHOLD


def _default_fetch(url: str, method: str, headers: dict, timeout: int) -> tuple:
    """Real HTTP fetch via the SSRF-safe wrapper. Returns (status, body).

    Network/DNS failures return (0, "") so a single dead host never aborts a
    batch. HTTPError (4xx/5xx) still carries a status + body and is reported.
    """
    req_headers = {"User-Agent": USER_AGENT}
    req_headers.update(headers or {})
    req = urllib.request.Request(url, headers=req_headers, method=method)
    try:
        with safe_urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return (resp.status, body)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return (e.code, body)
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError):
        return (0, "")


def test_endpoint(
    url: str,
    method: str,
    a_headers: dict,
    b_headers: dict,
    timeout: int = 15,
    fetch: Fetch | None = None,
) -> dict:
    """Replay one endpoint as A, then B, then anon, and classify the result.

    Args:
        url: the endpoint that returns account A's data.
        method: HTTP method (GET/HEAD/OPTIONS unless the caller allowed unsafe).
        a_headers: account A's auth headers.
        b_headers: account B's auth headers.
        timeout: per-request timeout (seconds), used only by the default fetch.
        fetch: optional injectable `fetch(url, headers) -> (status, body)`.
            Defaults to a real safe_urlopen-based fetch bound to `method`.

    Returns:
        A dict with url, method, status_a, status_b, status_anon, body_len_a,
        body_len_b, verdict, reason (+ a short redacted snippet on a leak).
        NEVER contains raw tokens or full bodies.

    Verdicts:
        public            anon already sees A's body (resource is unauthenticated).
        POSSIBLE_IDOR     A=200 and B=200 with the same body => B reads A's data.
        properly_isolated A=200 but B is denied (401/403).
        inconclusive      no clean baseline, or B got an unexpected status.
    """
    method = (method or "GET").upper()
    if fetch is None:
        def fetch(u: str, h: dict) -> tuple:  # bind method + timeout
            return _default_fetch(u, method, h, timeout)

    status_a, body_a = fetch(url, a_headers)
    status_b, body_b = fetch(url, b_headers)
    status_anon, body_anon = fetch(url, {})

    result: dict = {
        "url": url,
        "method": method,
        "status_a": status_a,
        "status_b": status_b,
        "status_anon": status_anon,
        "body_len_a": len(body_a),
        "body_len_b": len(body_b),
    }

    # Public resource: anon already returns the same body A sees. This is the
    # critical false-positive guard — no auth boundary exists, so B "reading"
    # it is not a bug. Checked first so it can veto a would-be IDOR.
    if status_anon == 200 and _similar(body_anon, body_a):
        result["verdict"] = PUBLIC
        result["reason"] = "resource is public/unauthenticated (anon sees the same body as account A)"
        return result

    # Need a clean 200 baseline from A to reason about cross-account access.
    if status_a != 200:
        result["verdict"] = INCONCLUSIVE
        result["reason"] = f"no baseline: account A got {status_a} (expected 200) for its own resource"
        return result

    # A is authenticated and sees its data. Does B see the SAME data?
    if status_b == 200 and _similar(body_a, body_b):
        result["verdict"] = POSSIBLE_IDOR
        result["reason"] = "account B receives account A's data (same 200 body) — cross-account read"
        result["snippet"] = _snippet(body_a)
        return result

    if status_b in (401, 403):
        result["verdict"] = ISOLATED
        result["reason"] = f"account B is denied ({status_b}) access to account A's resource"
        return result

    result["verdict"] = INCONCLUSIVE
    result["reason"] = (
        f"account A=200, account B={status_b}; bodies differ or B returned an unexpected status"
    )
    return result


def _account_headers(store: CredentialStore, prefix: str) -> dict:
    """Build auth headers for one account, preferring a bearer TOKEN over COOKIE."""
    token_key = f"{prefix}_TOKEN"
    cookie_key = f"{prefix}_COOKIE"
    if store.has(token_key):
        return store.as_headers(token_key, header_type="bearer")
    if store.has(cookie_key):
        return store.as_headers(cookie_key, header_type="cookie")
    return {}


def _parse_entry(entry: str) -> tuple:
    """Parse a URL-list line into (method, url). 'METHOD URL' or just 'URL'."""
    parts = entry.split(None, 1)
    if len(parts) == 2 and parts[0].isalpha() and parts[0].upper() in (
        SAFE_METHODS | {"POST", "PUT", "PATCH", "DELETE"}
    ):
        return parts[0].upper(), parts[1].strip()
    return "GET", entry.strip()


def run(
    urls: list,
    store: CredentialStore,
    unsafe: bool = False,
    timeout: int = 15,
    fetch: Fetch | None = None,
    sleep: float = 0.3,
) -> list:
    """Test every endpoint for a cross-account read and return findings.

    Builds A/B auth headers from the store (bearer TOKEN preferred, else
    COOKIE). If either account's credentials are missing, logs a warning and
    returns [] — the harness is meaningless without two accounts.

    Rate-limits politely with a small `sleep` between requests. State-changing
    methods are skipped unless `unsafe=True`.
    """
    a_headers = _account_headers(store, "ACCOUNT_A")
    b_headers = _account_headers(store, "ACCOUNT_B")
    if not a_headers or not b_headers:
        log.warning(
            "two-account IDOR harness needs BOTH accounts: set ACCOUNT_A_TOKEN/"
            "ACCOUNT_A_COOKIE and ACCOUNT_B_TOKEN/ACCOUNT_B_COOKIE in the .env — "
            "skipping (A creds present=%s, B creds present=%s)",
            bool(a_headers), bool(b_headers),
        )
        return []

    findings: list = []
    first = True
    for entry in urls:
        method, url = _parse_entry(entry)
        if not url:
            continue
        if method not in SAFE_METHODS and not unsafe:
            log.warning(
                "skipping state-changing method %s %s — re-run with --unsafe to test it",
                method, url,
            )
            findings.append({
                "url": url,
                "method": method,
                "verdict": SKIPPED,
                "reason": "state-changing method skipped (no --unsafe); detection-only by default",
            })
            continue

        # Polite rate-limit between network requests (not before the first one).
        if not first and sleep and fetch is None:
            time.sleep(sleep)
        first = False

        findings.append(
            test_endpoint(url, method, a_headers, b_headers, timeout=timeout, fetch=fetch)
        )
    return findings


def _print_human(store: CredentialStore, findings: list) -> None:
    # Show which accounts are loaded, masked — never the raw token values.
    def _mask(prefix: str) -> str:
        for suffix in ("_TOKEN", "_COOKIE"):
            key = prefix + suffix
            if store.has(key):
                return f"{key}={store.get_masked(key)}"
        return "(none)"

    print(f"\n=== Two-account IDOR/BOLA harness ===")
    print(f"  Account A: {_mask('ACCOUNT_A')}")
    print(f"  Account B: {_mask('ACCOUNT_B')}")
    if not findings:
        print("  no endpoints tested (missing credentials or empty URL list)\n")
        return

    leaks = [f for f in findings if f.get("verdict") == POSSIBLE_IDOR]
    for f in findings:
        v = f.get("verdict")
        marker = "  <-- CROSS-ACCOUNT READ — INVESTIGATE" if v == POSSIBLE_IDOR else ""
        print(f"\n  [{v}] {f['method']} {f['url']}{marker}")
        if "status_a" in f:
            print(
                f"      A={f['status_a']} ({f['body_len_a']}b)  "
                f"B={f['status_b']} ({f['body_len_b']}b)  anon={f['status_anon']}"
            )
        print(f"      {f.get('reason', '')}")
        if f.get("snippet"):
            print(f"      snippet: {f['snippet']}")
    if leaks:
        print(f"\n  {len(leaks)} POSSIBLE_IDOR finding(s) — verify manually before reporting.")
    print()


def main(argv: list | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    ap = argparse.ArgumentParser(description="Two-account IDOR/BOLA harness (detection-only, SAFE)")
    ap.add_argument("url", nargs="?", help="a single endpoint that returns account A's data")
    ap.add_argument("-l", "--list", help="file of endpoints, one per line ('URL' or 'METHOD URL')")
    ap.add_argument("--env", default=".env", help="path to the .env credential file (default: .env)")
    ap.add_argument("--unsafe", action="store_true",
                    help="also test state-changing methods (POST/PUT/PATCH/DELETE)")
    ap.add_argument("--timeout", type=int, default=15, help="per-request timeout in seconds")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    urls: list = []
    if args.list:
        from pathlib import Path
        urls += [l.strip() for l in Path(args.list).read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.strip().startswith("#")]
    if args.url:
        urls.append(args.url)
    if not urls:
        ap.error("provide a URL or -l <file>")

    store = CredentialStore(args.env)
    findings = run(urls, store, unsafe=args.unsafe, timeout=args.timeout)

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        _print_human(store, findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
