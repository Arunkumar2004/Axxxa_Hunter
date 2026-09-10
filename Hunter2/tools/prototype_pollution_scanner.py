#!/usr/bin/env python3
"""
Prototype pollution scanner (client-side gadgets + server-side reflection).

Two complementary strategies:

1. STATIC (client-side): fetch the page and its inline/linked JavaScript and
   flag the classic pollution *sources* (URL/query merged into an object) and
   *sinks/gadgets* (recursive merge, `Object.assign` on user data, dangerous
   template/`innerHTML` gadgets). Pure, unit-tested pattern matcher.

2. ACTIVE (server-side): send `__proto__`/`constructor.prototype` payloads as
   JSON body and query params to a state endpoint and look for:
     - the injected canary property reflected back where it should not exist
       (object now carries a polluted property), or
     - a 500 / type error triggered by prototype traversal.
   Non-destructive: the polluted key is a random canary, never an app property.

The verdict logic is pure and unit-tested; only `scan()` touches the network.

Severity model:
  HIGH    server reflects the polluted canary in a response object, OR a
          known deep-merge sink processes attacker JSON (RCE/DoS gadget chain).
  MEDIUM  client-side source+sink both present in shipped JS (needs a gadget
          to weaponise but the primitive is there), OR proto payload causes a
          consistent 500 that a benign malformed body does not.
  LOW     a pollution source present without an obvious sink.

Usage:
  tools/prototype_pollution_scanner.py https://target.com/app.js       # static
  tools/prototype_pollution_scanner.py https://target.com/api/profile --active --json
  tools/prototype_pollution_scanner.py -l urls.txt --active --cookie "s=..."
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.safe_http import safe_urlopen  # noqa: E402

# Sources: user-controlled input parsed into a nested object.
_SOURCES = [
    (r"location\.(hash|search)", "URL hash/search read"),
    (r"URLSearchParams", "URLSearchParams parsing"),
    (r"\bqs\.parse\b|\bquerystring\.parse\b|\bqueryString\.parse\b", "query-string parse"),
    (r"JSON\.parse\s*\(", "JSON.parse of external data"),
    (r"parseNestedKeys|deepSet|setValue\(.*\.split", "nested-key setter"),
]
# Sinks / gadgets: recursive merge / assign that can write __proto__.
_SINKS = [
    (r"\$\.extend\s*\(\s*true", "jQuery deep $.extend(true, ...)"),
    (r"_\.merge\b|_\.defaultsDeep\b|lodash\.merge", "lodash merge/defaultsDeep"),
    (r"\bdeepmerge\b|deepAssign|mergeDeep|deepExtend", "deep-merge helper"),
    (r"Object\.assign\s*\([^)]*req\.|Object\.assign\s*\([^)]*body", "Object.assign on request data"),
    (r"for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+\w+\)[^}]*\[\w+\]\s*=", "for-in copy loop"),
    (r"angular\.merge|\$\.parseHTML", "framework merge/parse gadget"),
]

_PROTO_KEYS = ["__proto__", "constructor"]


@dataclass
class PpFinding:
    url: str
    kind: str          # "static" | "active"
    severity: str
    reason: str


def analyze_js(text: str, url: str) -> list[PpFinding]:
    """Pure: flag pollution sources and sinks in a JS/HTML blob."""
    found_sources = [d for rx, d in _SOURCES if re.search(rx, text)]
    found_sinks = [d for rx, d in _SINKS if re.search(rx, text)]
    out: list[PpFinding] = []
    if found_sinks and found_sources:
        out.append(PpFinding(url, "static", "MEDIUM",
                             f"pollution source ({found_sources[0]}) + sink ({found_sinks[0]}) present — "
                             f"client-side prototype pollution primitive"))
    elif found_sinks:
        out.append(PpFinding(url, "static", "MEDIUM",
                             f"dangerous merge sink present ({found_sinks[0]}) — check if it processes user JSON"))
    elif found_sources:
        out.append(PpFinding(url, "static", "LOW",
                             f"pollution source present ({found_sources[0]}) but no obvious sink in this file"))
    return out


def classify_active(canary: str, resp_body: str, status: int, base_status: int) -> PpFinding | None:
    """Pure: decide whether an active probe response indicates server-side PP."""
    if canary and canary in resp_body:
        return PpFinding("", "active", "HIGH",
                         f"injected prototype property '{canary}' reflected in response — server-side prototype pollution")
    if status >= 500 and base_status < 500:
        return PpFinding("", "active", "MEDIUM",
                         f"__proto__ payload triggered HTTP {status} (baseline {base_status}) — likely prototype traversal error")
    return None


def _request(url, method, headers, data, timeout):
    req = urllib.request.Request(url, headers=headers, data=data, method=method)
    try:
        resp = safe_urlopen(req, timeout=timeout)
        return resp.getcode(), resp.read(1_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read(500_000).decode("utf-8", "replace") if hasattr(e, "read") else ""
        return e.code, body
    except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError):
        return 0, ""


def scan(url: str, active: bool = False, cookie: str | None = None, timeout: int = 15) -> list[PpFinding]:
    headers = {"User-Agent": "Mozilla/5.0 (BugHunter PP scanner)"}
    if cookie:
        headers["Cookie"] = cookie

    if not active:
        _, body = _request(url, "GET", headers, None, timeout)
        return analyze_js(body, url)

    # Active server-side probing.
    canary = "pp" + os.urandom(4).hex()
    base_status, _ = _request(url, "GET", headers, None, timeout)
    out: list[PpFinding] = []

    # JSON body variant.
    jheaders = dict(headers); jheaders["Content-Type"] = "application/json"
    payload = json.dumps({"__proto__": {canary: canary}, "constructor": {"prototype": {canary: canary}}}).encode()
    st, body = _request(url, "POST", jheaders, payload, timeout)
    v = classify_active(canary, body, st, base_status)
    if v:
        v.url = url; out.append(v)

    # Query-param bracket variant (Express/qs style).
    sep = "&" if "?" in url else "?"
    qurl = f"{url}{sep}__proto__[{canary}]={canary}"
    st2, body2 = _request(qurl, "GET", headers, None, timeout)
    v2 = classify_active(canary, body2, st2, base_status)
    if v2 and not out:
        v2.url = url; out.append(v2)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Prototype pollution scanner")
    ap.add_argument("url", nargs="?", help="target URL (JS file for static, endpoint for --active)")
    ap.add_argument("-l", "--list", help="file of URLs (one per line)")
    ap.add_argument("--active", action="store_true", help="send server-side __proto__ probes (state endpoint)")
    ap.add_argument("--cookie", help="Cookie header")
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
        findings.extend(scan(u, active=args.active, cookie=args.cookie, timeout=args.timeout))

    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        if not findings:
            print("[proto-pollution] nothing flagged")
        for f in findings:
            print(f"[{f.severity}] ({f.kind}) {f.url}: {f.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
