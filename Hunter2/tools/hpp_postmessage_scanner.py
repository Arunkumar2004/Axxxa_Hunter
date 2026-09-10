#!/usr/bin/env python3
"""
HTTP Parameter Pollution (HPP) + postMessage listener scanner.

Two web attack surfaces that both hinge on trusting duplicated / cross-context
input:

1. HPP (server-side): send a parameter twice (`?x=A&x=B`) and compare how the
   app resolves it against the single-value baseline. Divergent handling
   (first-wins vs last-wins vs concatenation) enables WAF/validation bypass and
   auth/logic confusion (e.g. a filter checks the first `x`, the sink uses the
   last). Pure differential classifier.

2. postMessage (client-side): fetch the page/JS and flag `message` event
   listeners that consume `event.data` without checking `event.origin`. That is
   a cross-origin injection source (DOM XSS / state tampering / token theft).
   Pure, unit-tested pattern matcher.

The verdict logic is pure and unit-tested; only `scan()` touches the network.

Severity model:
  HIGH    postMessage listener uses event.data in a dangerous sink (innerHTML,
          eval, location) with no origin check.
  MEDIUM  HPP: duplicated parameter changes the response meaningfully (bypass
          primitive), OR a message listener with no origin check (non-obvious sink).
  LOW     HPP handling differs only cosmetically; recorded for manual review.

Usage:
  tools/hpp_postmessage_scanner.py https://target.com/search?q=x          # HPP + JS
  tools/hpp_postmessage_scanner.py https://target.com/app.js --postmessage-only
  tools/hpp_postmessage_scanner.py -l urls.txt --cookie "s=..." --json
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
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.safe_http import safe_urlopen  # noqa: E402

_LISTENER = re.compile(
    r"addEventListener\s*\(\s*['\"]message['\"]|onmessage\s*=", re.I)
_ORIGIN_CHECK = re.compile(
    r"\.origin\s*(===|==|!=|!==)|checkOrigin|allowedOrigins|event\.origin|e\.origin|"
    r"origin\s*(===|==)|\.origin\)|trustedOrigins", re.I)
_DANGEROUS_SINK = re.compile(
    r"innerHTML|outerHTML|document\.write|eval\s*\(|\.src\s*=|location\s*=|"
    r"location\.href|insertAdjacentHTML|setTimeout\s*\(\s*[a-zA-Z_$]", re.I)


@dataclass
class Finding:
    url: str
    kind: str          # "hpp" | "postmessage"
    severity: str
    reason: str


def analyze_postmessage(js: str, url: str) -> list[Finding]:
    """Pure: flag message listeners that skip origin validation."""
    out: list[Finding] = []
    if not _LISTENER.search(js):
        return out
    # Examine a window of text around each listener for origin checks + sinks.
    has_origin_check = bool(_ORIGIN_CHECK.search(js))
    has_sink = bool(_DANGEROUS_SINK.search(js))
    if not has_origin_check and has_sink:
        out.append(Finding(url, "postmessage", "HIGH",
                           "message listener uses a dangerous sink (innerHTML/eval/location) with no origin check"))
    elif not has_origin_check:
        out.append(Finding(url, "postmessage", "MEDIUM",
                           "message listener present with no event.origin validation — cross-origin injection source"))
    return out


def classify_hpp(param: str, baseline: str, dup_first: str, dup_last: str) -> Finding | None:
    """Pure: given response bodies, decide if duplicated param handling diverges."""
    # If polluted variants differ from each other, first/last handling is
    # inconsistent — the classic HPP bypass primitive.
    if dup_first and dup_last and dup_first != dup_last:
        return Finding("", "hpp", "MEDIUM",
                       f"parameter '{param}' resolves differently by position (first-value vs last-value) — HPP bypass primitive")
    # If a duplicated value changes the response vs baseline, the extra copy is
    # honoured somewhere.
    if baseline and dup_last and baseline != dup_last:
        return Finding("", "hpp", "LOW",
                       f"duplicating '{param}' altered the response — review which copy the app trusts")
    return None


def _get(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        resp = safe_urlopen(req, timeout=timeout)
        return resp.read(1_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read(500_000).decode("utf-8", "replace") if hasattr(e, "read") else ""
    except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError):
        return ""


def _with_params(url, params):
    u = urlparse(url)
    return urlunparse(u._replace(query=urlencode(params)))


def scan(url: str, postmessage_only: bool = False, cookie: str | None = None, timeout: int = 15) -> list[Finding]:
    headers = {"User-Agent": "Mozilla/5.0 (BugHunter HPP scanner)"}
    if cookie:
        headers["Cookie"] = cookie
    out: list[Finding] = []

    body = _get(url, headers, timeout)
    out.extend(analyze_postmessage(body, url))
    if postmessage_only:
        return out

    # HPP: pick the first query parameter to pollute.
    u = urlparse(url)
    params = parse_qsl(u.query, keep_blank_values=True)
    if params:
        param = params[0][0]
        orig_val = params[0][1] or "1"
        evil = orig_val + "EVIL"
        baseline = _get(_with_params(url, params), headers, timeout)
        first = _get(_with_params(url, [(param, orig_val), (param, evil)]), headers, timeout)
        last = _get(_with_params(url, [(param, evil), (param, orig_val)]), headers, timeout)
        v = classify_hpp(param, baseline, first, last)
        if v:
            v.url = url
            out.append(v)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="HTTP parameter pollution + postMessage scanner")
    ap.add_argument("url", nargs="?", help="target URL (include a query param for HPP)")
    ap.add_argument("-l", "--list", help="file of URLs (one per line)")
    ap.add_argument("--postmessage-only", action="store_true", help="only run the client-side postMessage check")
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
        findings.extend(scan(u, postmessage_only=args.postmessage_only, cookie=args.cookie, timeout=args.timeout))

    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        if not findings:
            print("[hpp/postmessage] nothing flagged")
        for f in findings:
            print(f"[{f.severity}] ({f.kind}) {f.url}: {f.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
