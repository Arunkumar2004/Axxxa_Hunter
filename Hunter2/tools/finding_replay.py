#!/usr/bin/env python3
"""
Finding replay / regression re-verification.

Re-issues the exact request that proved a finding and decides whether the bug is
still there. Use it to (a) re-confirm a finding before you submit, (b) prove a
fix landed after the program patches, and (c) regression-check your whole
findings folder in one pass.

Finding schema (JSON) — this is the canonical replayable-finding format:

  {
    "id": "idor-orders-001",
    "severity": "HIGH",
    "request": {
      "method": "GET",
      "url": "https://api.target.com/orders/1337",
      "headers": {"Authorization": "Bearer ..."},   # or "cookie": "..."
      "body": null
    },
    "match": {                 # what "still vulnerable" looks like
      "status": 200,           # optional exact status
      "contains": ["victim@"], # ALL must be present in the response
      "absent": ["Forbidden"]  # NONE may be present
    }
  }

The verdict logic is pure and unit-tested; only `replay()` touches the network.

Verdicts:
  VULNERABLE  the match still holds -> bug is live.
  FIXED       the match no longer holds -> patched / access now denied.
  CHANGED     response changed but is ambiguous -> re-triage manually.
  ERROR       request could not be sent.

Usage:
  tools/finding_replay.py finding.json
  tools/finding_replay.py findings/target/ --dir --json
  tools/finding_replay.py finding.json --auth-file .private/target.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.safe_http import safe_urlopen  # noqa: E402


@dataclass
class ReplayResult:
    id: str
    verdict: str
    detail: str
    status: int


def evaluate(match: dict, status: int, body: str) -> tuple[str, str]:
    """Pure: given the match spec and the fresh response, return (verdict, detail).

    VULNERABLE only if EVERY specified condition still holds. If some but not all
    hold, it's CHANGED (needs human eyes). If none/the key one fails, FIXED.
    """
    checks: list[tuple[str, bool]] = []
    if "status" in match and match["status"] is not None:
        checks.append((f"status=={match['status']}", status == match["status"]))
    for needle in match.get("contains", []) or []:
        checks.append((f"contains {needle!r}", needle in body))
    for needle in match.get("absent", []) or []:
        checks.append((f"absent {needle!r}", needle not in body))

    if not checks:
        return "CHANGED", "no match conditions specified — compare manually"

    passed = [c for c, ok in checks if ok]
    failed = [c for c, ok in checks if not ok]
    if not failed:
        return "VULNERABLE", "all conditions still hold: " + "; ".join(passed)
    if not passed:
        return "FIXED", "no conditions hold: " + "; ".join(failed)
    return "CHANGED", f"partial — held: {'; '.join(passed)} | failed: {'; '.join(failed)}"


def _load_auth(auth_file: str | None) -> dict:
    if not auth_file or not os.path.exists(auth_file):
        return {}
    try:
        data = json.loads(open(auth_file, encoding="utf-8").read())
    except (OSError, json.JSONDecodeError):
        return {}
    headers = {}
    for h in data.get("headers", []) or []:
        k, _, v = h.partition(":")
        if v:
            headers[k.strip()] = v.strip()
    if data.get("cookie"):
        headers["Cookie"] = data["cookie"]
    if data.get("bearer"):
        headers["Authorization"] = f"Bearer {data['bearer']}"
    return headers


def replay(finding: dict, auth_headers: dict | None = None, timeout: int = 15) -> ReplayResult:
    fid = finding.get("id", "?")
    req_spec = finding.get("request", {})
    url = req_spec.get("url")
    if not url:
        return ReplayResult(fid, "ERROR", "finding has no request.url", 0)
    method = (req_spec.get("method") or "GET").upper()
    headers = dict(req_spec.get("headers") or {})
    if req_spec.get("cookie"):
        headers.setdefault("Cookie", req_spec["cookie"])
    if auth_headers:  # CLI auth overlays the finding's stored (possibly stale) auth
        headers.update(auth_headers)
    body = req_spec.get("body")
    data = body.encode() if isinstance(body, str) else (json.dumps(body).encode() if isinstance(body, (dict, list)) else None)
    headers.setdefault("User-Agent", "Mozilla/5.0 (BugHunter replay)")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = safe_urlopen(req, timeout=timeout)
        status, text = resp.getcode(), resp.read(1_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read(500_000).decode("utf-8", "replace") if hasattr(e, "read") else ""
    except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError) as e:
        return ReplayResult(fid, "ERROR", f"request failed: {e}", 0)

    verdict, detail = evaluate(finding.get("match", {}), status, text)
    return ReplayResult(fid, verdict, detail, status)


def _iter_findings(path: str, is_dir: bool):
    if is_dir:
        for root, _, files in os.walk(path):
            for fn in files:
                if fn.endswith(".json"):
                    yield os.path.join(root, fn)
    else:
        yield path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Replay a saved finding to re-verify it")
    ap.add_argument("path", help="a finding .json, or a directory with --dir")
    ap.add_argument("--dir", action="store_true", help="treat path as a directory of finding .json files")
    ap.add_argument("--auth-file", help="AuthSession JSON to overlay fresh auth (.private/<target>.json)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    auth = _load_auth(args.auth_file)
    results: list[ReplayResult] = []
    for fpath in _iter_findings(args.path, args.dir):
        try:
            finding = json.loads(open(fpath, encoding="utf-8").read())
        except (OSError, json.JSONDecodeError) as e:
            results.append(ReplayResult(fpath, "ERROR", f"cannot read finding: {e}", 0))
            continue
        if "request" not in finding:  # not a replayable finding; skip quietly in dir mode
            if not args.dir:
                results.append(ReplayResult(fpath, "ERROR", "not a replayable finding (no 'request')", 0))
            continue
        results.append(replay(finding, auth, args.timeout))

    if args.json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
    else:
        for r in results:
            print(f"[{r.verdict}] {r.id} (HTTP {r.status}): {r.detail}")
        live = sum(1 for r in results if r.verdict == "VULNERABLE")
        print(f"\n{live} still VULNERABLE / {len(results)} replayed")
    return 1 if any(r.verdict == "VULNERABLE" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
