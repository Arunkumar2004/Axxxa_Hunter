#!/usr/bin/env python3
"""Fetch compact public HackerOne metadata for the Phase 1 report set.

Only public JSON summaries are stored. No credentials, cookies, private comments,
or target-session data are used. The output path must be outside the repository's
tracked source tree unless the operator explicitly wants an audit artifact there.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPORT_RE = re.compile(r"https://hackerone\.com/reports/(\d+)")


def report_ids(ledger: Path) -> list[str]:
    ids = REPORT_RE.findall(ledger.read_text(encoding="utf-8"))
    return list(dict.fromkeys(ids))


def fetch(report_id: str) -> dict:
    request = Request(
        f"https://hackerone.com/reports/{report_id}.json",
        headers={"User-Agent": "Hunter2-Phase1-Research/1.0"},
    )
    with urlopen(request, timeout=30) as response:
        payload = json.load(response)
    summaries = [
        item.get("content", "")
        for item in payload.get("summaries", [])
        if item.get("content")
    ]
    return {
        "id": report_id,
        "url": payload.get("url", f"https://hackerone.com/reports/{report_id}"),
        "title": payload.get("title", ""),
        "state": payload.get("readable_substate", payload.get("state", "")),
        "severity": payload.get("severity_rating", ""),
        "bounty": payload.get("formatted_bounty", ""),
        "weakness": (payload.get("weakness") or {}).get("name", ""),
        "scope": (payload.get("structured_scope") or {}).get("asset_identifier", ""),
        "summaries": summaries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--delay", type=float, default=0.2)
    args = parser.parse_args()

    ids = report_ids(args.ledger)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    failures: list[dict[str, str]] = []
    with args.output.open("w", encoding="utf-8") as stream:
        for index, report_id in enumerate(ids, start=1):
            try:
                item = fetch(report_id)
                stream.write(json.dumps(item, ensure_ascii=True) + "\n")
                print(f"[{index}/{len(ids)}] fetched {report_id}")
            except (HTTPError, URLError, TimeoutError, ValueError, OSError) as exc:
                failures.append({"id": report_id, "error": str(exc)})
                print(f"[{index}/{len(ids)}] failed {report_id}: {exc}")
            time.sleep(max(args.delay, 0.0))

    if failures:
        failure_path = args.output.with_suffix(".failures.json")
        failure_path.write_text(json.dumps(failures, indent=2), encoding="utf-8")
        print(f"Fetched {len(ids) - len(failures)}/{len(ids)}; failures: {failure_path}")
        return 1
    print(f"Fetched {len(ids)}/{len(ids)} reports to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
