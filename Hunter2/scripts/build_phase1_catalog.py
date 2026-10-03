#!/usr/bin/env python3
"""Build a compact, redacted catalog from Phase 1 public report metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


GROUPS = [
    "IDOR / BOLA / BFLA",
    "Authentication / Account Takeover",
    "SSRF",
    "Command Injection / RCE",
    "Business Logic / Race Conditions",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines()]
    if len(rows) != 50:
        raise SystemExit(f"expected 50 report records, found {len(rows)}")

    out: list[str] = [
        "# Phase 1 Public Report Catalog",
        "",
        "This catalog was generated from 50 public HackerOne JSON summaries downloaded",
        "to the untracked D: research directory. It stores compact metadata and redacted",
        "summaries only; it does not store credentials, cookies, attachments, or raw",
        "authenticated traffic.",
        "",
    ]
    for index, row in enumerate(rows):
        if index % 10 == 0:
            out.extend([f"## {GROUPS[index // 10]}", ""])
        summary = " ".join(row.get("summaries", []))
        summary = " ".join(summary.split())[:500] or "No public summary was available."
        summary = summary.replace("|", "\\|")
        out.extend([
            f"### {index % 10 + 1}. [{row['id']}]({row['url']}) - {row.get('title', '').strip()}",
            f"- **Weakness:** {row.get('weakness') or 'Not classified'}",
            f"- **Severity/bounty:** {row.get('severity') or 'Not stated'} / {row.get('bounty') or 'Not stated'}",
            f"- **Scope:** {row.get('scope') or 'Not stated'}",
            f"- **Public summary:** {summary}",
            "",
        ])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} report records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
