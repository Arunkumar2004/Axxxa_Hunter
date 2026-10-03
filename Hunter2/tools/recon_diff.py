#!/usr/bin/env python3
"""
Recon freshness diff — surface NEW attack surface between hunts.

Rule 12 (NEW == UNREVIEWED): features/subdomains/endpoints that appeared since the
last recon run have the lowest security maturity and the highest bug density. This
tool snapshots the recon output each time it runs and reports what changed since the
previous snapshot, so the operator hunts the fresh surface first instead of
re-testing already-picked-over assets.

Usage:
    python3 recon_diff.py --target example.com          # diff vs last snapshot, then snapshot
    python3 recon_diff.py --target example.com --json    # machine-readable
    python3 recon_diff.py --target example.com --no-save  # diff only, don't snapshot

Compares subdomains and live URLs. New items are written to
recon/<target>/fresh/{subdomains,urls}.txt for the hunt loop to prioritize.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(TOOLS_DIR)
RECON_DIR = os.path.join(BASE_DIR, "recon")

# (label, candidate relative paths within recon/<target>/) — first existing wins.
SOURCES = {
    "subdomains": [
        os.path.join("subdomains", "all.txt"),
        "subdomains.txt",
    ],
    "urls": [
        os.path.join("live", "urls.txt"),
        os.path.join("urls", "all.txt"),
        "all-urls.txt",
        "live-hosts.txt",
    ],
}


def _validate_domain(domain: str) -> str:
    if not domain or "/" in domain or "\\" in domain or ".." in domain:
        raise ValueError(f"invalid domain: {domain!r}")
    return domain


def _read_set(path: str) -> set[str]:
    items: set[str] = set()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    items.add(s.split()[0])
    except OSError:
        pass
    return items


def _current_set(recon_dir: str, candidates: list[str]) -> set[str]:
    for rel in candidates:
        path = os.path.join(recon_dir, rel)
        if os.path.isfile(path):
            return _read_set(path)
    return set()


def _snapshot_path(recon_dir: str, label: str) -> str:
    return os.path.join(recon_dir, ".snapshot", f"{label}.txt")


def diff_target(domain: str, save: bool = True) -> dict:
    """Return {label: {"new": [...], "total": N, "previous": M}} and, when
    ``save`` is set, write new items to recon/<target>/fresh/ and refresh the
    snapshot for next time."""
    domain = _validate_domain(domain)
    recon_dir = os.path.join(RECON_DIR, domain)
    if not os.path.isdir(recon_dir):
        raise FileNotFoundError(f"no recon dir for {domain} — run recon first")

    result: dict = {"target": domain, "generated_at": datetime.now().isoformat()}
    fresh_dir = os.path.join(recon_dir, "fresh")
    snap_dir = os.path.join(recon_dir, ".snapshot")

    for label, candidates in SOURCES.items():
        current = _current_set(recon_dir, candidates)
        previous = _read_set(_snapshot_path(recon_dir, label))
        # First-ever run has no snapshot: everything is "new" but we flag that so
        # the operator knows it isn't a genuine delta.
        first_run = not previous
        new_items = sorted(current - previous)

        result[label] = {
            "new": new_items,
            "new_count": len(new_items),
            "total": len(current),
            "previous": len(previous),
            "first_run": first_run,
        }

        if save:
            os.makedirs(fresh_dir, exist_ok=True)
            os.makedirs(snap_dir, exist_ok=True)
            with open(os.path.join(fresh_dir, f"{label}.txt"), "w", encoding="utf-8") as fh:
                fh.write("\n".join(new_items) + ("\n" if new_items else ""))
            with open(_snapshot_path(recon_dir, label), "w", encoding="utf-8") as fh:
                fh.write("\n".join(sorted(current)) + ("\n" if current else ""))

    return result


def _print_human(result: dict) -> None:
    print(f"\n=== Recon freshness: {result['target']} ===")
    any_new = False
    for label in SOURCES:
        d = result[label]
        if d["first_run"]:
            print(f"  {label:11s}: first snapshot ({d['total']} items) — no prior run to diff")
            continue
        marker = "  <-- HUNT THESE FIRST" if d["new_count"] else ""
        print(f"  {label:11s}: {d['new_count']} new  ({d['previous']} -> {d['total']}){marker}")
        if d["new_count"]:
            any_new = True
            for item in d["new"][:15]:
                print(f"       + {item}")
            if d["new_count"] > 15:
                print(f"       ... and {d['new_count'] - 15} more")
    if any_new:
        print(f"\n  New items written to recon/{result['target']}/fresh/ — "
              f"prioritize per Rule 12 (NEW == UNREVIEWED).")
    print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Recon freshness diff")
    ap.add_argument("--target", required=True, help="domain with an existing recon/<target>/ dir")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-save", action="store_true",
                    help="diff only; do not update the snapshot or write fresh/")
    args = ap.parse_args(argv)

    try:
        result = diff_target(args.target, save=not args.no_save)
    except (ValueError, FileNotFoundError) as e:
        print(f"[-] {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
