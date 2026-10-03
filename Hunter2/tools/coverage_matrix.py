#!/usr/bin/env python3
"""Persistent per-target coverage matrix for the hunt orchestrator."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
SOURCE = BASE_DIR / "rules" / "coverage-matrix.md"
STORE = BASE_DIR / "memory" / "coverage"
VALID_STATUSES = {"PENDING", "TESTED", "FOUND", "N/A", "BLOCKED"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def canonical_classes() -> list[dict[str, str]]:
    """Read the documented class rows without duplicating the registry in code."""
    classes: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in SOURCE.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or "---" in line:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 2 or cells[0] in {"Class", ""}:
            continue
        display = re.sub(r"\*\*", "", cells[0]).strip()
        display = re.sub(r"\s*\([^)]*\)", "", display).strip()
        if not display or display.lower() == "class":
            continue
        class_id = _slug(display)
        if class_id in seen:
            continue
        seen.add(class_id)
        classes.append({"id": class_id, "name": display, "route": cells[2] if len(cells) > 2 else ""})
    return classes


def _path(target: str) -> Path:
    return STORE / f"{_slug(target)}.json"


def initialize(target: str) -> dict:
    classes = canonical_classes()
    return {
        "target": target,
        "updated_at": _now(),
        "classes": {
            item["id"]: {
                "name": item["name"],
                "route": item["route"],
                "status": "PENDING",
                "reason": "",
                "evidence": [],
                "updated_at": _now(),
            }
            for item in classes
        },
    }


def save(matrix: dict) -> Path:
    STORE.mkdir(parents=True, exist_ok=True)
    destination = _path(matrix["target"])
    fd, temporary = tempfile.mkstemp(prefix=destination.stem + ".", suffix=".tmp", dir=STORE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(matrix, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination


def load(target: str) -> dict:
    path = _path(target)
    if not path.exists():
        return initialize(target)
    matrix = json.loads(path.read_text(encoding="utf-8"))
    if matrix.get("target") != target or not isinstance(matrix.get("classes"), dict):
        raise ValueError(f"invalid coverage matrix: {path}")
    return matrix


def update(target: str, class_name: str, status: str, reason: str = "", evidence=None) -> dict:
    status = status.upper()
    if status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {sorted(VALID_STATUSES)}")
    matrix = load(target)
    class_id = _slug(class_name)
    if class_id not in matrix["classes"]:
        matches = [key for key, item in matrix["classes"].items() if item["name"].lower() == class_name.lower()]
        if len(matches) != 1:
            raise KeyError(f"unknown coverage class: {class_name}")
        class_id = matches[0]
    if status in {"N/A", "BLOCKED"} and not reason.strip():
        raise ValueError(f"{status} requires a reason")
    if status in {"TESTED", "FOUND"} and not (evidence or reason.strip()):
        raise ValueError(f"{status} requires evidence or a result note")
    item = matrix["classes"][class_id]
    if item["status"] == "FOUND" and status not in {"FOUND", "TESTED"}:
        return matrix
    item.update({
        "status": status,
        "reason": reason,
        "evidence": list(evidence or item.get("evidence", [])),
        "updated_at": _now(),
    })
    matrix["updated_at"] = _now()
    save(matrix)
    return matrix


def summary(matrix: dict) -> dict:
    counts = {status: 0 for status in VALID_STATUSES}
    pending: list[str] = []
    for item in matrix["classes"].values():
        status = item.get("status", "PENDING")
        counts[status] = counts.get(status, 0) + 1
        if status in {"PENDING", "BLOCKED"}:
            pending.append(item["name"])
    return {"counts": counts, "unresolved": sorted(pending), "complete": not pending}


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Hunter2 coverage matrices")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("target")
    set_cmd = sub.add_parser("set")
    set_cmd.add_argument("target")
    set_cmd.add_argument("class_name")
    set_cmd.add_argument("status", choices=sorted(VALID_STATUSES))
    set_cmd.add_argument("--reason", default="")
    show = sub.add_parser("show")
    show.add_argument("target")
    args = parser.parse_args()
    if args.command == "init":
        matrix = initialize(args.target)
        save(matrix)
    elif args.command == "set":
        matrix = update(args.target, args.class_name, args.status, args.reason)
    else:
        matrix = load(args.target)
    print(json.dumps(summary(matrix), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
