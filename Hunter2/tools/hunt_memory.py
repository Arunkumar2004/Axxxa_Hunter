#!/usr/bin/env python3
"""
Hunt memory — learning that compounds across hunts (Phase 2, Step #7).

At session end, record what was tested per target and per vuln-class plus the
outcome (what worked, what was rejected and why, dead ends). At hunt start,
load prior outcomes for that target/class so the agent repeats winning
techniques and skips dead ends.

Storage is a dedicated append-only JSONL under the repo memory dir
(``memory/hunt_outcomes.jsonl``), rotated with the shared 10 MB cap so writes
stay bounded. This reuses the same infra the rest of hunt memory uses
(``memory.rotation`` for rotation, ``memory._lock`` for the append lock,
``memory.schemas.CURRENT_SCHEMA_VERSION`` + the ``BBHUNT_SESSION_ID`` env
fallback) rather than inventing a parallel system.

The ``worked | rejected | dead_end | inconclusive`` outcome vocabulary does not
map onto the journal schema's ``VALID_RESULTS`` (confirmed/rejected/partial/
informational), so outcome records live in their own file with their own shape.

NEVER stored: credentials, cookies, tokens, raw request/response bodies, or
target PII. Only: target (domain), vuln_class, endpoint_pattern (generalized,
e.g. ``/api/user/{id}/orders``), technique (short string), outcome, reason
(short), timestamp, session_id. Records are built from a fixed set of keys, so
no caller-supplied blob can widen the stored shape.

Usage:
    python -m tools.hunt_memory --record --target t.com --class idor \
        --technique "two-account swap" --outcome worked
    python -m tools.hunt_memory --show --target t.com [--json]

CLI usage from Python:
    from tools.hunt_memory import (
        record_outcome, load_target_memory, load_class_memory, summarize_for_hunt,
    )
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make memory/ importable when running as a script from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memory import _lock as fcntl  # noqa: E402
from memory.rotation import (  # noqa: E402
    DEFAULT_KEEP,
    DEFAULT_MAX_BYTES,
    rotate_if_needed,
)
from memory.schemas import CURRENT_SCHEMA_VERSION  # noqa: E402

# ── Constants ────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_OUTCOMES_PATH = BASE_DIR / "memory" / "hunt_outcomes.jsonl"

# Env override so operators (and tests) can redirect the store without touching
# real memory. Tests set this to a tmp_path via monkeypatch.
OUTCOMES_ENV_VAR = "HUNT_OUTCOMES_PATH"

VALID_OUTCOMES = {"worked", "rejected", "dead_end", "inconclusive"}

# Keep every free-text field short so a record can never smuggle a large blob
# (or an accidental token) into the store. Records are bounded by design.
MAX_FIELD_LEN = 200

# The complete set of keys a record may ever contain. Records are assembled from
# exactly these fields, so passing a token-like technique/reason cannot add keys.
ALLOWED_KEYS = {
    "ts",
    "target",
    "vuln_class",
    "technique",
    "outcome",
    "endpoint_pattern",
    "reason",
    "schema_version",
    "session_id",
}


# ── Internals ────────────────────────────────────────────────────────────────

def _warn(msg: str) -> None:
    print(f"WARNING: hunt_memory: {msg}", file=sys.stderr)


def _outcomes_path() -> Path:
    """Resolve the outcomes JSONL path (env override wins)."""
    override = os.environ.get(OUTCOMES_ENV_VAR)
    if override:
        return Path(override)
    return DEFAULT_OUTCOMES_PATH


def _short(value) -> str:
    """Coerce to a stripped, length-capped string. Keeps records bounded."""
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) > MAX_FIELD_LEN:
        text = text[:MAX_FIELD_LEN]
    return text


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(record: dict) -> None:
    """Append a single record as one JSONL line, rotating first if oversize.

    Mirrors the write path used by PatternDB.save / AuditLog.log: rotate under
    the shared cap, then append under an exclusive advisory lock.
    """
    path = _outcomes_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    line = json.dumps(record, separators=(",", ":")) + "\n"
    encoded = line.encode("utf-8")

    rotate_if_needed(path, max_bytes=DEFAULT_MAX_BYTES, keep=DEFAULT_KEEP)

    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            written = os.write(fd, encoded)
            if written != len(encoded):
                raise OSError(f"Partial write: {written}/{len(encoded)} bytes")
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _read_all() -> list[dict]:
    """Read every outcome record. Corrupted lines are skipped with a warning."""
    path = _outcomes_path()
    if not path.exists():
        return []

    entries: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                _warn(f"{path} line {lineno} corrupted (skipping): {e}")
    return entries


# ── Public API ───────────────────────────────────────────────────────────────

def record_outcome(
    target,
    vuln_class,
    technique,
    outcome,
    *,
    endpoint_pattern: str = "",
    reason: str = "",
) -> bool:
    """Record one tested-technique outcome for a target/vuln-class.

    Args:
        target: Domain under test (e.g. ``target.com``).
        vuln_class: Vulnerability class (e.g. ``idor``, ``ssrf``).
        technique: Short description of what was tried.
        outcome: One of ``worked``, ``rejected``, ``dead_end``, ``inconclusive``.
        endpoint_pattern: Generalized endpoint (e.g. ``/api/user/{id}/orders``).
        reason: Short note on why (esp. for rejected / dead_end).

    Returns:
        True if a record was appended, False on invalid input or write error.
        Non-fatal: memory must never break a hunt.
    """
    try:
        if outcome not in VALID_OUTCOMES:
            _warn(
                f"invalid outcome {outcome!r}; must be one of "
                f"{sorted(VALID_OUTCOMES)}"
            )
            return False

        target = _short(target)
        vuln_class = _short(vuln_class)
        technique = _short(technique)
        if not target or not vuln_class or not technique:
            _warn("target, vuln_class and technique are all required")
            return False

        record = {
            "ts": _now(),
            "target": target,
            "vuln_class": vuln_class,
            "technique": technique,
            "outcome": outcome,
            "endpoint_pattern": _short(endpoint_pattern),
            "reason": _short(reason),
            "schema_version": CURRENT_SCHEMA_VERSION,
        }
        # Correlate with audit.jsonl when the run is authenticated. This is the
        # non-secret 12-char hash, never a credential.
        sid = os.environ.get("BBHUNT_SESSION_ID")
        if sid:
            record["session_id"] = _short(sid)

        _append(record)
        return True
    except Exception as e:  # noqa: BLE001 - memory writes are best-effort
        _warn(f"failed to record outcome: {e}")
        return False


def load_target_memory(target) -> list[dict]:
    """Return all prior outcome records for ``target`` (empty list if none)."""
    target = _short(target)
    if not target:
        return []
    return [e for e in _read_all() if e.get("target") == target]


def load_class_memory(vuln_class) -> list[dict]:
    """Return all prior outcome records for ``vuln_class`` across targets."""
    vuln_class = _short(vuln_class)
    if not vuln_class:
        return []
    return [e for e in _read_all() if e.get("vuln_class") == vuln_class]


def summarize_for_hunt(target) -> dict:
    """Compact per-outcome summary to inject at hunt start.

    Returns ``{"worked": [...], "rejected": [...], "dead_ends": [...]}`` where
    each item is ``{vuln_class, technique, endpoint_pattern, reason}``. This lets
    the agent repeat wins and skip dead ends. ``inconclusive`` records are
    omitted — they steer nothing.
    """
    summary: dict[str, list[dict]] = {"worked": [], "rejected": [], "dead_ends": []}
    bucket = {"worked": "worked", "rejected": "rejected", "dead_end": "dead_ends"}

    for e in load_target_memory(target):
        key = bucket.get(e.get("outcome"))
        if key is None:
            continue
        summary[key].append({
            "vuln_class": e.get("vuln_class", ""),
            "technique": e.get("technique", ""),
            "endpoint_pattern": e.get("endpoint_pattern", ""),
            "reason": e.get("reason", ""),
        })
    return summary


# ── CLI ──────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Learning hunt memory — record and recall per-target outcomes.",
    )
    parser.add_argument("--record", action="store_true", help="Record an outcome")
    parser.add_argument(
        "--show", action="store_true",
        help="Show the hunt-start summary for --target",
    )
    parser.add_argument("--target", default="", help="Target domain")
    parser.add_argument(
        "--class", dest="vuln_class", default="", help="Vuln class (e.g. idor)",
    )
    parser.add_argument("--technique", default="", help="Short technique description")
    parser.add_argument(
        "--outcome", default="",
        help=f"One of {sorted(VALID_OUTCOMES)}",
    )
    parser.add_argument(
        "--endpoint", dest="endpoint_pattern", default="",
        help="Generalized endpoint pattern (e.g. /api/user/{id}/orders)",
    )
    parser.add_argument("--reason", default="", help="Short reason / note")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args(argv)

    if args.record:
        ok = record_outcome(
            args.target,
            args.vuln_class,
            args.technique,
            args.outcome,
            endpoint_pattern=args.endpoint_pattern,
            reason=args.reason,
        )
        if args.json:
            print(json.dumps({"recorded": ok}))
        else:
            print(f"recorded: {ok}")
        return 0

    if args.show:
        summary = summarize_for_hunt(args.target)
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(
                f"Memory for {args.target or '(none)'}: "
                f"{len(summary['worked'])} prior wins, "
                f"{len(summary['rejected'])} rejected, "
                f"{len(summary['dead_ends'])} dead ends"
            )
            for label in ("worked", "rejected", "dead_ends"):
                for item in summary[label]:
                    tail = f" — {item['reason']}" if item["reason"] else ""
                    ep = f" @ {item['endpoint_pattern']}" if item["endpoint_pattern"] else ""
                    print(f"  [{label}] {item['vuln_class']}: {item['technique']}{ep}{tail}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
