#!/usr/bin/env python3
"""
Feedback loop — learn from real submission outcomes (Level 2, L2.1).

The truest learning signal is not what *looked* promising during a hunt, but
what actually got PAID vs REJECTED on real programs. This module is the
submission-outcome sibling of ``tools.hunt_memory``: where hunt memory records
what techniques *worked* in-session, this records how a submitted finding
*resolved* with the program (paid, rejected, duped, informative) and, on the
next hunt, boosts techniques that earned bounties and de-prioritizes techniques
that got rejected or duplicated.

Storage is a dedicated append-only JSONL under the repo memory dir
(``memory/feedback_outcomes.jsonl``), rotated with the shared 10 MB cap so
writes stay bounded. This reuses the same infra as the rest of hunt memory
(``memory.rotation`` for rotation, ``memory._lock`` for the append lock,
``memory.schemas.CURRENT_SCHEMA_VERSION`` + the ``BBHUNT_SESSION_ID`` env
fallback) rather than inventing a parallel system.

The ``PAID | REJECTED | DUPLICATE | INFORMATIVE`` outcome vocabulary is the
real-world resolution of a submission, distinct from both the journal schema's
``VALID_RESULTS`` and hunt_memory's in-session ``worked | rejected | ...``, so
submission outcomes live in their own file with their own shape.

NEVER stored: credentials, cookies, tokens, raw request/response bodies, or
target PII. Only: target (domain), vuln_class, technique, outcome,
endpoint_pattern (generalized, e.g. ``/api/user/{id}/orders``), severity,
bounty (amount), reason (short), timestamp, session_id. Records are built from a
fixed set of keys, so no caller-supplied blob can widen the stored shape.

Usage:
    python -m tools.feedback_loop --record --target t.com --class idor \
        --technique "two-account swap" --outcome PAID --bounty 500
    python -m tools.feedback_loop --advise --target t.com [--json]

CLI usage from Python:
    from tools.feedback_loop import (
        record_submission, load_feedback, technique_scores, advise_for_hunt,
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
DEFAULT_OUTCOMES_PATH = BASE_DIR / "memory" / "feedback_outcomes.jsonl"

# Env override so operators (and tests) can redirect the store without touching
# real memory. Tests set this to a tmp_path via monkeypatch.
OUTCOMES_ENV_VAR = "FEEDBACK_OUTCOMES_PATH"

# Real-world resolution of a submitted finding.
VALID_OUTCOMES = {"PAID", "REJECTED", "DUPLICATE", "INFORMATIVE"}

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
    "severity",
    "bounty",
    "reason",
    "schema_version",
    "session_id",
}


# ── Internals ────────────────────────────────────────────────────────────────

def _warn(msg: str) -> None:
    print(f"WARNING: feedback_loop: {msg}", file=sys.stderr)


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


def _money(value) -> float:
    """Coerce a bounty amount to a non-negative float. Non-numeric → 0."""
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return 0.0
    if amount < 0 or amount != amount:  # reject negatives and NaN
        return 0.0
    return amount


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(record: dict) -> None:
    """Append a single record as one JSONL line, rotating first if oversize.

    Mirrors the write path used by hunt_memory / PatternDB.save: rotate under
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

def record_submission(
    target,
    vuln_class,
    technique,
    outcome,
    *,
    endpoint_pattern: str = "",
    severity: str = "",
    bounty=0,
    reason: str = "",
) -> bool:
    """Record the real-world outcome of a submitted finding.

    Args:
        target: Domain the finding was submitted against (e.g. ``target.com``).
        vuln_class: Vulnerability class (e.g. ``idor``, ``ssrf``).
        technique: Short description of the technique that found it.
        outcome: One of ``PAID``, ``REJECTED``, ``DUPLICATE``, ``INFORMATIVE``.
        endpoint_pattern: Generalized endpoint (e.g. ``/api/user/{id}/orders``).
        severity: Reported severity (short free-text, e.g. ``high``).
        bounty: Amount paid (numeric; coerced to a non-negative float).
        reason: Short note on why (esp. for rejected / duplicate).

    Returns:
        True if a record was appended, False on invalid input or write error.
        Non-fatal: feedback must never break a hunt.
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
            "severity": _short(severity),
            "bounty": _money(bounty),
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
    except Exception as e:  # noqa: BLE001 - feedback writes are best-effort
        _warn(f"failed to record submission: {e}")
        return False


def load_feedback(vuln_class=None, target=None) -> list[dict]:
    """Return submission-outcome records, optionally filtered.

    Args:
        vuln_class: If given, keep only records for this vuln class.
        target: If given, keep only records for this target.

    Returns:
        A list of records (empty if the store is missing or nothing matches).
    """
    records = _read_all()
    if vuln_class is not None:
        vc = _short(vuln_class)
        records = [r for r in records if r.get("vuln_class") == vc]
    if target is not None:
        tg = _short(target)
        records = [r for r in records if r.get("target") == tg]
    return records


def technique_scores() -> dict:
    """Aggregate submission outcomes into a per-vuln-class technique scoreboard.

    Returns a mapping::

        {vuln_class: {"paid": [techniques], "rejected": [techniques], "score": N}}

    where ``score = (#PAID * 2 + #INFORMATIVE) - (#REJECTED + #DUPLICATE)``.
    ``paid`` lists techniques that earned a bounty; ``rejected`` lists techniques
    that were rejected or duplicated. Use this to rank what to repeat vs drop.
    """
    scores: dict[str, dict] = {}
    for r in _read_all():
        vc = r.get("vuln_class")
        technique = r.get("technique")
        outcome = r.get("outcome")
        if not vc or not technique or outcome not in VALID_OUTCOMES:
            continue

        bucket = scores.setdefault(vc, {"paid": [], "rejected": [], "score": 0})
        if outcome == "PAID":
            bucket["paid"].append(technique)
            bucket["score"] += 2
        elif outcome == "INFORMATIVE":
            bucket["score"] += 1
        elif outcome == "REJECTED":
            bucket["rejected"].append(technique)
            bucket["score"] -= 1
        elif outcome == "DUPLICATE":
            bucket["rejected"].append(technique)
            bucket["score"] -= 1
    return scores


def advise_for_hunt(target=None) -> dict:
    """Compact boost/avoid advice to inject at hunt start.

    Returns ``{"boost": [...], "avoid": [...]}`` where each item is
    ``{vuln_class, technique, why}``. ``boost`` holds techniques that earned
    bounties before (repeat the wins); ``avoid`` holds techniques that got
    rejected or duplicated (skip the losers). When ``target`` is given, only
    that target's history steers the advice.

    A technique that both paid and was later rejected still counts as a win, so
    it only appears under ``boost`` — the money is the stronger signal.
    """
    advice: dict[str, list[dict]] = {"boost": [], "avoid": []}

    boosted: dict[str, set] = {}
    for r in load_feedback(target=target):
        vc = r.get("vuln_class")
        technique = r.get("technique")
        outcome = r.get("outcome")
        if not vc or not technique:
            continue

        if outcome == "PAID":
            if technique in boosted.get(vc, set()):
                continue
            boosted.setdefault(vc, set()).add(technique)
            bounty = r.get("bounty", 0)
            why = f"paid ${bounty:g} before" if bounty else "paid out before"
            advice["boost"].append(
                {"vuln_class": vc, "technique": technique, "why": why}
            )

    seen_avoid: dict[str, set] = {}
    for r in load_feedback(target=target):
        vc = r.get("vuln_class")
        technique = r.get("technique")
        outcome = r.get("outcome")
        if not vc or not technique or outcome not in {"REJECTED", "DUPLICATE"}:
            continue
        # A technique that paid elsewhere stays a win — don't tell the agent to
        # avoid something that has earned money.
        if technique in boosted.get(vc, set()):
            continue
        if technique in seen_avoid.get(vc, set()):
            continue
        seen_avoid.setdefault(vc, set()).add(technique)
        reason = r.get("reason", "")
        verb = "duped" if outcome == "DUPLICATE" else "rejected"
        why = f"{verb} before — {reason}" if reason else f"{verb} before"
        advice["avoid"].append(
            {"vuln_class": vc, "technique": technique, "why": why}
        )

    return advice


# ── CLI ──────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Feedback loop — learn from real PAID/REJECTED submission outcomes.",
    )
    parser.add_argument("--record", action="store_true", help="Record a submission outcome")
    parser.add_argument(
        "--advise", action="store_true",
        help="Show boost/avoid advice for --target (or across all targets)",
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
    parser.add_argument("--severity", default="", help="Reported severity (e.g. high)")
    parser.add_argument("--bounty", default=0, help="Bounty amount paid")
    parser.add_argument("--reason", default="", help="Short reason / note")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args(argv)

    if args.record:
        ok = record_submission(
            args.target,
            args.vuln_class,
            args.technique,
            args.outcome,
            endpoint_pattern=args.endpoint_pattern,
            severity=args.severity,
            bounty=args.bounty,
            reason=args.reason,
        )
        if args.json:
            print(json.dumps({"recorded": ok}))
        else:
            print(f"recorded: {ok}")
        return 0

    if args.advise:
        advice = advise_for_hunt(args.target or None)
        if args.json:
            print(json.dumps(advice, indent=2))
        else:
            print(
                f"Feedback for {args.target or '(all targets)'}: "
                f"{len(advice['boost'])} to boost, "
                f"{len(advice['avoid'])} to avoid"
            )
            for label in ("boost", "avoid"):
                for item in advice[label]:
                    print(
                        f"  [{label}] {item['vuln_class']}: "
                        f"{item['technique']} — {item['why']}"
                    )
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
