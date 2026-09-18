#!/usr/bin/env python3
"""
Shared payload-corpus loader (Phase 2 real-payload upgrade).

Scanners keep their built-in payloads as the guaranteed baseline and call these
helpers to ADD real-world payloads from versioned text files in tools/payloads/.
If a corpus file is missing or empty, the helpers return [] so the scanner falls
back to its built-ins unchanged (keeps unit-test invariants intact).

Corpus files are plain text:
  - lines starting with '#' and blank lines are ignored
  - `load_lines` -> one payload per line (with {PLACEHOLDER} substitution)
  - `load_blocks` -> multi-line payloads separated by a line containing only '---'

All payloads here are for DETECTION against explicitly authorized targets only.
"""
from pathlib import Path

_DIR = Path(__file__).resolve().parent / "payloads"


def _read(name: str) -> str:
    try:
        return (_DIR / f"{name}.txt").read_text(encoding="utf-8")
    except Exception:
        return ""


def load_lines(name: str, **subs) -> list[str]:
    """Non-comment, non-blank lines from tools/payloads/<name>.txt ({key} -> subs[key])."""
    out: list[str] = []
    for line in _read(name).splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for k, v in subs.items():
            s = s.replace("{" + k + "}", v)
        out.append(s)
    return out


def load_blocks(name: str, **subs) -> list[str]:
    """Multi-line payloads separated by a line that is exactly '---'."""
    blocks: list[str] = []
    cur: list[str] = []
    started = False
    for line in _read(name).splitlines():
        if line.strip() == "---":
            if cur:
                blocks.append("\n".join(cur).strip())
                cur = []
            started = True
            continue
        if not started and line.strip().startswith("#"):
            continue
        cur.append(line)
    if cur and "\n".join(cur).strip():
        blocks.append("\n".join(cur).strip())
    out: list[str] = []
    for b in blocks:
        if not b:
            continue
        for k, v in subs.items():
            b = b.replace("{" + k + "}", v)
        out.append(b)
    return out
