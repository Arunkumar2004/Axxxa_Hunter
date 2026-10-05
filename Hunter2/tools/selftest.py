#!/usr/bin/env python3
"""
selftest.py - fast, offline smoke test of every tool in tools/.

Run this BEFORE a hunt. It catches the two failure modes that wrecked past
hunts - a tool that crashes the moment it starts, and a tool that hangs - so
the agent verifies the arsenal instead of discovering mid-hunt that something
is broken (or, worse, wrongly declaring a working tool "broken" and hand-
rolling a replacement).

What it does (no network, no targets):
  * every ``*.py``  -> run ``python <tool> --help`` in a subprocess with a hard
    timeout. FAIL on a Python traceback (crash-on-start / bad import / Windows
    unicode crash) or a timeout (hang). Otherwise PASS.
  * every ``*.sh``  -> ``bash -n`` syntax check + CRLF line-ending check.

Usage:
  python tools/selftest.py                 # test everything
  python tools/selftest.py --only cloud    # only tools whose name contains 'cloud'
  python tools/selftest.py --timeout 40    # raise the per-tool timeout
  python tools/selftest.py --json          # machine-readable

Exit code is non-zero if anything FAILED, so it drops straight into CI / a hook.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
TRACEBACK_MARK = "Traceback (most recent call last)"

# These are not CLIs; importing them is the right check, not --help. Everything
# else is run with --help. (Kept tiny on purpose - add only genuine libraries.)
IMPORT_ONLY = {"__init__.py", "safe_http.py", "spa_baseline.py"}

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


def _run(cmd: list[str], timeout: int) -> tuple[int | None, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=str(TOOLS_DIR))
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return None, "TIMEOUT"
    except Exception as exc:  # noqa: BLE001
        return -1, f"launch-error: {exc}"


def check_python_tool(path: Path, timeout: int) -> tuple[str, str]:
    """PASS unless the tool crashes on start (traceback) or hangs (timeout)."""
    if path.name in IMPORT_ONLY:
        rc, out = _run([sys.executable, "-c",
                        f"import importlib.util,sys;"
                        f"s=importlib.util.spec_from_file_location('m',r'{path}');"
                        f"m=importlib.util.module_from_spec(s);s.loader.exec_module(m)"],
                       timeout)
        verb = "import"
    else:
        rc, out = _run([sys.executable, str(path), "--help"], timeout)
        verb = "--help"
    if rc is None:
        return FAIL, f"HANG: {verb} did not return within {timeout}s"
    if TRACEBACK_MARK in out:
        tail = out.strip().splitlines()[-1][:160] if out.strip() else ""
        return FAIL, f"CRASH on {verb}: {tail}"
    if rc == -1:
        return FAIL, out
    return PASS, f"{verb} ok (rc={rc})"


def check_shell_tool(path: Path) -> tuple[str, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return FAIL, f"unreadable: {exc}"
    if b"\r\n" in raw:
        return FAIL, "CRLF line endings (will fail under sh/bash)"
    rc, out = _run(["bash", "-n", str(path)], timeout=15)
    if rc is None:
        return FAIL, "bash -n timed out"
    if rc == -1:
        return SKIP, "bash not available to syntax-check"
    if rc != 0:
        return FAIL, f"bash -n syntax error: {out.strip()[:160]}"
    return PASS, "bash -n ok, LF endings"


def run(pattern: str | None = None, timeout: int = 25) -> list[dict]:
    results: list[dict] = []
    for path in sorted(TOOLS_DIR.iterdir()):
        if path.name == "selftest.py" or path.name.startswith("__"):
            continue
        if pattern and pattern.lower() not in path.name.lower():
            continue
        if path.suffix == ".py":
            status, detail = check_python_tool(path, timeout)
        elif path.suffix == ".sh":
            status, detail = check_shell_tool(path)
        else:
            continue
        results.append({"tool": path.name, "status": status, "detail": detail})
    return results


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="Offline smoke test of every tool in tools/")
    ap.add_argument("--only", help="substring filter on tool filename")
    ap.add_argument("--timeout", type=int, default=25, help="per-tool timeout (s)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    results = run(args.only, args.timeout)
    failed = [r for r in results if r["status"] == FAIL]

    if args.json:
        print(json.dumps({"results": results, "failed": len(failed)}, indent=2))
        return 1 if failed else 0

    for r in results:
        mark = {"PASS": "[+]", "FAIL": "[!]", "SKIP": "[~]"}[r["status"]]
        print(f"  {mark} {r['status']:<4} {r['tool']:<34} {r['detail']}")
    n = len(results)
    print(f"\n[selftest] {n - len(failed)}/{n} passed, {len(failed)} failed")
    if failed:
        print("[selftest] BROKEN TOOLS:")
        for r in failed:
            print(f"    - {r['tool']}: {r['detail']}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
