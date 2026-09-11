#!/usr/bin/env python3
"""
AXXX HUNTER — start dashboard.

The single "starting point" screen: a big AXXX HUNTER banner (Metasploit-style) followed
by the live Connection Board (what tools / MCPs / proxies / browser-login / agents / skills
are actually armed right now). Run this FIRST, before every hunt.

    python tools/start.py                 # banner + full board
    python tools/start.py <target>        # also shows the target + scope hint
    python tools/start.py --no-banner     # board only

Pure stdlib. Respects NO_COLOR and non-TTY (plain text). Never fails a hunt — purely
informational.
"""
from __future__ import annotations
import os, shutil, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Windows consoles default to cp1252 which can't render the block banner — force UTF-8.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _utf8(stream) -> bool:
    return "utf" in (getattr(stream, "encoding", "") or "").lower()

# ---- AXXX HUNTER block letters (ANSI-Shadow style) ------------------------
_G = {
 "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
 "X": ["██╗  ██╗", "╚██╗██╔╝", " ╚███╔╝ ", " ██╔██╗ ", "██╔╝ ██╗", "╚═╝  ╚═╝"],
 "H": ["██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
 "U": ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
 "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
 "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
 "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
 "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
 " ": ["   ", "   ", "   ", "   ", "   ", "   "],
}
_GRAD256 = ["\033[38;5;196m", "\033[38;5;202m", "\033[38;5;208m",
            "\033[38;5;214m", "\033[38;5;220m", "\033[38;5;226m"]
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def _color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _compose(text: str):
    rows = ["" for _ in range(6)]
    for ch in text.upper():
        g = _G.get(ch, _G[" "])
        for i in range(6):
            rows[i] += g[i] + " "
    return rows


_ASCII_LOGO = [
    r"  /\  \/ \/ \/ \   |  | |  | |\ | ||  ||__ |__)",
    r" /--\ /\ /\ /\  >  |__| |__| | \| ||  ||__ |  \ ",
    r"        A  X  X  X     H U N T E R",
]


def print_banner(target: str | None = None, stream=sys.stdout):
    color = _color(stream)
    if _utf8(stream):
        rows = _compose("AXXX HUNTER")
    else:
        rows = _ASCII_LOGO  # cp1252-safe fallback
    print(file=stream)
    for i, r in enumerate(rows):
        if color:
            print(_GRAD256[i % len(_GRAD256)] + r + _RESET, file=stream)
        else:
            print(r, file=stream)
    tag = "Agentic Bug-Bounty Framework  ·  real-hunter flow  ·  Claude Code + OpenCode"
    sub = f"  {tag}"
    print((_DIM + sub + _RESET) if color else sub, file=stream)
    if target:
        line = f"  ▶ TARGET: {target}"
        print((_BOLD + line + _RESET) if color else line, file=stream)
    print(file=stream)


# ---- browser / login-capture readiness (the OTP/MFA window) ---------------
def _browser_login_ready() -> tuple[bool, str]:
    """The primary browser/login path is the BROWSER MCP (@playwright/mcp via npx) — it
    opens its own Chromium and needs only Node/npx, NOT the Python playwright package."""
    node = shutil.which("node")
    npx = shutil.which("npx")
    if node and npx:
        return True, "browser MCP opens Chromium for login/OTP/MFA (no Python playwright needed)"
    return False, "install Node.js (gives npx) so the browser MCP can open Chromium for login"


def _playwright_ready() -> tuple[bool, str]:
    try:
        import importlib
        importlib.import_module("playwright.sync_api")
    except Exception:
        return False, "pip install playwright && playwright install chromium"
    # chromium browser actually installed?
    try:
        from playwright.sync_api import sync_playwright  # noqa
        cache = Path.home() / "AppData" / "Local" / "ms-playwright"
        alt = Path.home() / ".cache" / "ms-playwright"
        if any((cache.exists(), alt.exists())):
            return True, "Chromium ready — /login-capture opens a real window for OTP/MFA"
        return False, "playwright installed, browser missing: playwright install chromium"
    except Exception:
        return False, "playwright install chromium"


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    no_banner = "--no-banner" in argv
    argv = [a for a in argv if not a.startswith("-")]
    target = argv[0] if argv else None

    if not no_banner:
        print_banner(target)

    # Connection board via preflight (reuse its logic; identical in both CLIs)
    try:
        from tools import preflight
        preflight.main()  # prints the full board (tools/MCPs/proxies/agents/skills)
    except Exception as e:
        print(f"  [preflight unavailable: {e}]")

    # Browser / login readiness — the OTP/MFA login window
    b_ok, b_hint = _browser_login_ready()
    print("-- Browser login (opens Chromium for OTP/MFA) --")
    print(f"  [{'OK ' if b_ok else '-- '}] browser MCP (Node/npx)     {b_hint}")
    p_ok, _ph = _playwright_ready()
    print(f"  [{'OK ' if p_ok else '-- '}] python playwright          optional - only for login_capture.py session save")
    print()

    # Next-step hint
    if target:
        print(f"  NEXT: python tools/scope_checker.py {target}   then   hunt {target}")
    else:
        print("  NEXT: say  hunt <target>  (scope → recon → lead board → hunt all classes → chain → report)")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
