#!/usr/bin/env python3
"""Cross-platform dependency inventory and installer for Bug Hunter.

The shell registry remains the single source of truth for the tool catalogue;
this module parses it and uses ``shutil.which`` so status checks work from
PowerShell, cmd.exe, Git Bash, WSL, Linux, and macOS alike.

Examples:
    python tools/arsenal.py status
    python tools/arsenal.py status --category recon
    python tools/arsenal.py install --profile core --dry-run
    python tools/arsenal.py install --profile recon --yes
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REGISTRY = ROOT / "external_arsenal.sh"

PROFILES = {
    "core": {"recon", "probe", "crawl", "fuzz", "scan"},
    "recon": {"recon", "probe", "crawl"},
    "web": {"fuzz", "scan", "xss", "param", "bypass", "js"},
    "api": {"param", "graphql", "jwt", "scan"},
    "cloud": {"cloud", "takeover"},
    "secrets": {"secrets", "sast"},
    "auth": {"jwt", "oauth"},
    "mobile": {"mobile"},
    "web3": {"web3"},
    "osint": {"osint"},
    # "all" deliberately excludes credential-attack tools.  Those are
    # opt-in because installing them does not authorize password spraying.
    "all": {"recon", "probe", "crawl", "fuzz", "scan", "xss", "sqli", "upload", "cve", "js", "secrets", "cloud", "takeover", "bypass", "graphql", "jwt", "scope", "mobile", "sast", "browser", "osint", "filter", "oob", "ai", "web3"},
    "credential-attack": {"cred"},
}


def load_registry() -> list[dict[str, str]]:
    """Read tool|category|hint|upstream rows from external_arsenal.sh."""
    rows = []
    pattern = re.compile(r'^\s*"([^"|]+)\|([^"|]+)\|([^"|]*)\|([^"|]+)"')
    in_registry = False
    for line in REGISTRY.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip().startswith("ARSENAL_TOOLS=("):
            in_registry = True
            continue
        if in_registry and line.strip() == ")":
            break
        if not in_registry:
            continue
        match = pattern.match(line)
        if match:
            name, category, hint, upstream = match.groups()
            rows.append({"name": name, "category": category, "hint": hint, "upstream": upstream})
    return rows


def locate_tool(name: str) -> str | None:
    """Locate a binary across native PATH, Go bin, and Git Bash PATH.

    Windows users often install Go tools into ``%USERPROFILE%\\go\\bin``
    while the Python process only sees the native PATH.  Conversely, Git Bash
    may know about a binary that PowerShell does not.  Checking both avoids the
    old false ``0/N installed`` result without mutating the user's PATH.
    """
    candidates = [name]
    if os.name == "nt" and not name.lower().endswith(".exe"):
        candidates.append(name + ".exe")
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found

    extra_dirs = [Path.home() / "go" / "bin", ROOT.parent / ".tools" / "bin"]
    userprofile = os.environ.get("USERPROFILE")
    if userprofile:
        extra_dirs.append(Path(userprofile) / "go" / "bin")
    for directory in extra_dirs:
        for candidate in candidates:
            path = directory / candidate
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)

    # Last resort: ask an available POSIX shell.  This is especially useful
    # when the caller is PowerShell but Git Bash owns the configured PATH.
    bash = shutil.which("bash")
    if bash:
        try:
            if os.name == "nt":
                # Calling the registry as a script lets Git Bash resolve its
                # own translated PATH (for example /c/Users/.../go/bin),
                # which is not necessarily visible to native Python.
                result = subprocess.run(
                    [bash, "tools/external_arsenal.sh", "--have", name],
                    cwd=str(ROOT.parent), capture_output=True, text=True,
                    timeout=5, check=False,
                )
                if result.returncode == 0:
                    return name
            result = subprocess.run(
                [bash, "-lc", f"source {shlex.quote(str(REGISTRY))}; command -v {shlex.quote(name)}"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            value = result.stdout.strip().splitlines()
            if result.returncode == 0 and value:
                return value[-1]
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def status(rows: list[dict[str, str]], category: str | None = None) -> tuple[list[dict], list[dict]]:
    selected = [r for r in rows if not category or r["category"] == category]
    installed, missing = [], []
    for row in selected:
        row = dict(row)
        row["path"] = locate_tool(row["name"])
        (installed if row["path"] else missing).append(row)
    return installed, missing


def print_status(rows: list[dict[str, str]], category: str | None = None) -> None:
    installed, missing = status(rows, category)
    selected = installed + missing
    print(f"Platform: {platform.system()} {platform.machine()}")
    print(f"Registry: {REGISTRY}")
    print(f"Tools: {len(installed)}/{len(selected)} installed")
    if category:
        print(f"Category: {category}")
    for row in sorted(selected, key=lambda r: (r["category"], r["name"])):
        state = "OK" if row["path"] else "MISSING"
        location = row["path"] or f"install hint: {row['hint']}"
        print(f"[{state:7}] {row['name']:<18} {row['category']:<10} {location}")
    if missing:
        print("\nMissing tools are skipped by the Hunter; install only the profile you need.")
        print("Examples: python tools/arsenal.py install --profile core --dry-run")


def profile_rows(rows: list[dict[str, str]], profile: str) -> list[dict[str, str]]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; choose: {', '.join(PROFILES)}")
    categories = PROFILES[profile]
    return [r for r in rows if categories is None or r["category"] in categories]


def _command_for(row: dict[str, str]) -> tuple[list[str] | None, str]:
    """Return an executable argv where possible and a human-readable fallback."""
    hint = row["hint"]
    # Go install hints are portable after removing the shell-only GOBIN prefix.
    match = re.search(r"go install (.+)$", hint)
    if match and shutil.which("go"):
        return ["go", "install", match.group(1)], "go " + match.group(1)
    if hint.startswith("pipx install "):
        package = hint.split()[2]
        if shutil.which("pipx"):
            return ["pipx", "install", package], hint
        if shutil.which("python"):
            return [sys.executable, "-m", "pip", "install", package], f"{sys.executable} -m pip install {package}"
    if hint.startswith("pip install ") and shutil.which("python"):
        package = hint.split()[2]
        return [sys.executable, "-m", "pip", "install", package], f"{sys.executable} -m pip install {package}"
    if hint.startswith("npm install ") and shutil.which("npm"):
        return hint.split(), hint
    if hint.startswith("cargo install ") and shutil.which("cargo"):
        return hint.split(), hint
    # Homebrew and git/curl recipes are intentionally not executed on Windows.
    return None, hint


def install(rows: list[dict[str, str]], profile: str, yes: bool, dry_run: bool, acknowledge: bool) -> int:
    if profile == "credential-attack" and not acknowledge:
        print("Credential-attack tooling is opt-in. Add --acknowledge-credential-attack after confirming program authorization.")
        return 2
    selected = profile_rows(rows, profile)
    _, missing = status(selected)
    if not missing:
        print(f"Profile {profile}: all {len(selected)} tools are already installed.")
        return 0
    print(f"Profile {profile}: {len(missing)} missing tool(s)")
    unsupported = []
    for row in missing:
        argv, display = _command_for(row)
        if argv is None:
            unsupported.append(row)
            print(f"[MANUAL ] {row['name']:<18} {display}")
            continue
        print(f"[INSTALL ] {row['name']:<18} {' '.join(argv)}")
        if dry_run:
            continue
        if not yes:
            print("Refusing to install without --yes (use --dry-run to preview).")
            return 2
        try:
            completed = subprocess.run(argv, check=False)
        except OSError as exc:
            print(f"[FAILED  ] {row['name']}: {exc}")
            continue
        print(f"[{'OK' if completed.returncode == 0 else 'FAILED':7}] {row['name']}")
    if unsupported:
        print("\nManual/platform-specific installs remain; they were not executed automatically:")
        for row in unsupported:
            print(f"  {row['name']}: {row['hint']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bug Hunter cross-platform tool manager")
    sub = parser.add_subparsers(dest="command", required=True)
    p_status = sub.add_parser("status", help="show installed and missing tools")
    p_status.add_argument("--category")
    p_status.add_argument("--json", action="store_true")
    p_install = sub.add_parser("install", help="install a selectable tool profile")
    p_install.add_argument("--profile", choices=sorted(PROFILES), default="core")
    p_install.add_argument("--yes", action="store_true", help="execute install commands")
    p_install.add_argument("--dry-run", action="store_true", help="show commands without executing")
    p_install.add_argument("--acknowledge-credential-attack", action="store_true")
    args = parser.parse_args(argv)
    rows = load_registry()
    if args.command == "status":
        installed, missing = status(rows, args.category)
        if args.json:
            print(json.dumps({"platform": platform.system(), "installed": installed, "missing": missing}, indent=2))
        else:
            print_status(rows, args.category)
        return 0
    return install(rows, args.profile, args.yes, args.dry_run, args.acknowledge_credential_attack)


if __name__ == "__main__":
    raise SystemExit(main())
