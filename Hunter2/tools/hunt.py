#!/usr/bin/env python3
"""
Bug Bounty Hunt Orchestrator
Main script that chains target selection, recon, scanning, and reporting.

Usage:
    python3 hunt.py                         # Full pipeline: select targets + hunt
    python3 hunt.py --target <domain>       # Hunt a specific target
    python3 hunt.py --quick --target <domain>  # Quick scan mode
    python3 hunt.py --recon-only --target <domain>  # Only run recon
    python3 hunt.py --scan-only --target <domain>   # Only run vuln scanner (requires prior recon)
    python3 hunt.py --status                # Show current progress
    python3 hunt.py --setup-wordlists       # Download common wordlists
    python3 hunt.py --cve-hunt --target <domain>   # Focused nuclei CVE sweep
    python3 hunt.py --zero-day --target <domain>   # Run zero-day fuzzer
    python3 hunt.py --graphql --target <domain>    # Auto GraphQL audit when endpoints found
    python3 hunt.py --skip-leads --target <domain> # Skip lead_board ingest + EOL after recon
"""

import argparse
import itertools
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import uuid as _uuid
from datetime import datetime

# Auth session is bundled into the package; importable when run as a script
# because tools/__init__.py is present.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.auth_session import AuthSession, add_cli_args, session_from_args  # noqa: E402
from tools.arsenal import locate_tool  # noqa: E402
from tools.banner import print_banner  # noqa: E402
from tools import coverage_matrix  # noqa: E402

# Process-wide AuthSession. Populated in main() once flags are parsed and
# read by run_recon / run_vuln_scan so every subprocess inherits the same
# session env vars. (Plain assignment — kept 3.9-compatible; the codebase
# elsewhere uses 3.10+ union syntax but hunt.py historically did not.)
_AUTH_SESSION = None


def _mark_coverage(matrix, fragments, status, reason):
    """Apply a stage result only to classes the stage actually exercises."""
    lowered = [fragment.lower() for fragment in fragments]
    for item in matrix["classes"].values():
        name = item["name"].lower()
        if any(fragment in name for fragment in lowered):
            if item["status"] == "FOUND" and status != "FOUND":
                continue
            item.update({"status": status, "reason": reason, "updated_at": coverage_matrix._now()})
    matrix["updated_at"] = coverage_matrix._now()


def _coverage_complete(matrix):
    return coverage_matrix.summary(matrix)["complete"]


def _normalize_argv(argv):
    if not argv:
        return argv
    if argv[0] in {"help", "-help"}:
        return ["--help", *argv[1:]]
    return ["--help" if item == "-help" else item for item in argv]


# ── Target type detection (FQDN / single IP / CIDR) ──────────────────────────

MAX_CIDR_HOSTS = 254

def detect_target_type(target: str) -> str:
    """Return 'list', 'cidr', 'ip', or 'domain'.

    'list' = path to a readable file of pre-resolved hosts (one per line).
    Used for programs without wildcard scope where subdomain enum is wasted.
    """
    if os.path.isfile(target):
        return "list"
    try:
        net = ipaddress.ip_network(target, strict=False)
        return "cidr" if net.num_addresses > 1 else "ip"
    except ValueError:
        return "domain"


def expand_cidr(cidr: str, max_hosts: int = MAX_CIDR_HOSTS) -> list[str]:
    """Expand CIDR to host IPs, rejecting ranges larger than max_hosts."""
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(host) for host in itertools.islice(net.hosts(), max_hosts + 1)]

    if len(hosts) > max_hosts:
        raise ValueError(
            f"CIDR {cidr} expands beyond the supported limit of {max_hosts} hosts; "
            "use /24 or smaller ranges"
        )

    if not hosts:
        return [str(net.network_address)]
    return hosts

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(TOOLS_DIR)
TARGETS_DIR = os.path.join(BASE_DIR, "targets")
RECON_DIR = os.path.join(BASE_DIR, "recon")
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")


def _validate_domain_for_path(domain: str) -> str:
    """Reject anything that isn't a plain path segment before it touches
    os.path.join — closes the path-traversal gap in SECURITY-REVIEW-
    2026-08-22.md finding #0/#7 (domain flowing unsanitized into
    RECON_DIR/FINDINGS_DIR joins)."""
    if not domain or "/" in domain or "\\" in domain or ".." in domain:
        raise ValueError(f"invalid domain for path resolution: {domain!r}")
    return domain


def _resolve_recon_dir(domain: str) -> str:
    domain = _validate_domain_for_path(domain)
    return os.path.join(RECON_DIR, domain)


def _resolve_findings_dir(domain: str, create: bool = False) -> str:
    domain = _validate_domain_for_path(domain)
    path = os.path.join(FINDINGS_DIR, domain)
    if create:
        os.makedirs(path, exist_ok=True)
    return path


def _activate_recon_session(
    domain: str, requested_session_id: str = "latest", create: bool = False
) -> tuple[str, str]:
    """Resolve (and optionally create) a session directory under
    RECON_DIR/<domain>/sessions/<session_id>/, for agent.py's --resume
    support. Session IDs sort lexicographically by creation time (ISO
    timestamp prefix), so 'latest' is just the last directory name."""
    domain = _validate_domain_for_path(domain)
    sessions_dir = os.path.join(RECON_DIR, domain, "sessions")

    if create and requested_session_id in (None, "latest", ""):
        session_id = f"{datetime.now().strftime('%Y%m%dT%H%M%S%f')}-{_uuid.uuid4().hex[:8]}"
        session_dir = os.path.join(sessions_dir, session_id)
        os.makedirs(session_dir, exist_ok=True)
        return session_id, session_dir

    if not os.path.isdir(sessions_dir):
        raise ValueError(f"no sessions exist for domain {domain!r}")
    existing = sorted(
        d for d in os.listdir(sessions_dir) if os.path.isdir(os.path.join(sessions_dir, d))
    )
    if not existing:
        raise ValueError(f"no sessions exist for domain {domain!r}")

    if requested_session_id in (None, "latest", ""):
        session_id = existing[-1]
    elif requested_session_id in existing:
        session_id = requested_session_id
    else:
        raise ValueError(f"unknown session id {requested_session_id!r} for domain {domain!r}")

    session_dir = os.path.join(sessions_dir, session_id)
    if create:
        os.makedirs(session_dir, exist_ok=True)
    return session_id, session_dir

# Colors
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


# os.setsid / os.killpg / os.getpgid are POSIX-only. On Windows they raise
# AttributeError, which previously crashed every run_cmd() call (and thus recon
# ingest, EOL, etc.). Detect the platform once and use process groups only where
# they exist; on Windows fall back to a plain kill.
_POSIX = hasattr(os, "setsid")


def _kill_proc_tree(proc):
    """Best-effort kill of a child (and its group on POSIX)."""
    if proc is None:
        return
    try:
        if _POSIX:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait()
    except OSError:
        pass


def run_cmd(cmd, cwd=None, timeout=600):
    """Run an argv command and return (success, output).

    On POSIX, runs the child in its own process group (os.setsid) so a timeout
    kills the whole tree via os.killpg. On Windows those APIs don't exist, so we
    use a new process group flag and a plain kill instead.
    """
    proc = None
    if isinstance(cmd, str):
        cmd = shlex.split(cmd, posix=os.name != "nt")
    if not cmd:
        return False, "Command failed: empty argv"
    if cmd[0] == "python3":
        cmd[0] = sys.executable
    popen_kwargs = dict(
        shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, cwd=cwd,
    )
    if _POSIX:
        popen_kwargs["preexec_fn"] = os.setsid
    elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
        stdout, _ = proc.communicate(timeout=timeout)
        return proc.returncode == 0, stdout or ""
    except subprocess.TimeoutExpired:
        _kill_proc_tree(proc)
        return False, f"Command timed out after {timeout}s: {cmd[:120]}"
    except Exception as e:
        _kill_proc_tree(proc)
        return False, f"Command failed ({type(e).__name__}): {e}"


def check_tools():
    """Check which tools are installed.

    Prefers ``external_arsenal.sh`` (full ~50-tool registry). Falls back to a
    short core list if the arsenal script is missing or fails.
    """
    # shutil.which is platform-neutral.  The old implementation delegated
    # `command -v` to subprocess(shell=True), which silently failed on
    # Windows PowerShell and reported every tool as missing even when Git
    # Bash/Go binaries were installed.
    arsenal = os.path.join(TOOLS_DIR, "external_arsenal.sh")
    if os.path.isfile(arsenal):
        # Parse `tool|category|...` rows and probe each binary.
        installed, missing = [], []
        try:
            with open(arsenal, encoding="utf-8", errors="replace") as fh:
                in_registry = False
                for line in fh:
                    line = line.strip()
                    if line.startswith("ARSENAL_TOOLS=("):
                        in_registry = True
                        continue
                    if in_registry and line == ")":
                        break
                    if not in_registry:
                        continue
                    if not line.startswith('"') or "|" not in line:
                        continue
                    # "name|category|hint|url"
                    inner = line.strip(' ",')
                    name = inner.split("|", 1)[0].strip()
                    if not name or name.startswith("#"):
                        continue
                    (installed if locate_tool(name) else missing).append(name)
            if installed or missing:
                return installed, missing
        except OSError:
            pass

    tools = [
        "subfinder", "httpx", "nuclei", "ffuf", "nmap", "amass", "gau",
        "dalfox", "subjack", "katana", "arjun", "trufflehog", "gitleaks",
    ]
    installed, missing = [], []
    for tool in tools:
        (installed if locate_tool(tool) else missing).append(tool)
    return installed, missing


def setup_wordlists():
    """Download common wordlists for fuzzing."""
    os.makedirs(WORDLIST_DIR, exist_ok=True)

    wordlists = {
        "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "raft-medium-dirs.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
        "api-endpoints.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "params.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    }

    for name, url in wordlists.items():
        filepath = os.path.join(WORDLIST_DIR, name)
        if os.path.exists(filepath):
            log("ok", f"Wordlist exists: {name}")
            continue

        log("info", f"Downloading {name}...")
        success, output = run_cmd(["curl", "-sL", url, "-o", filepath])
        if success and os.path.getsize(filepath) > 100:
            lines = sum(1 for _ in open(filepath))
            log("ok", f"Downloaded {name} ({lines} entries)")
        else:
            log("err", f"Failed to download {name}")

    log("ok", f"Wordlists ready in {WORDLIST_DIR}")


def select_targets(top_n=10):
    """Run target selector."""
    log("info", "Running target selector...")
    script = os.path.join(TOOLS_DIR, "target_selector.py")
    success, output = run_cmd([sys.executable, script, "--top", str(top_n)], timeout=60)
    print(output)

    if not success:
        log("err", f"Target selection failed: {output[:200]}")
        return []

    # Load selected targets
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        try:
            with open(targets_file) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            log("err", f"Could not read targets file {targets_file}: {e}")
            return []
        return data.get("targets", [])

    log("err", f"Targets file not found: {targets_file}")
    return []


def run_recon(domain, quick=False, scope_lock=False, max_urls=None):
    """Run recon engine on a domain, single IP, or CIDR range."""
    log("info", f"Running recon on {domain}...")
    script = os.path.join(TOOLS_DIR, "recon_engine.sh")
    quick_flag = "--quick" if quick else ""

    # Detect target type and pass to recon_engine.sh
    target_type = detect_target_type(domain)
    if target_type in ("ip", "cidr", "list"):
        scope_lock = True  # IPs/CIDRs/pre-resolved lists never need subdomain enum
        log("info", f"Target type: {target_type.upper()} — subdomain enum skipped")
        if target_type == "cidr":
            try:
                hosts = expand_cidr(domain)
            except ValueError as exc:
                log("err", str(exc))
                return False
            log("info", f"CIDR {domain} → {len(hosts)} host(s) to scan")
        elif target_type == "list":
            try:
                with open(domain, "r", encoding="utf-8") as f:
                    n = sum(
                        1 for line in f
                        if line.strip() and not line.lstrip().startswith("#")
                    )
            except OSError as exc:
                log("err", f"Could not read domain list {domain}: {exc}")
                return False
            if n == 0:
                log("err", f"Domain list {domain} has no usable entries")
                return False
            log("info", f"Domain list {domain} → {n} host(s) to scan")

    # Pass SCOPE_LOCK / TARGET_TYPE through the child environment, NOT as a
    # `VAR=x bash ...` command prefix. The prefix form is bash-only syntax; on
    # Windows subprocess(shell=True) runs cmd.exe, which treated "TARGET_TYPE=..."
    # as a command name and failed — silently skipping recon entirely.
    child_env = os.environ.copy()
    if scope_lock:
        child_env["SCOPE_LOCK"] = "1"
    child_env["TARGET_TYPE"] = target_type

    # Inject auth env vars (if any) so the bash helper picks them up.
    if _AUTH_SESSION is not None:
        _AUTH_SESSION.export_to_env(child_env)
        if not _AUTH_SESSION.is_empty():
            log("info", _AUTH_SESSION.describe())

    # Run with live output
    try:
        bash = shutil.which("bash")
        if not bash:
            log("err", "bash is required for recon_engine.sh on this host")
            return False
        argv = [bash, script, domain]
        if quick_flag:
            argv.append(quick_flag)
        proc = subprocess.Popen(argv, shell=False, cwd=BASE_DIR, env=child_env)
        proc.wait(timeout=3600)  # 60 min timeout (CIDR ranges can be large)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Recon timed out for {domain}")
        return False


def check_cicd_results(domain):
    """Check and surface CI/CD scan results from recon Phase 8."""
    cicd_dir = os.path.join(RECON_DIR, domain, "cicd")
    if not os.path.isdir(cicd_dir):
        return
    for root, dirs, files in os.walk(cicd_dir):
        for f in files:
            if f == "summary.txt":
                summary_path = os.path.join(root, f)
                with open(summary_path) as sf:
                    content = sf.read()
                if "Total findings: 0" not in content:
                    log("warn", f"CI/CD findings detected — review: {summary_path}")


def ingest_lead_board(domain):
    """Parse recon into the persistent lead ledger and print the top lead."""
    script = os.path.join(TOOLS_DIR, "lead_board.py")
    if not os.path.isfile(script):
        log("warn", "lead_board.py missing — skip lead ingest")
        return False

    recon_dir = os.path.join(RECON_DIR, domain)
    if not os.path.isdir(recon_dir):
        log("warn", f"No recon dir for {domain} — skip lead ingest")
        return False

    log("info", f"Ingesting lead board for {domain}...")
    ok, out = run_cmd(
        [sys.executable, script, "ingest", domain, "--recon-dir", recon_dir],
        timeout=120,
    )
    if out.strip():
        print(out.rstrip())
    if not ok:
        log("warn", f"lead_board ingest returned non-zero for {domain}")
        return False

    ok2, out2 = run_cmd([sys.executable, script, "next", domain], timeout=30)
    if out2.strip():
        log("info", "Top untouched lead:")
        print(out2.rstrip())
    return ok2


def _tech_pairs_from_recon(domain):
    """Best-effort product=version pairs from recon/technologies.txt."""
    candidates = [
        os.path.join(RECON_DIR, domain, "technologies.txt"),
        os.path.join(RECON_DIR, f"{domain}-technologies.txt"),
    ]
    lines = []
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines.extend(ln.strip() for ln in fh if ln.strip())
        except OSError:
            continue

    pairs = []
    seen = set()
    for raw in lines:
        # Accept "php=7.4", "php:7.4", "PHP/7.4", "nginx 1.18.0"
        m = re.match(
            r"(?i)^([a-z][a-z0-9_.+-]+)\s*[=:/]\s*([0-9][0-9a-zA-Z._+-]*)",
            raw,
        )
        if not m:
            m = re.match(
                r"(?i)^([a-z][a-z0-9_.+-]+)\s+([0-9][0-9a-zA-Z._+-]*)",
                raw,
            )
        if not m:
            continue
        product, version = m.group(1).lower(), m.group(2)
        key = f"{product}={version}"
        if key not in seen:
            seen.add(key)
            pairs.append(key)
    return pairs


def run_eol_check(domain):
    """Run EOL lifecycle intel against fingerprint pairs from recon."""
    script = os.path.join(TOOLS_DIR, "eol_check.py")
    if not os.path.isfile(script):
        return False
    pairs = _tech_pairs_from_recon(domain)
    if not pairs:
        log("info", "No product=version fingerprints for EOL check")
        return False

    tech = ",".join(pairs[:20])
    log("info", f"EOL check: {tech}")
    ok, out = run_cmd([sys.executable, script, "--tech", tech], timeout=60)
    if out.strip():
        print(out.rstrip())
    return ok


def run_graphql_audit(domain):
    """Run graphql_audit.sh against any GraphQL URLs found in recon."""
    script = os.path.join(TOOLS_DIR, "graphql_audit.sh")
    if not os.path.isfile(script):
        log("warn", "graphql_audit.sh missing")
        return False

    recon_dir = os.path.join(RECON_DIR, domain)
    gql_files = [
        os.path.join(recon_dir, "urls", "graphql.txt"),
        os.path.join(recon_dir, "graphql.txt"),
    ]
    urls = []
    for path in gql_files:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    u = line.strip()
                    if u.startswith("http"):
                        urls.append(u)
        except OSError:
            continue

    # Also grep all-urls for /graphql paths
    for path in (
        os.path.join(recon_dir, "urls", "all.txt"),
        os.path.join(recon_dir, "all-urls.txt"),
    ):
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if re.search(r"/graphql|/gql|/graphiql", line, re.I):
                        u = line.strip().split()[0]
                        if u.startswith("http"):
                            urls.append(u)
        except OSError:
            continue

    # dedupe preserve order
    seen, uniq = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    urls = uniq[:5]

    if not urls:
        log("info", "No GraphQL endpoints found — skip graphql audit")
        return False

    child_env = os.environ.copy()
    if _AUTH_SESSION is not None:
        _AUTH_SESSION.export_to_env(child_env)

    any_ok = False
    for url in urls:
        log("info", f"GraphQL audit: {url}")
        out_dir = os.path.join(FINDINGS_DIR, domain, "graphql")
        os.makedirs(out_dir, exist_ok=True)
        try:
            proc = subprocess.Popen(
                ["bash", str(script), url, "--output-dir", out_dir],
                shell=False, cwd=BASE_DIR, env=child_env,
            )
            proc.wait(timeout=600)
            any_ok = any_ok or proc.returncode == 0
        except subprocess.TimeoutExpired:
            proc.kill()
            log("err", f"GraphQL audit timed out for {url}")
    return any_ok


# ── Extended class scanners ──────────────────────────────────────────────────
# These purpose-built Python scanners already exist in tools/ but the legacy
# vuln_scanner.sh pipeline never invoked them, so a plain /hunt silently skipped
# entire bug classes (CORS, CRLF, NoSQLi, XXE, CSRF, prototype pollution,
# WebSocket, HPP/postMessage). They all share the same CLI shape:
#   <scanner>.py -l <url-list> --json   (+ optional --cookie / --oob)
# so wiring them is a matter of feeding each the recon URL list and capturing
# the JSON. Detection-only against the authorized recon surface — no new
# payloads authored here, each scanner keeps its own safety model.
EXTENDED_SCANNERS = [
    ("cors", "cors_scanner.py", []),
    ("crlf", "crlf_scanner.py", ["--host-header"]),
    ("xxe", "xxe_scanner.py", []),
    ("csrf", "csrf_scanner.py", []),
    ("prototype_pollution", "prototype_pollution_scanner.py", []),
    ("hpp_postmessage", "hpp_postmessage_scanner.py", []),
    ("websocket", "websocket_scanner.py", []),
]

MAX_EXTENDED_URLS = 60


def _collect_recon_urls(domain, limit=MAX_EXTENDED_URLS):
    """Gather live URLs from recon output, tolerating both the nested and flat
    layouts. Returns a deduped, order-preserving list capped at ``limit``."""
    recon_dir = os.path.join(RECON_DIR, domain)
    candidates = [
        os.path.join(recon_dir, "live", "urls.txt"),
        os.path.join(recon_dir, "urls", "all.txt"),
        os.path.join(recon_dir, "all-urls.txt"),
        os.path.join(recon_dir, "live-hosts.txt"),
    ]
    seen, urls = set(), []
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    u = line.strip().split()[0] if line.strip() else ""
                    if u.startswith("http") and u not in seen:
                        seen.add(u)
                        urls.append(u)
                        if len(urls) >= limit:
                            return urls
        except OSError:
            continue
    return urls


def run_extended_scans(domain, quick=False):
    """Run the class scanners the legacy pipeline skipped against recon URLs.

    Writes one JSON file per class to findings/<domain>/extended/<class>.json.
    Non-fatal: a missing scanner or a single scan failure never aborts the hunt.
    Blind XXE automatically picks up an OOB collaborator from BBHUNT_OOB_DOMAIN
    when the operator has exported one (see /oob), closing the blind-bug gap.
    """
    urls = _collect_recon_urls(domain)
    if not urls:
        log("info", "No recon URLs for extended class scans — skip")
        return False

    out_dir = os.path.join(FINDINGS_DIR, domain, "extended")
    os.makedirs(out_dir, exist_ok=True)
    url_list = os.path.join(out_dir, "_urls.txt")
    with open(url_list, "w", encoding="utf-8") as fh:
        fh.write("\n".join(urls) + "\n")

    cookie = os.environ.get("BBHUNT_COOKIE", "")
    oob_domain = os.environ.get("BBHUNT_OOB_DOMAIN", "")
    per_scan_timeout = 300 if quick else 600

    log("info", f"Extended class scans on {len(urls)} URL(s): "
                f"{', '.join(name for name, *_ in EXTENDED_SCANNERS)}")

    any_ran = False
    for name, script_name, extra in EXTENDED_SCANNERS:
        script = os.path.join(TOOLS_DIR, script_name)
        if not os.path.isfile(script):
            log("warn", f"  {name}: {script_name} missing — skip")
            continue

        cmd = ["python3", script, "-l", url_list, "--json", *extra]
        if cookie:
            cmd += ["--cookie", cookie]
        if name == "xxe" and oob_domain:
            cmd += ["--oob", oob_domain]

        out_file = os.path.join(out_dir, f"{name}.json")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=BASE_DIR,
            )
            stdout, _ = proc.communicate(timeout=per_scan_timeout)
            with open(out_file, "w", encoding="utf-8") as fh:
                fh.write(stdout or "")
            any_ran = True
            flagged = "hit" if stdout and ('"finding"' in stdout or '"severity"' in stdout
                                           or '"vulnerable": true' in stdout.lower()) else "clean"
            log("ok" if flagged == "hit" else "info", f"  {name}: {flagged} → {out_file}")
        except subprocess.TimeoutExpired:
            proc.kill()
            log("warn", f"  {name}: timed out after {per_scan_timeout}s")
        except Exception as e:  # noqa: BLE001 - scanner isolation, never abort the hunt
            log("warn", f"  {name}: {type(e).__name__}: {e}")

    return any_ran


def run_recon_freshness(domain):
    """Diff recon vs the previous snapshot and surface new assets (Rule 12)."""
    try:
        from tools.recon_diff import diff_target
    except Exception as e:  # noqa: BLE001
        log("warn", f"recon_diff unavailable: {e}")
        return False
    try:
        res = diff_target(domain, save=True)
    except (ValueError, FileNotFoundError) as e:
        log("warn", f"recon freshness skipped: {e}")
        return False

    new_subs = res.get("subdomains", {}).get("new_count", 0)
    new_urls = res.get("urls", {}).get("new_count", 0)
    if res.get("subdomains", {}).get("first_run") and res.get("urls", {}).get("first_run"):
        log("info", "Recon freshness: first snapshot taken (no prior run to diff)")
    elif new_subs or new_urls:
        log("ok", f"Recon freshness: {new_subs} new subdomain(s), {new_urls} new URL(s) "
                  f"→ recon/{domain}/fresh/ (hunt these first — Rule 12)")
    else:
        log("info", "Recon freshness: no new assets since last hunt")
    return True


def run_playbook_context(domain):
    """Surface the real-world playbook for every class this hunt will touch, so the
    agent auto-reads the right methodology per lead (Phase 1, Step #1). Writes
    findings/<domain>/PLAYBOOKS.md mapping class -> playbook path + checklist size.
    Non-fatal."""
    try:
        from tools.playbook_router import resolve, load_playbook, REFERENCES_DIR
    except Exception as e:  # noqa: BLE001
        log("warn", f"playbook_router unavailable: {e}")
        return False

    # The core classes a full hunt should always have methodology ready for.
    classes = [
        "idor-bola", "auth-session", "account-takeover", "oauth", "jwt", "saml-sso",
        "ssrf", "sqli", "xss", "ssti", "rce", "command-injection", "business-logic",
        "race-condition", "csrf", "cors", "xxe", "nosqli", "file-upload",
        "open-redirect", "graphql", "prototype-pollution", "subdomain-takeover",
        "path-traversal-lfi", "request-smuggling", "web-cache", "secrets-leak",
    ]
    out_dir = os.path.join(FINDINGS_DIR, domain)
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "PLAYBOOKS.md")

    lines = [
        f"# Playbooks for {domain}",
        "",
        "Auto-resolved by playbook_router. For each lead, OPEN the matching file and "
        "follow its checklist + rejection rules before testing.",
        "",
        "| Class | Playbook | Checklist items | Rejection rules |",
        "|---|---|---|---|",
    ]
    resolved = 0
    for c in classes:
        pb = load_playbook(c)
        if not pb:
            continue
        resolved += 1
        rel = os.path.relpath(pb["path"], BASE_DIR)
        lines.append(
            f"| {c} | `{rel}` | {len(pb.get('checklist', []))} | "
            f"{len(pb.get('rejection_rules', []))} |"
        )
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    log("ok", f"Playbook context: {resolved} class playbooks indexed → {out_file}")
    return True


def run_two_account_idor(domain, unsafe=False):
    """Two-account IDOR/BOLA harness — the #1 expert move for access-control bugs.

    Replays account A's requests with account B's auth (and vice-versa) across the
    recon URL set to detect cross-tenant/cross-account reads. Reads the operator's
    OWN two accounts from .env (ACCOUNT_A_TOKEN/COOKIE, ACCOUNT_B_TOKEN/COOKIE).
    Skips cleanly when both accounts are not configured. Detection-only; safe HTTP
    methods unless unsafe=True. Never logs raw token values.
    """
    try:
        from tools.credential_store import CredentialStore
        from tools.two_account_idor import run as run_ta
    except Exception as e:  # noqa: BLE001
        log("warn", f"two-account harness unavailable: {e}")
        return False

    env_path = os.path.join(BASE_DIR, ".env")
    store = CredentialStore(env_path)
    have_a = store.has("ACCOUNT_A_TOKEN") or store.has("ACCOUNT_A_COOKIE")
    have_b = store.has("ACCOUNT_B_TOKEN") or store.has("ACCOUNT_B_COOKIE")
    if not (have_a and have_b):
        log("info", "Two-account IDOR: skipped (set ACCOUNT_A_/ACCOUNT_B_ creds in "
                    ".env to enable the highest-value access-control tests)")
        return False

    urls = _collect_recon_urls(domain)
    if not urls:
        log("info", "Two-account IDOR: no recon URLs — skip")
        return False

    log("info", f"Two-account IDOR/BOLA on {len(urls)} URL(s)")
    try:
        findings = run_ta(urls, store, unsafe=unsafe)
    except Exception as e:  # noqa: BLE001
        log("warn", f"Two-account IDOR failed: {type(e).__name__}: {e}")
        return False

    out_dir = os.path.join(FINDINGS_DIR, domain)
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "two_account_idor.json")
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)

    hits = [f for f in findings if f.get("verdict") == "POSSIBLE_IDOR"]
    if hits:
        log("ok", f"Two-account IDOR: {len(hits)} POSSIBLE cross-account read(s) → "
                  f"{out_file} — VALIDATE by hand before reporting")
        # Auto-chain (Phase 2, Step #3): each confirmed-ish access-control hit is a
        # signal the same flaw exists nearby — generate sibling + A→B next-tests.
        _chain_from_hits(domain, hits, "idor")
    else:
        log("info", f"Two-account IDOR: no cross-account reads → {out_file}")
    return True


def _chain_from_hits(domain, hits, vuln_class):
    """Run the chain engine on confirmed hits and write next-test plans. Non-fatal."""
    try:
        from tools.chain_engine import chain as _chain
    except Exception as e:  # noqa: BLE001
        log("warn", f"chain_engine unavailable: {e}")
        return False
    plans = []
    for h in hits:
        url = h.get("url") or h.get("endpoint") or ""
        if not url:
            continue
        try:
            plans.append(_chain({"vuln_class": vuln_class, "url": url}))
        except Exception:  # noqa: BLE001
            continue
    if not plans:
        return False
    out_dir = os.path.join(FINDINGS_DIR, domain)
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "chains.json")
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(plans, fh, indent=2)
    total_next = sum(len(p.get("ranked_next", [])) for p in plans)
    log("ok", f"Auto-chain: {total_next} next-test(s) from {len(plans)} hit(s) "
              f"(sibling rule + A→B) → {out_file}")
    return True


def run_vuln_scan(domain, quick=False, full=False):
    """Run vulnerability scanner on recon results."""
    recon_dir = os.path.join(RECON_DIR, domain)
    if not os.path.isdir(recon_dir):
        log("err", f"No recon data found for {domain}. Run recon first.")
        return False

    log("info", f"Running vulnerability scanner on {domain}...")
    script = os.path.join(TOOLS_DIR, "vuln_scanner.sh")
    quick_flag = "--quick" if quick else ""

    child_env = os.environ.copy()
    if _AUTH_SESSION is not None:
        _AUTH_SESSION.export_to_env(child_env)

    try:
        bash = shutil.which("bash")
        if not bash:
            log("err", "bash is required for vuln_scanner.sh on this host")
            return False
        argv = [bash, script, recon_dir]
        if quick_flag:
            argv.append(quick_flag)
        proc = subprocess.Popen(argv, shell=False, cwd=BASE_DIR, env=child_env)
        proc.wait(timeout=1800)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Vulnerability scan timed out for {domain}")
        return False


def generate_reports(domain):
    """Generate reports for findings."""
    log("warn", "report_generator.py has been removed. Use /report in Claude Code to generate reports.")
    return 0


def show_status():
    """Show current pipeline status."""
    print(f"\n{BOLD}{'='*50}{NC}")
    print(f"{BOLD}  Bug Bounty Pipeline Status{NC}")
    print(f"{BOLD}{'='*50}{NC}\n")

    # Check tools
    installed, missing = check_tools()
    print(f"  Tools: {len(installed)}/{len(installed)+len(missing)} installed")
    if missing:
        print(f"  Missing: {', '.join(missing)}")

    # Check targets
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        print(f"  Selected targets: {data.get('total_targets', 0)}")
    else:
        print("  Selected targets: None (run target selector first)")

    # Check recon results
    if os.path.isdir(RECON_DIR):
        recon_targets = [d for d in os.listdir(RECON_DIR) if os.path.isdir(os.path.join(RECON_DIR, d))]
        print(f"  Recon completed: {len(recon_targets)} targets")
        for t in recon_targets:
            subs_file = os.path.join(RECON_DIR, t, "subdomains", "all.txt")
            live_file = os.path.join(RECON_DIR, t, "live", "urls.txt")
            subs = sum(1 for _ in open(subs_file)) if os.path.exists(subs_file) else 0
            live = sum(1 for _ in open(live_file)) if os.path.exists(live_file) else 0
            print(f"    - {t}: {subs} subdomains, {live} live hosts")

    # Check findings
    if os.path.isdir(FINDINGS_DIR):
        finding_targets = [d for d in os.listdir(FINDINGS_DIR) if os.path.isdir(os.path.join(FINDINGS_DIR, d))]
        print(f"  Scanned targets: {len(finding_targets)}")
        for t in finding_targets:
            summary = os.path.join(FINDINGS_DIR, t, "summary.txt")
            if os.path.exists(summary):
                with open(summary) as f:
                    content = f.read()
                total_match = content.split("TOTAL FINDINGS:")
                if len(total_match) > 1:
                    total = total_match[1].strip().split("\n")[0].strip()
                    print(f"    - {t}: {total} findings")

    # Check reports
    if os.path.isdir(REPORTS_DIR):
        report_targets = [d for d in os.listdir(REPORTS_DIR) if os.path.isdir(os.path.join(REPORTS_DIR, d))]
        print(f"  Reports generated: {len(report_targets)} targets")
        for t in report_targets:
            reports = [f for f in os.listdir(os.path.join(REPORTS_DIR, t)) if f.endswith(".md") and f != "SUMMARY.md"]
            print(f"    - {t}: {len(reports)} reports")

    print(f"\n{'='*50}\n")


def print_dashboard(results):
    """Print final summary dashboard."""
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  HUNT COMPLETE — Summary Dashboard{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    total_findings = 0
    total_reports = 0

    for r in results:
        status_icon = f"{GREEN}OK{NC}" if r["success"] else f"{RED}FAIL{NC}"
        print(f"  [{status_icon}] {r['domain']}")
        print(f"       Recon: {'Done' if r.get('recon') else 'Skipped'} | "
              f"Leads: {'Done' if r.get('leads') else '—'} | "
              f"Scan: {'Done' if r.get('scan') else 'Skipped'} | "
              f"Extended: {'Done' if r.get('extended') else '—'} | "
              f"Reports: {r.get('reports', 0)}")
        coverage = r.get("coverage_summary") or coverage_matrix.summary(r.get("coverage", {"classes": {}}))
        counts = coverage.get("counts", {})
        print(
            f"       Coverage: FOUND={counts.get('FOUND', 0)} "
            f"TESTED={counts.get('TESTED', 0)} N/A={counts.get('N/A', 0)} "
            f"BLOCKED={counts.get('BLOCKED', 0)} PENDING={counts.get('PENDING', 0)}"
        )
        if coverage.get("unresolved"):
            print(f"       Unresolved: {', '.join(coverage['unresolved'])}")
        total_findings += r.get("findings", 0)
        total_reports += r.get("reports", 0)

    print(f"\n  Total reports generated: {total_reports}")
    print(f"\n  Reports directory: {REPORTS_DIR}/")
    print(f"\n{'='*60}")

    if total_reports > 0:
        print(f"\n  {YELLOW}Next steps:{NC}")
        print("  1. Review each report in the reports/ directory")
        print("  2. Manually verify findings before submitting")
        print("  3. Add PoC screenshots where applicable")
        print("  4. Submit via HackerOne program pages")
        print(f"\n{'='*60}\n")


def run_cve_hunt(domain):
    """Run focused nuclei CVE sweep via cve_scan.sh."""
    script = os.path.join(TOOLS_DIR, "cve_scan.sh")
    if not os.path.isfile(script):
        log("warn", "cve_scan.sh missing — use /intel for CVE intelligence")
        return False

    log("info", f"Running CVE sweep on {domain}...")
    child_env = os.environ.copy()
    if _AUTH_SESSION is not None:
        _AUTH_SESSION.export_to_env(child_env)

    try:
        bash = shutil.which("bash")
        if not bash:
            log("err", "bash is required for cve_scan.sh on this host")
            return False
        proc = subprocess.Popen([bash, script, domain], shell=False, cwd=BASE_DIR, env=child_env)
        proc.wait(timeout=900)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"CVE sweep timed out for {domain}")
        return False


def run_zero_day_fuzzer(domain, deep=False):
    """Run zero-day fuzzer on a target."""
    log("info", f"Running zero-day fuzzer on {domain}...")
    script = os.path.join(TOOLS_DIR, "zero_day_fuzzer.py")
    deep_flag = "--deep" if deep else ""

    # Check if we have recon data with live URLs
    recon_dir = os.path.join(RECON_DIR, domain)
    if os.path.isdir(recon_dir):
        cmd = f'python3 "{script}" "https://{domain}" --recon-dir "{recon_dir}" {deep_flag}'
    else:
        cmd = f'python3 "{script}" "https://{domain}" {deep_flag}'

    try:
        proc = subprocess.Popen(shlex.split(cmd, posix=os.name != "nt"), shell=False, cwd=BASE_DIR)
        proc.wait(timeout=900)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Zero-day fuzzer timed out for {domain}")
        return False


def hunt_target(
    domain,
    quick=False,
    recon_only=False,
    scan_only=False,
    cve_hunt=False,
    zero_day=False,
    skip_leads=False,
    graphql=False,
    extended=True,
    two_account=False,
    two_account_unsafe=False,
):
    """Run the full hunt pipeline on a single target."""
    result = {
        "domain": domain,
        "success": True,
        "recon": False,
        "scan": False,
        "leads": False,
        "reports": 0,
    }
    result["coverage"] = coverage_matrix.load(domain)
    coverage_matrix.save(result["coverage"])

    if not scan_only:
        result["recon"] = run_recon(domain, quick=quick)
        if not result["recon"]:
            log("warn", f"Recon had issues for {domain}, continuing anyway...")

        # Learning memory (Phase 2 #7): surface prior outcomes so the agent
        # repeats winning techniques and skips dead ends. Best-effort only —
        # a memory hiccup must never break the hunt.
        try:
            from tools.hunt_memory import summarize_for_hunt as _summarize_memory
            _mem = _summarize_memory(domain)
            log("info", f"memory: {len(_mem['worked'])} prior wins, {len(_mem['dead_ends'])} dead ends")
        except Exception:
            pass

        # Feedback loop (L2.1): boost techniques that got PAID and skip ones that
        # got rejected/duped on real submissions. Best-effort — never fatal.
        try:
            from tools.feedback_loop import advise_for_hunt as _advise_feedback
            _fb = _advise_feedback(domain)
            log("info", f"feedback: {len(_fb['boost'])} techniques to boost, {len(_fb['avoid'])} to avoid")
        except Exception:
            pass

        # Post-recon enrichment: never lose a lead + flag EOL tech.
        if not skip_leads and os.path.isdir(os.path.join(RECON_DIR, domain)):
            result["leads"] = ingest_lead_board(domain)
            run_eol_check(domain)

        # Freshness diff: surface assets that appeared since the last hunt so the
        # operator prioritizes them (Rule 12: NEW == UNREVIEWED). Non-fatal.
        if os.path.isdir(os.path.join(RECON_DIR, domain)):
            run_recon_freshness(domain)

    # Surface the per-class playbooks so the agent auto-reads the right methodology
    # for each lead (Phase 1, Step #1). Cheap + always useful.
    run_playbook_context(domain)

    # Attack-surface graph (Level 2 v1): connect recon into a map, flag IDOR/action
    # candidates, sibling clusters, and version anomalies. Non-fatal.
    try:
        from tools.surface_graph import build_graph as _bg, write_graph as _wg
        _g = _bg(domain)
        _wg(domain, _g)
        _s = _g["stats"]
        log("ok", f"Surface graph: {_s['endpoints']} endpoints, "
                  f"{_s['sibling_clusters']} clusters, {_s['anomalies']} leads "
                  f"→ findings/{domain}/SURFACE_GRAPH.md")
    except Exception as e:  # noqa: BLE001
        log("warn", f"surface graph skipped: {type(e).__name__}: {e}")

    if recon_only:
        result["success"] = _coverage_complete(result["coverage"])
        coverage_matrix.save(result["coverage"])
        return result

    check_cicd_results(domain)

    if graphql:
        graphql_ok = run_graphql_audit(domain)
        if graphql_ok:
            _mark_coverage(result["coverage"], ["graphql"], "TESTED", "GraphQL audit completed")

    result["scan"] = run_vuln_scan(domain, quick=quick)
    if result["scan"]:
        _mark_coverage(
            result["coverage"],
            ["sql injection", "xss", "ssti", "ssrf", "os command injection"],
            "TESTED",
            "main vulnerability scanner completed; findings require validation",
        )

    # Extended class scanners the legacy vuln_scanner.sh never called
    # (CORS/CRLF/XXE/CSRF/prototype-pollution/HPP/WebSocket). On by default so a
    # plain /hunt covers these classes; disable with --no-extended.
    if extended:
        result["extended"] = run_extended_scans(domain, quick=quick)
        if result["extended"]:
            _mark_coverage(
                result["coverage"],
                [
                    "nosql injection", "xxe", "csrf", "cors", "crlf", "host header",
                    "prototype pollution", "websocket", "hpp", "postmessage",
                ],
                "TESTED",
                "extended scanner completed; findings require validation",
            )

    # Two-account IDOR/BOLA harness — highest-value access-control test. Runs only
    # when the operator has configured their own two accounts in .env.
    if two_account:
        result["two_account"] = run_two_account_idor(domain, unsafe=two_account_unsafe)
        if result.get("two_account"):
            _mark_coverage(
                result["coverage"],
                ["idor", "bola", "broken access control", "privilege escalation"],
                "TESTED",
                "two-account harness completed; POSSIBLE_IDOR hits require validation",
            )

    # CVE hunting (only when explicitly requested)
    if cve_hunt:
        run_cve_hunt(domain)

    # Zero-day fuzzing (disabled by default — high false positive rate)
    if zero_day:
        log("warn", "Zero-day fuzzer enabled — results require manual verification")
        run_zero_day_fuzzer(domain, deep=not quick)

    result["reports"] = generate_reports(domain)
    coverage_matrix.save(result["coverage"])
    result["coverage_summary"] = coverage_matrix.summary(result["coverage"])
    result["success"] = _coverage_complete(result["coverage"])

    return result


def main():
    argv = _normalize_argv(sys.argv[1:])
    parser = argparse.ArgumentParser(
        description="Bug Bounty Hunt Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hunt.py                            Full pipeline (select + hunt)
  python3 hunt.py --target example.com       Hunt specific target
  python3 hunt.py --quick --target example.com  Quick scan
  python3 hunt.py --status                   Show progress
  python3 hunt.py --setup-wordlists          Download wordlists
  python3 hunt.py --graphql --target example.com  Audit GraphQL endpoints from recon
  python3 hunt.py --cve-hunt --target example.com Focused nuclei CVE sweep
        """
    )
    parser.add_argument("--target", type=str, help="Target: FQDN, IP, or CIDR (e.g. example.com, 192.168.1.1, 10.0.0.0/24)")
    parser.add_argument("--quick", action="store_true", help="Quick scan mode (fewer checks)")
    parser.add_argument("--recon-only", action="store_true", help="Only run reconnaissance")
    parser.add_argument("--scan-only", action="store_true", help="Only run vulnerability scanner")
    parser.add_argument("--report-only", action="store_true", help="Only generate reports")
    parser.add_argument("--status", action="store_true", help="Show pipeline status")
    parser.add_argument("--setup-wordlists", action="store_true", help="Download wordlists")
    parser.add_argument("--cve-hunt", action="store_true", help="Run focused nuclei CVE sweep (cve_scan.sh)")
    parser.add_argument("--zero-day", action="store_true", help="Run zero-day fuzzer")
    parser.add_argument("--agent", action="store_true", help="Run the agent-driven hunt backend")
    parser.add_argument("--langgraph", action="store_true", help="Use LangGraph for --agent")
    parser.add_argument("--max-steps", type=int, default=20, help="Maximum agent steps")
    parser.add_argument("--time-budget", type=float, default=2.0, help="Agent time budget in hours")
    parser.add_argument("--graphql", action="store_true",
                        help="Run graphql_audit.sh on GraphQL URLs found in recon")
    parser.add_argument("--skip-leads", action="store_true",
                        help="Skip lead_board ingest + EOL check after recon")
    parser.add_argument("--no-extended", action="store_true",
                        help="Skip the extended class scanners "
                             "(CORS/CRLF/XXE/CSRF/prototype-pollution/HPP/WebSocket)")
    parser.add_argument("--two-account", action="store_true",
                        help="Run the two-account IDOR/BOLA harness (needs ACCOUNT_A_/"
                             "ACCOUNT_B_ creds in .env; highest-value access-control test)")
    parser.add_argument("--two-account-unsafe", action="store_true",
                        help="Allow state-changing HTTP methods in the two-account harness "
                             "(default: safe GET/HEAD/OPTIONS only)")
    parser.add_argument("--select-targets", action="store_true", help="Only run target selection")
    parser.add_argument("--top", type=int, default=10, help="Number of targets to select")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress the startup banner (useful for CI / piped output)")
    add_cli_args(parser)
    args = parser.parse_args(argv)

    # Build the auth session once. It propagates to every subprocess via
    # BBHUNT_AUTH_HEADERS / BBHUNT_SESSION_ID env vars (set per-call so the
    # session_id is consistent across recon, scan, and audit log entries).
    global _AUTH_SESSION
    _AUTH_SESSION = session_from_args(args)

    # Suppress banner on --status / --setup-wordlists (utility paths that
    # shouldn't print a splash) and when explicitly disabled.
    _banner_suppressed = args.no_banner or args.status or args.setup_wordlists
    if args.no_banner:
        os.environ["BBHUNT_NO_BANNER"] = "1"
    if not _banner_suppressed:
        print_banner(
            "Bug Bounty Automation Pipeline",
            target=args.target or "(target selector)",
            steps=[
                ("Recon",    "subdomain enum, URL crawl, tech fingerprint, CVE sweep"),
                ("Leads",    "lead_board ingest → route signals to hunt-* skills"),
                ("Hunt",     "XSS · SQLi · SSRF · IDOR · auth bypass · GraphQL · LLM"),
                ("Validate", "7-Question Gate · 4-gate checklist · kill weak findings"),
                ("Report",   "H1/Bugcrowd/Intigriti template · CVSS 3.1 · PoC + repro"),
            ],
        )

    # Status check
    if args.status:
        show_status()
        return

    # Setup wordlists
    if args.setup_wordlists:
        setup_wordlists()
        return

    if not any((
        args.target,
        args.recon_only,
        args.scan_only,
        args.report_only,
        args.cve_hunt,
        args.zero_day,
        args.select_targets,
    )):
        print("\nQuick start:")
        print("  python3 tools/hunt.py --target target.com")
        print("  python3 tools/hunt.py --scan-only --target target.com")
        print("  python3 tools/hunt.py --status")

    # Check tools
    installed, missing = check_tools()
    log("info", f"Tools: {len(installed)}/{len(installed)+len(missing)} installed")
    if missing:
        log("warn", f"Missing tools: {', '.join(missing[:12])}{'…' if len(missing) > 12 else ''}")
        log("warn", "Missing tools are skipped; see: python tools/arsenal.py status")
        log("warn", "Install selectively: python tools/arsenal.py install --profile core --dry-run")

    # Target selection only
    if args.select_targets:
        select_targets(top_n=args.top)
        return

    if args.agent:
        if not args.target:
            parser.error("--agent requires --target")
        from tools.scope_checker import ScopeChecker
        from agent import run_agent_hunt
        agent_result = run_agent_hunt(
            args.target,
            scope_lock=True,
            max_steps=args.max_steps,
            time_budget_hours=args.time_budget,
            use_langgraph=args.langgraph,
            scope_checker=ScopeChecker([args.target]),
        )
        print(json.dumps(agent_result, indent=2, default=str))
        return

    # Report only
    if args.report_only:
        if args.target:
            generate_reports(args.target)
        else:
            if os.path.isdir(FINDINGS_DIR):
                for d in os.listdir(FINDINGS_DIR):
                    if os.path.isdir(os.path.join(FINDINGS_DIR, d)):
                        generate_reports(d)
        return

    # Hunt specific target
    if args.target:
        log("info", f"Hunting target: {args.target}")

        # Setup wordlists if missing
        if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
            setup_wordlists()

        result = hunt_target(
            args.target,
            quick=args.quick,
            recon_only=args.recon_only,
            scan_only=args.scan_only,
            cve_hunt=args.cve_hunt,
            zero_day=args.zero_day,
            skip_leads=args.skip_leads,
            graphql=args.graphql,
            extended=not args.no_extended,
            two_account=args.two_account,
            two_account_unsafe=args.two_account_unsafe,
        )
        print_dashboard([result])
        return

    # Full pipeline: select targets then hunt each
    log("info", "Starting full pipeline...")

    # Setup wordlists
    if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
        setup_wordlists()

    # Select targets
    targets = select_targets(top_n=args.top)
    if not targets:
        log("err", "No targets selected. Exiting.")
        sys.exit(1)

    # Hunt each target
    results = []
    for i, target in enumerate(targets):
        domains = target.get("scope_domains", [])
        if not domains:
            log("warn", f"No domains for {target.get('name', 'unknown')} — skipping")
            continue

        # Hunt the primary domain
        primary_domain = domains[0]
        log("info", f"[{i+1}/{len(targets)}] Hunting: {target.get('name', primary_domain)}")
        log("info", f"  Domain: {primary_domain}")
        log("info", f"  Program: {target.get('url', 'N/A')}")

        result = hunt_target(
            primary_domain,
            quick=args.quick,
            skip_leads=args.skip_leads,
            graphql=args.graphql,
            extended=not args.no_extended,
            two_account=args.two_account,
            two_account_unsafe=args.two_account_unsafe,
        )
        results.append(result)

    print_dashboard(results)


if __name__ == "__main__":
    main()
