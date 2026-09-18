#!/usr/bin/env python3
"""
Hunter2 Preflight - "what is actually armed right now?"

Run this FIRST at the start of any hunt (the Operating Contract in CLAUDE.md
requires it). It reports, in one screen, what is connected and what is not, so
the operator never assumes a tool/MCP/agent is live when it is only *shipped*.

  python tools/preflight.py            # full readout
  python tools/preflight.py --json     # machine-readable

Pure stdlib. Cross-platform (Windows/Git-Bash/Linux). No network calls except a
localhost port poke for local proxies (Caido/Burp).
"""
import json, os, re, shutil, socket, sys, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OK, WARN, BAD = "OK ", "WARN", "-- "

# Prefer this repo's own tools/bin so recon binaries resolve LOCALLY
# (self-contained) instead of from any other project that is on PATH.
_LOCAL_BIN = str(ROOT / "tools" / "bin")
if _LOCAL_BIN not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = _LOCAL_BIN + os.pathsep + os.environ.get("PATH", "")

# ---- external CLI tools the recon/vuln pipelines expect -------------------
CORE_TOOLS = ["subfinder","assetfinder","amass","dnsx","httpx","katana","gau",
              "waybackurls","nuclei","ffuf","nmap","gf","interactsh-client"]
# known local fallback bins that Defender may quarantine on Windows
FALLBACK_BINDIRS = [ROOT/"tools"/"bin", Path.home()/"go"/"bin"]

def which(tool):
    p = shutil.which(tool)
    if p: return p
    for d in FALLBACK_BINDIRS:
        for ext in ("", ".exe"):
            c = d/(tool+ext)
            if c.exists(): return str(c)
            c2 = d/tool/(tool+ext)
            if c2.exists(): return str(c2)
    return None

def port_open(host, port, t=2.0):
    try:
        with socket.create_connection((host, port), timeout=t):
            return True
    except OSError:
        return False

def resolve_placeholder(val):
    """Resolve config env placeholders against os.environ so the board shows the real URL.
    Handles OpenCode '{env:VAR}' and Claude '${VAR}' / '${VAR:-default}' forms."""
    if not isinstance(val, str) or not val:
        return val or ""
    m = re.match(r"^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$", val)
    if m:
        return os.environ.get(m.group(1), "")
    m = re.match(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}$", val)
    if m:
        return os.environ.get(m.group(1)) or (m.group(2) or "")
    return val


def load_mcp_config():
    """Merge MCP servers declared for Claude Code (.mcp.json / .claude settings) AND
    OpenCode (opencode.json 'mcp' block), so the board is identical in both CLIs."""
    servers = {}
    # Claude Code style: {"mcpServers": {name: {command, env, ...}}}
    for f in [ROOT/".mcp.json", ROOT/".claude"/"settings.json",
              ROOT/".claude"/"settings.local.json", Path.home()/".claude.json"]:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            for k, v in (d.get("mcpServers") or {}).items():
                servers.setdefault(k, {"cfg": v, "src": f.name})
        except Exception:
            pass
    # OpenCode style: {"mcp": {name: {type, command, enabled, environment}}}
    for f in [ROOT/"opencode.json", ROOT/".opencode"/"opencode.json"]:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            for k, v in (d.get("mcp") or {}).items():
                # normalise OpenCode 'environment' -> 'env' so downstream url probe works
                cfg = dict(v)
                if "environment" in cfg and "env" not in cfg:
                    cfg["env"] = cfg["environment"]
                if v.get("enabled") is False:
                    cfg["_disabled"] = True
                servers.setdefault(k, {"cfg": cfg, "src": f.name})
        except Exception:
            pass
    return servers

def main():
    as_json = "--json" in sys.argv
    report = {"tools": {}, "mcp": {}, "agents": 0, "skills": 0, "notes": []}

    # tools
    for t in CORE_TOOLS:
        path = which(t)
        report["tools"][t] = path or None

    # MCP servers (configured != running; MCP loads at Claude Code startup)
    mcp = load_mcp_config()
    for name, meta in mcp.items():
        env = (meta["cfg"].get("env") or {})
        url = resolve_placeholder(env.get("CAIDO_URL") or env.get("BURP_API_URL") or "")
        reachable = None
        if url.startswith("http"):
            try:
                hostport = url.split("//",1)[1].split("/",1)[0]
                h, _, p = hostport.partition(":")
                reachable = port_open(h, int(p or 80))
            except Exception:
                reachable = None
        report["mcp"][name] = {"src": meta["src"], "backend_url": url or None,
                                "backend_reachable": reachable}

    # local proxies even if no MCP entry (so we notice Caido/Burp are up)
    report["proxies"] = {
        "caido(:8080)": port_open("127.0.0.1", 8080),
        "burp(:8080/1337)": port_open("127.0.0.1", 1337),
    }

    # agents & skills shipped
    report["agents"] = len(list((ROOT/".claude"/"agents").glob("*.md"))) or \
                        len(list((ROOT/"agents").glob("*.md")))
    report["skills"] = len([d for d in (ROOT/"skills").glob("*") if d.is_dir()])

    if as_json:
        print(json.dumps(report, indent=2)); return

    # ---- pretty ----
    def line(status, label, detail=""): print(f"  [{status}] {label:26s} {detail}")
    print("\n=== HUNTER2 PREFLIGHT " + "="*34)

    print("\n-- External tools (recon/vuln pipelines) --")
    present = 0
    for t, p in report["tools"].items():
        if p:
            present += 1
            defmark = " (local bin; Defender may quarantine PD tools)" if "Dukan" in (p or "") or "tools\\bin" in (p or "") else ""
            line(OK, t, p + defmark)
        else:
            line(BAD, t, "MISSING - use curl/python fallback")
    print(f"     -> {present}/{len(report['tools'])} tools on PATH. "
          f"httpx/nuclei on Windows are commonly AV-blocked; curl/python cover the same ground.")

    print("\n-- MCP servers (loaded ONLY at Claude Code startup) --")
    if not mcp:
        line(BAD, "(none configured)", "no .mcp.json / empty mcpServers -> no Caido/H1/Burp tools")
    for name, m in report["mcp"].items():
        d = f"src={m['src']}"
        if m["backend_url"]:
            r = m["backend_reachable"]
            d += f"  backend={m['backend_url']} " + ("REACHABLE" if r else ("DOWN" if r is False else "?"))
        line(WARN, name, d + "  (needs Claude Code RESTART to become callable)")

    print("\n-- Local proxies (raw port check) --")
    for name, up in report["proxies"].items():
        line(OK if up else BAD, name, "listening" if up else "not listening")

    print("\n-- Shipped capability --")
    line(OK if report["agents"] else BAD, "agents", f"{report['agents']} specialized agents")
    line(OK if report["skills"] else BAD, "skills", f"{report['skills']} skill domains")

    print("\n-- Readiness verdict --")
    armed = present >= 3 or any(report["proxies"].values())
    if armed:
        print("  READY to hunt. Unarmed items above are optional; curl/python + agents cover core flow.")
    else:
        print("  DEGRADED: few native tools. Proceed with curl/python fallbacks (still fully capable).")
    if mcp and not as_json:
        print("  NOTE: MCP tools (Caido/H1) appear only AFTER a Claude Code restart + approving them.")
    print("="*56 + "\n")

if __name__ == "__main__":
    main()
