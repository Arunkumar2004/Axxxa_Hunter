#!/usr/bin/env python3
"""
nuclei-mcp/server.py - MCP stdio server wrapping the nuclei binary
(ProjectDiscovery template scanner).

Tools:
  - nuclei_scan   : run nuclei against a target with tags/severity/template filters
  - nuclei_templates : list loaded templates (count + sample)

Requires `nuclei` on PATH (or NUCLEI_BIN env / common install paths).
Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _minimal_mcp import serve  # noqa: E402

DEFAULT_TIMEOUT = 180


def find_nuclei():
    env = os.environ.get("NUCLEI_BIN")
    if env and Path(env).exists():
        return env
    for name in ("nuclei", "nuclei.exe"):
        p = shutil.which(name)
        if p:
            return p
    for p in (
        os.path.expanduser("~/go/bin/nuclei"),
        os.path.expanduser("~/go/bin/nuclei.exe"),
        os.path.expanduser("~/.local/bin/nuclei"),
        "C:/tools/nuclei.exe",
    ):
        if Path(p).exists():
            return p
    return None


def _run_nuclei(target, tags=None, severity=None, template=None, exclude=None,
                timeout=DEFAULT_TIMEOUT, extra=None):
    bin_path = find_nuclei()
    if not bin_path:
        return ("Nuclei binary not found. Install it (go install "
                "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest) "
                "or set NUCLEI_BIN.", None)

    cmd = [bin_path, "-u", target, "-jsonl", "-silent", "-no-color"]
    if tags:
        cmd += ["-tags", tags]
    if severity:
        cmd += ["-severity", severity]
    if template:
        cmd += ["-t", template]
    if exclude:
        cmd += ["-exclude-tags", exclude]
    if extra:
        cmd += extra

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ("nuclei timed out after {}s (large target? use --severity/critical or tags)".format(timeout), None)
    except Exception as exc:  # noqa: BLE001
        return (f"nuclei failed to start: {exc}", None)

    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings, proc.stderr


def nuclei_scan_handler(args):
    target = (args.get("target") or "").strip()
    if not target:
        return "ERROR: target is required (e.g. https://example.com or example.com:443)"
    findings, err = _run_nuclei(
        target,
        tags=args.get("tags"),
        severity=args.get("severity"),
        template=args.get("template"),
        exclude=args.get("exclude"),
        timeout=int(args.get("timeout", DEFAULT_TIMEOUT)),
        extra=args.get("extra"),
    )
    if findings is None:
        return err or "nuclei error"
    if not findings:
        return f"[+] nuclei: 0 findings for {target}"
    out = [f"[+] nuclei: {len(findings)} finding(s) for {target}"]
    for f in findings:
        info = f.get("info", {})
        out.append(json.dumps({
            "template": f.get("template-id"),
            "severity": info.get("severity"),
            "name": info.get("name"),
            "matched-at": f.get("matched-at"),
            "type": f.get("type"),
        }))
    if err and err.strip():
        out.append("[stderr] " + err.strip()[:500])
    return "\n".join(out)


def nuclei_version_handler(args):
    bin_path = find_nuclei()
    if not bin_path:
        return "Nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    try:
        proc = subprocess.run([bin_path, "-version"], capture_output=True, text=True, timeout=30)
        return (proc.stdout or proc.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"


def main():
    serve("nuclei-mcp", {
        "nuclei_scan": {
            "description": "Run a nuclei template scan against one target. "
                           "Args: target (required), tags, severity (info,low,medium,high,critical), "
                           "template (path), exclude (tags), timeout (sec), extra (list of extra CLI args).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "tags": {"type": "string"},
                    "severity": {"type": "string"},
                    "template": {"type": "string"},
                    "exclude": {"type": "string"},
                    "timeout": {"type": "integer"},
                    "extra": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["target"],
            },
            "handler": nuclei_scan_handler,
        },
        "nuclei_version": {
            "description": "Return the installed nuclei version (or install instructions).",
            "inputSchema": {"type": "object", "properties": {}},
            "handler": nuclei_version_handler,
        },
    })


if __name__ == "__main__":
    main()
