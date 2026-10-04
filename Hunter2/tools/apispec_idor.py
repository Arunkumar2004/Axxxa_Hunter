#!/usr/bin/env python3
"""
API-spec -> automatic IDOR/BOLA test generator.

Feed it an OpenAPI/Swagger spec (JSON, or YAML if PyYAML is available) and it
finds every endpoint whose path or query carries an object identifier
(`/users/{id}`, `?account_id=`, `/orders/{orderId}`) — the exact surface where
BOLA/IDOR lives — and emits a ready-to-run test plan: the same request issued as
account A and account B, so you can diff the responses for missing
object-level authorization.

The spec-parsing / endpoint-selection logic is pure and unit-tested; nothing here
touches the network (it generates the plan; run it with two real tokens).

Usage:
  tools/apispec_idor.py openapi.json
  tools/apispec_idor.py https://target.com/swagger.json --base https://api.target.com
  tools/apispec_idor.py openapi.json --token-a "$A" --token-b "$B" --sh > idor_tests.sh
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from tools.safe_http import safe_urlopen
except Exception:  # pragma: no cover
    safe_urlopen = None

# Path/query names that denote an object identifier worth an IDOR test.
_ID_HINT = re.compile(r"(^|[_/{])(id|.*_id|.*Id|uuid|guid|slug|handle|user|account|order|"
                      r"invoice|ticket|doc|file|report|project|team|org|customer|"
                      r"payment|card|address|key|token|number|ref)([_/}]|$)", re.I)
_PATH_PARAM = re.compile(r"\{([^}]+)\}")


def _looks_like_id(name: str) -> bool:
    return bool(_ID_HINT.search(name))


def extract_idor_endpoints(spec: dict) -> list[dict]:
    """Pure: return endpoints that carry an object id (candidates for IDOR)."""
    out: list[dict] = []
    base_path = ""
    # Swagger 2.0 basePath; OpenAPI 3 servers.
    if isinstance(spec.get("basePath"), str):
        base_path = spec["basePath"].rstrip("/")
    paths = spec.get("paths", {}) or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        path_params = [p for p in _PATH_PARAM.findall(path) if _looks_like_id(p)]
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            op = op if isinstance(op, dict) else {}
            id_query = []
            for prm in (op.get("parameters", []) or []) + (item.get("parameters", []) or []):
                if isinstance(prm, dict) and prm.get("in") in ("query", "path") and _looks_like_id(str(prm.get("name", ""))):
                    id_query.append(prm["name"])
            id_params = sorted(set(path_params + [q for q in id_query if q not in path_params]))
            if id_params:
                out.append({
                    "method": method.upper(),
                    "path": base_path + path,
                    "id_params": id_params,
                    "summary": (op.get("summary") or op.get("operationId") or "")[:80],
                })
    return out


def build_curls(endpoints: list[dict], base_url: str, token_a: str = "", token_b: str = "") -> list[str]:
    """Pure: for each endpoint, emit an A-vs-B request pair (the IDOR diff).

    The emitted shell text ALWAYS references ``$TOKEN_A``/``$TOKEN_B`` and never
    inlines a literal token, so redirecting this plan to a ``.sh`` file (or
    having it land in shell history) cannot leak a live bearer token. The
    ``token_a``/``token_b`` arguments are accepted for signature compatibility
    but are deliberately NOT written into the output — export the real values in
    the shell before running the plan (``export TOKEN_A=... TOKEN_B=...``).
    """
    lines: list[str] = []
    for ep in endpoints:
        # Fill path params with a placeholder the hunter replaces with a real A-owned id.
        path = re.sub(r"\{[^}]+\}", "OBJECT_ID", ep["path"])
        url = base_url.rstrip("/") + path
        note = f"# {ep['method']} {ep['path']}  ({', '.join(ep['id_params'])}) {ep['summary']}".rstrip()
        # Never inline a real token into saved shell output — always placeholders.
        auth_a = '-H "Authorization: Bearer $TOKEN_A"'
        auth_b = '-H "Authorization: Bearer $TOKEN_B"'
        lines.append(note)
        lines.append(f'curl -sk -X {ep["method"]} {auth_a} "{url}"   # account A (owns OBJECT_ID)')
        lines.append(f'curl -sk -X {ep["method"]} {auth_b} "{url}"   # account B — IDOR if this returns A\'s data')
        lines.append("")
    return lines


def _load_spec(src: str, timeout: int) -> dict:
    if src.startswith(("http://", "https://")):
        req = urllib.request.Request(src, headers={"User-Agent": "Mozilla/5.0 (BugHunter apispec)"})
        opener = safe_urlopen if safe_urlopen else urllib.request.urlopen
        text = opener(req, timeout=timeout).read(20_000_000).decode("utf-8", "replace")
    else:
        text = open(src, encoding="utf-8").read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # optional
            return yaml.safe_load(text)
        except Exception as e:  # pragma: no cover
            raise ValueError(f"spec is not JSON and PyYAML unavailable/failed: {e}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="OpenAPI/Swagger -> IDOR test generator")
    ap.add_argument("spec", help="path or URL to an OpenAPI/Swagger spec (JSON/YAML)")
    ap.add_argument("--base", help="base URL for requests (default: from spec/servers or the spec host)")
    ap.add_argument("--token-a", default="", help="bearer token for account A")
    ap.add_argument("--token-b", default="", help="bearer token for account B")
    ap.add_argument("--sh", action="store_true", help="emit a runnable shell test plan")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args(argv)

    try:
        spec = _load_spec(args.spec, args.timeout)
    except (OSError, ValueError, urllib.error.URLError) as e:
        print(f"[apispec] load failed: {e}", file=sys.stderr)
        return 1
    if not isinstance(spec, dict):
        print("[apispec] spec did not parse to an object", file=sys.stderr)
        return 1

    endpoints = extract_idor_endpoints(spec)
    base = args.base or ""
    if not base:
        servers = spec.get("servers") or []
        if servers and isinstance(servers[0], dict):
            base = servers[0].get("url", "")
        elif spec.get("host"):
            scheme = (spec.get("schemes") or ["https"])[0]
            base = f"{scheme}://{spec['host']}"
    base = base or "https://TARGET"

    if args.json:
        print(json.dumps({"base": base, "endpoints": endpoints}, indent=2))
    elif args.sh:
        print("#!/bin/bash\n# Auto-generated IDOR/BOLA test plan. Replace OBJECT_ID with an id account A owns.")
        print("# Set your tokens first (not written into this file):  export TOKEN_A=... TOKEN_B=...")
        print(f"# Endpoints with object identifiers: {len(endpoints)}\n")
        print("\n".join(build_curls(endpoints, base, args.token_a, args.token_b)))
    else:
        print(f"[apispec] {len(endpoints)} IDOR-candidate endpoints (base={base})")
        for ep in endpoints:
            print(f"  {ep['method']:6s} {ep['path']}  <{', '.join(ep['id_params'])}>  {ep['summary']}")
        print("\nRe-run with --sh (and --token-a/--token-b) to emit runnable A-vs-B tests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
