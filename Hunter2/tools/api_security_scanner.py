#!/usr/bin/env python3
"""
api_security_scanner.py - OWASP API Security Top 10 2023 probing.

Cross-platform (requests). Discovers API specs/endpoints, then runs safe
read-mostly probes: missing auth, BOLA/IDOR (single-identity ID swap),
BFLA method escalation, mass assignment, sensitive-field exposure, SSRF
param detection, debug endpoints, and version inventory.

Usage:
  python tools/api_security_scanner.py <base-url>
  python tools/api_security_scanner.py <base-url> --auth bearer <token>
  python tools/api_security_scanner.py <base-url> --cookie "a=b; c=d"
  python tools/api_security_scanner.py <base-url> --spec https://t/swagger.json
  python tools/api_security_scanner.py <base-url> --id 1001 --check-bola
  python tools/api_security_scanner.py <base-url> --second-token <token> --id 1001

Output: JSON report to stdout + summary lines. No destructive writes.
"""

import argparse
import json
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import requests.exceptions
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    sys.exit(1)

UA = "api-security-scanner/1.0"
TIMEOUT = 10
SPEC_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/v3/api-docs",
    "/v2/api-docs", "/swagger/v1/swagger.json", "/swagger-ui/index.html",
    "/redoc", "/api/swagger.json", "/docs",
]
DEBUG_PATHS = ["/actuator", "/actuator/env", "/debug", "/health", "/metrics",
               "/api/debug", "/console", "/env", "/api/v1/health"]
SENSITIVE_FIELDS = ["email", "phone", "ssn", "dob", "password", "secret",
                    "api_key", "apikey", "token", "credit_card", "card_number",
                    "iban", "passport", "address", "id_card", "cvv"]
SSRF_PARAMS = ["url", "uri", "link", "src", "image_url", "avatar", "callback",
               "webhook", "redirect", "proxy", "feed", "import", "fetch",
               "target", "host", "ip", "domain", "file"]
MASS_ASSIGN_FIELDS = ["role", "is_admin", "admin", "verified", "balance",
                      "price", "status", "permissions", "active", "type"]
AUTH_HEADERS = ["authorization", "cookie", "x-api-key", "apikey", "x-auth-token",
                "x-access-token"]


class Session:
    def __init__(self, base, auth=None, cookie=None, second_token=None):
        self.base = base.rstrip("/")
        self.auth = auth  # ("bearer", token) or None
        self.cookie = cookie
        self.second_token = second_token
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        if cookie:
            self.s.headers["Cookie"] = cookie
        if auth:
            kind, tok = auth
            if kind == "bearer":
                self.s.headers["Authorization"] = f"Bearer {tok}"
            elif kind == "basic":
                self.s.headers["Authorization"] = f"Basic {tok}"
            else:
                self.s.headers["Authorization"] = tok

    def get(self, path, **kw):
        try:
            r = self.s.get(self.base + path, timeout=TIMEOUT, allow_redirects=False, **kw)
            return r
        except requests.RequestException:
            return None

    def post(self, path, **kw):
        try:
            r = self.s.post(self.base + path, timeout=TIMEOUT, allow_redirects=False, **kw)
            return r
        except requests.RequestException:
            return None


def try_specs(sc: Session):
    hits = []
    for p in SPEC_PATHS:
        r = sc.get(p)
        if r is None or r.status_code >= 500:
            continue
        body = r.text[:200]
        looks_spec = (r.status_code in (200, 200) and
                      any(k in body.lower() for k in
                          ("swagger", "openapi", "paths", "components", "definitions",
                           "info", "servers")) and
                      "html" not in body.lower()[:200])
        if looks_spec:
            hits.append({"path": p, "status": r.status_code, "bytes": len(r.text)})
            if p.endswith(".json") or "api-docs" in p:
                try:
                    data = r.json()
                    if isinstance(data, dict) and "paths" in data:
                        for hit in hits:
                            hit["spec"] = data
                except Exception:
                    pass
    return hits


def extract_paths(spec):
    paths = []
    if not spec:
        return paths
    for p, ops in spec.get("paths", {}).items():
        for method, op in ops.items():
            if isinstance(op, dict):
                paths.append({"method": method.upper(), "path": p})
    return paths


def endpoint_candidates(sc: Session):
    """Guess REST paths from the base host + common API prefixes."""
    candidates = set()
    for p in ["/api", "/api/v1", "/api/v2", "/v1", "/v2", "/rest", "/api/v3"]:
        r = sc.get(p)
        if r is not None and r.status_code not in (404, 405, 403, 401):
            candidates.add(p)
    return sorted(candidates)


def check_auth_gaps(sc: Session, paths):
    findings = []
    for ep in paths[:40]:
        r = sc.get(ep["path"])
        if r is None:
            continue
        missing = not any(h.lower() in {k.lower() for k in r.request.headers}
                          for h in AUTH_HEADERS)
        if missing and r.status_code == 200 and "html" not in r.text[:300].lower():
            findings.append({
                "type": "missing-auth",
                "endpoint": f"{ep['method']} {ep['path']}",
                "status": r.status_code,
                "note": "Endpoint returns data without any auth header",
            })
    return findings


def check_bola(sc: Session, paths, base_id, second_token=None):
    findings = []
    for ep in paths[:60]:
        path = ep["path"]
        if not re.search(r"\{\w+\}", path):
            continue
        probe = re.sub(r"\{(\w+)\}", str(base_id), path)
        r = sc.get(probe)
        if r is None:
            continue
        if r.status_code != 200:
            continue
        # If we have a second identity, compare - the strongest evidence.
        if second_token:
            s2 = requests.Session()
            s2.headers["User-Agent"] = UA
            s2.headers["Authorization"] = f"Bearer {second_token}"
            try:
                r2 = s2.get(sc.base + probe, timeout=TIMEOUT, allow_redirects=False)
                if r2.status_code == 200 and r2.text and r2.text != r.text:
                    findings.append({
                        "type": "bola-cross-identity",
                        "endpoint": f"{ep['method']} {probe}",
                        "status_a": r.status_code, "status_b": r2.status_code,
                        "note": "Two identities both receive data for object id (verify ownership)",
                    })
            except requests.RequestException:
                pass
        else:
            # single-identity heuristic: object data returned for id (needs manual confirm)
            if len(r.text) > 50 and "error" not in r.text[:200].lower():
                findings.append({
                    "type": "bola-candidate",
                    "endpoint": f"{ep['method']} {probe}",
                    "status": r.status_code,
                    "note": "Object returned for numeric id - swap to foreign id / second identity to confirm",
                })
    return findings


def check_mass_assignment(sc: Session, paths):
    findings = []
    for ep in paths[:40]:
        if ep["method"] not in ("POST", "PUT", "PATCH"):
            continue
        for f in MASS_ASSIGN_FIELDS[:6]:
            body = {f: "true" if f in ("verified", "admin", "is_admin", "active") else "0"}
            r = sc.post(ep["path"], json=body)
            if r is None:
                continue
            if r.status_code in (200, 201, 202):
                findings.append({
                    "type": "mass-assignment-candidate",
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "field": f,
                    "status": r.status_code,
                    "note": f"Accepted unexpected field '{f}' - verify persistence & impact",
                })
    return findings


def check_bfla(sc: Session, paths):
    findings = []
    for ep in paths[:40]:
        if ep["method"] != "GET":
            continue
        for alt in ("PUT", "POST", "DELETE", "PATCH"):
            r = sc.post(ep["path"], json={})
            if r is None:
                continue
            if r.status_code in (200, 201, 202, 204):
                findings.append({
                    "type": "bfla-candidate",
                    "endpoint": f"POST->{ep['path']}",
                    "status": r.status_code,
                    "note": f"POST succeeded on GET endpoint (check function-level auth)",
                })
                break
    return findings


def check_sensitive_exposure(sc: Session, paths):
    findings = []
    for ep in paths[:40]:
        r = sc.get(ep["path"])
        if r is None or r.status_code != 200:
            continue
        body = r.text.lower()
        for f in SENSITIVE_FIELDS:
            if f in body:
                findings.append({
                    "type": "sensitive-field-exposure",
                    "endpoint": f"GET {ep['path']}",
                    "field": f,
                    "status": 200,
                    "note": f"Field '{f}' present in response - check auth/authorization",
                })
                break
    return findings


def check_ssrf_params(sc: Session, paths):
    findings = []
    for ep in paths[:60]:
        if "{" in ep["path"]:
            continue
        for p in SSRF_PARAMS:
            q = urllib.parse.urlencode({p: "http://127.0.0.1/"})
            r = sc.get(f"{ep['path']}?{q}")
            if r is None:
                continue
            if r.status_code != 404:
                findings.append({
                    "type": "ssrf-param-candidate",
                    "endpoint": f"GET {ep['path']}?{p}=<url>",
                    "status": r.status_code,
                    "note": f"Param '{p}' looks like a URL fetcher - test with oob_listener",
                })
    return findings


def check_debug(sc: Session):
    findings = []
    for p in DEBUG_PATHS:
        r = sc.get(p)
        if r is None:
            continue
        if r.status_code == 200 and len(r.text) > 30:
            findings.append({
                "type": "debug-endpoint",
                "endpoint": p,
                "status": r.status_code,
                "note": "Debug/management endpoint exposed",
            })
    return findings


def check_versions(sc: Session):
    findings = []
    for v in ("v1", "v2", "v3"):
        r = sc.get(f"/{v}")
        if r is not None and r.status_code not in (404, 405):
            findings.append({"type": "version-live", "endpoint": f"/{v}", "status": r.status_code})
    return findings


def main():
    ap = argparse.ArgumentParser(description="OWASP API Top 10 2023 probe")
    ap.add_argument("base", help="base URL e.g. https://api.target.com")
    ap.add_argument("--auth", nargs=2, metavar=("KIND", "VALUE"),
                    help="auth kind: bearer|basic|raw, value")
    ap.add_argument("--cookie", help="cookie header value")
    ap.add_argument("--spec", help="known spec URL (skips discovery)")
    ap.add_argument("--id", type=int, default=1001, help="base object id for BOLA probes")
    ap.add_argument("--second-token", help="second identity bearer token (BOLA proof)")
    ap.add_argument("--max-paths", type=int, default=40, help="cap endpoints probed")
    ap.add_argument("--json", action="store_true", help="print JSON only")
    args = ap.parse_args()

    sc = Session(args.base, auth=args.auth, cookie=args.cookie,
                 second_token=args.second_token)

    report = {"target": args.base, "spec_found": [], "endpoints": [], "findings": []}

    specs = []
    if args.spec:
        r = sc.get(urllib.parse.urlparse(args.spec).path)
        if r is not None:
            try:
                specs.append(r.json())
            except Exception:
                pass
    else:
        hits = try_specs(sc)
        report["spec_found"] = hits
        for h in hits:
            if h.get("spec"):
                specs.append(h["spec"])

    paths = []
    for spec in specs:
        paths.extend(extract_paths(spec))
    # dedupe
    seen = set()
    uniq = []
    for p in paths:
        k = (p["method"], p["path"])
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    paths = uniq[: args.max_paths]
    report["endpoints"] = [f"{p['method']} {p['path']}" for p in paths]

    findings = []
    if paths:
        findings += check_auth_gaps(sc, paths)
        findings += check_bola(sc, paths, args.id, args.second_token)
        findings += check_mass_assignment(sc, paths)
        findings += check_bfla(sc, paths)
        findings += check_sensitive_exposure(sc, paths)
        findings += check_ssrf_params(sc, paths)
    findings += check_debug(sc)
    findings += check_versions(sc)
    report["findings"] = findings

    if args.json:
        print(json.dumps(report, indent=2))
        return

    print(f"\n[+] API security scan: {args.base}")
    print(f"    Specs found: {len(report['spec_found'])} | Endpoints: {len(report['endpoints'])}")
    if not findings:
        print("    No candidates found (try --auth/--second-token for deeper checks).")
    for f in findings:
        print(f"  [!] {f['type']} @ {f['endpoint']} ({f.get('status')}) - {f.get('note','')}")
    print("\n[!] Candidates are POSSIBLE until confirmed manually (see api-security skill).")


if __name__ == "__main__":
    main()
