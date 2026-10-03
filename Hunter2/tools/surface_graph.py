#!/usr/bin/env python3
"""
surface_graph.py — Attack-Surface Graph (Level 2, v1).

Turns a flat recon URL list into a CONNECTED map so the hunt reasons about the app
instead of testing URLs in isolation:

  host -> path-family -> endpoints -> params

and surfaces the two things a flat list can't see:

  1. ENDPOINT CLUSTERS (siblings) — endpoints sharing a path family; one bug in the
     family is a signal to test the rest (feeds the chain engine / sibling rule).
  2. ANOMALIES ("the odd one out") — an endpoint that differs from its siblings in a
     way that often means a bug: no-auth sibling among authed ones, a lone verb, an
     id-bearing endpoint with no sibling ownership check, a stray older API version.

v1 is built entirely from recon output (no live requests, no new deps — stdlib only).
It writes a machine graph + a readable report the agent/operator reads before hunting.

v2 adds an OPTIONAL live auth-probing layer (--probe): it fetches a small, prioritized
set of REAL (non-templated) URLs as anonymous / account-A / account-B to learn which
endpoints actually require login, and flags REAL missing-auth + cross-account gaps
(not guesses). The HTTP layer is injectable (fetch=...) so tests never hit the network;
it is GET-only, rate-limited, and capped so a live run stays small and responsible. It
reuses the repo's CredentialStore (.env A/B creds) and safe_urlopen (SSRF-safe fetch),
and never logs or returns raw tokens or response bodies — only statuses + body lengths.

Usage:
    python3 surface_graph.py --target example.com
    python3 surface_graph.py --target example.com --json
    python3 surface_graph.py --target example.com --probe --env .env --limit 40
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime
from typing import Callable
from urllib.parse import urlsplit, parse_qs

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(TOOLS_DIR)
RECON_DIR = os.path.join(BASE_DIR, "recon")
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
from tools.credential_store import CredentialStore  # noqa: E402
from tools.safe_http import safe_urlopen  # noqa: E402

log = logging.getLogger("surface_graph")

USER_AGENT = "agentic-bug-hunter/surface_graph"

# fetch(url, headers) -> (status:int, body:str) — injectable so tests skip the network.
Fetch = Callable[[str, dict], tuple]

# Bodies count as "the same data" when their lengths are within 5% of each other
# (dynamic timestamps/CSRF tokens shift a few bytes but the record is otherwise the same).
_LEN_RATIO_THRESHOLD = 0.95

# api / versioned path marker (reused by graph + probe prioritization).
_API_RE = re.compile(r"/api(/|$)|/v\d+(/|$)", re.I)
# obvious public storefront browse pages (product/category + a store slug) — low value, skip.
_STOREFRONT_RE = re.compile(r"/(products|categories)/[A-Za-z0-9][A-Za-z0-9_-]*", re.I)

# path segments that look like an object id (numeric, uuid, long hash, slug-with-digits)
_ID_RE = re.compile(
    r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{20,}|[0-9a-fA-F]{16,}|[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*)$"
)
_VERSION_RE = re.compile(r"^(v\d+|api|v\d+\.\d+)$", re.I)
# verbs that imply a state-changing / high-value action on an object
_ACTION_WORDS = {
    "export", "delete", "remove", "share", "invite", "transfer", "download",
    "update", "edit", "settings", "admin", "approve", "cancel", "refund", "pay",
    "payout", "withdraw", "role", "permission", "owner", "manage",
}


def _validate(target: str) -> str:
    if not target or "/" in target or "\\" in target or ".." in target:
        raise ValueError(f"invalid target: {target!r}")
    return target


def _read_lines(path: str) -> list[str]:
    out: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    out.append(s.split()[0])
    except OSError:
        pass
    return out


def _collect_urls(recon_dir: str) -> list[str]:
    urls, seen = [], set()
    for rel in (
        os.path.join("urls", "all.txt"),
        os.path.join("urls", "with_params.txt"),
        os.path.join("urls", "api_endpoints.txt"),
        "all-urls.txt",
        os.path.join("live", "urls.txt"),
        "live.txt",
    ):
        for u in _read_lines(os.path.join(recon_dir, rel)):
            if u.startswith("http") and u not in seen:
                seen.add(u)
                urls.append(u)
    return urls


def _normalize_path(path: str) -> tuple[str, bool]:
    """Return (templated_path, has_id). Replaces id-like segments with {id} so that
    /api/user/123/orders and /api/user/456/orders collapse to one family."""
    segs = [s for s in path.split("/") if s]
    out, has_id = [], False
    for s in segs:
        if _ID_RE.match(s) and not _VERSION_RE.match(s):
            out.append("{id}")
            has_id = True
        else:
            out.append(s)
    return "/" + "/".join(out), has_id


def _family(host: str, templated_path: str) -> str:
    """Path family = host + templated path with the LAST segment dropped, so siblings
    (/user/{id}/orders, /user/{id}/export) share a family."""
    segs = [s for s in templated_path.split("/") if s]
    base = "/".join(segs[:-1]) if len(segs) > 1 else "/".join(segs)
    return f"{host}/{base}"


def build_graph(target: str) -> dict:
    """Build the attack-surface graph for a target from its recon output."""
    target = _validate(target)
    recon_dir = os.path.join(RECON_DIR, target)
    if not os.path.isdir(recon_dir):
        raise FileNotFoundError(f"no recon dir for {target} — run recon first")

    subdomains = _read_lines(os.path.join(recon_dir, "subdomains", "all.txt"))
    urls = _collect_urls(recon_dir)

    # nodes
    hosts: set[str] = set()
    endpoints: dict[str, dict] = {}          # templated endpoint -> meta
    families: dict[str, list[str]] = defaultdict(list)  # family -> [templated endpoints]
    params: dict[str, int] = defaultdict(int)

    for u in urls:
        parts = urlsplit(u)
        host = parts.netloc
        if not host:
            continue
        hosts.add(host)
        tpath, has_id = _normalize_path(parts.path or "/")
        key = f"{host}{tpath}"
        qs = parse_qs(parts.query)
        for p in qs:
            params[p] += 1
        last = [s for s in tpath.split("/") if s]
        verb = last[-1].lower() if last else ""
        ep = endpoints.setdefault(key, {
            "host": host,
            "path": tpath,
            "has_id": has_id,
            "params": set(),
            "action": verb in _ACTION_WORDS,
            "api": bool(re.search(r"/api(/|$)|/v\d+(/|$)", tpath, re.I)),
            "count": 0,
        })
        ep["params"].update(qs.keys())
        ep["has_id"] = ep["has_id"] or has_id
        ep["count"] += 1
        fam = _family(host, tpath)
        if key not in families[fam]:
            families[fam].append(key)

    # ---- anomaly detection (the "odd one out" heuristics) ----
    anomalies: list[dict] = []

    # 1. id-bearing endpoints = IDOR/BOLA candidates (worth two-account testing)
    for key, ep in endpoints.items():
        if ep["has_id"]:
            anomalies.append({
                "type": "idor_candidate",
                "endpoint": key,
                "why": "path carries an object id -> test cross-account access (two accounts)",
                "priority": "high" if (ep["api"] or ep["action"]) else "medium",
            })

    # 2. high-value action verbs on objects = privesc / sensitive-action candidates
    for key, ep in endpoints.items():
        if ep["action"]:
            anomalies.append({
                "type": "sensitive_action",
                "endpoint": key,
                "why": f"action endpoint ({ep['path'].rsplit('/',1)[-1]}) -> test auth + CSRF + IDOR on it",
                "priority": "high",
            })

    # 3. sibling clusters worth the sibling rule (family with >1 endpoint)
    clusters = []
    for fam, members in families.items():
        if len(members) > 1:
            clusters.append({"family": fam, "members": members, "size": len(members)})
    clusters.sort(key=lambda c: c["size"], reverse=True)

    # 4. lone API version among a family (stray /v1 when siblings are /v2)
    ver_by_base: dict[str, set] = defaultdict(set)
    for key in endpoints:
        m = re.search(r"/(v\d+)(/|$)", key, re.I)
        if m:
            base = key[:m.start()] + key[m.end()-1:]
            ver_by_base[base].add(m.group(1).lower())
    for base, vers in ver_by_base.items():
        if len(vers) > 1:
            anomalies.append({
                "type": "multiple_api_versions",
                "endpoint": base,
                "why": f"multiple API versions seen ({', '.join(sorted(vers))}) -> test older versions for weaker auth",
                "priority": "high",
            })

    # dedupe anomalies by (type, endpoint)
    seen_a, uniq = set(), []
    for a in anomalies:
        k = (a["type"], a["endpoint"])
        if k not in seen_a:
            seen_a.add(k)
            uniq.append(a)

    # make endpoints JSON-serializable
    ep_out = {}
    for k, v in endpoints.items():
        v = dict(v)
        v["params"] = sorted(v["params"])
        ep_out[k] = v

    return {
        "target": target,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "stats": {
            "subdomains": len(subdomains),
            "hosts_with_urls": len(hosts),
            "endpoints": len(ep_out),
            "families": len(families),
            "sibling_clusters": len(clusters),
            "anomalies": len(uniq),
            "unique_params": len(params),
        },
        "hosts": sorted(hosts),
        "endpoints": ep_out,
        "sibling_clusters": clusters[:50],
        "anomalies": sorted(uniq, key=lambda a: 0 if a["priority"] == "high" else 1),
        "top_params": sorted(params.items(), key=lambda kv: kv[1], reverse=True)[:20],
    }


def write_graph(target: str, graph: dict) -> tuple[str, str]:
    out_dir = os.path.join(FINDINGS_DIR, target)
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "surface_graph.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(graph, fh, indent=2)

    md_path = os.path.join(out_dir, "SURFACE_GRAPH.md")
    s = graph["stats"]
    lines = [
        f"# Attack-Surface Graph — {target}",
        f"_generated {graph['generated_at']}_",
        "",
        f"- Hosts with URLs: **{s['hosts_with_urls']}**  ·  Subdomains: {s['subdomains']}",
        f"- Endpoints: **{s['endpoints']}**  ·  Families: {s['families']}  ·  "
        f"Sibling clusters: **{s['sibling_clusters']}**",
        f"- Anomalies / leads: **{s['anomalies']}**  ·  Unique params: {s['unique_params']}",
        "",
        "## Priority leads (hunt these first)",
    ]
    high = [a for a in graph["anomalies"] if a["priority"] == "high"][:30]
    if high:
        for a in high:
            lines.append(f"- **[{a['type']}]** `{a['endpoint']}` — {a['why']}")
    else:
        lines.append("- (none flagged high — check medium leads in surface_graph.json)")

    lines += ["", "## Biggest sibling clusters (apply the Sibling Rule)"]
    for c in graph["sibling_clusters"][:12]:
        lines.append(f"- `{c['family']}` → {c['size']} siblings")
        for m in c["members"][:6]:
            lines.append(f"    - {m}")

    lp = graph.get("live_probe")
    if lp is not None:
        lines += ["", "## Live auth-probing"]
        if lp.get("skipped"):
            lines.append(f"- skipped: {lp['skipped']}")
        else:
            rr = lp.get("role_reachability", {})
            lines.append(
                f"- Probed: **{lp.get('probed', 0)}** URLs  ·  anon-reachable: "
                f"{rr.get('anon_reachable', 0)}  ·  auth-only: {rr.get('auth_only', 0)}  ·  "
                f"blocked: {rr.get('blocked', 0)}"
            )
            probe_anoms = lp.get("anomalies", [])
            if probe_anoms:
                for a in probe_anoms:
                    lines.append(f"- **[{a['type']}]** `{a['endpoint']}` — {a['why']}")
            else:
                lines.append("- no live auth anomalies flagged")

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return json_path, md_path


# ---------------------------------------------------------------------------
# Live auth-probing layer (v2, optional --probe) — injectable, GET-only, capped.
# ---------------------------------------------------------------------------

def _is_api_or_sensitive(url: str) -> bool:
    """True if a URL is an api endpoint or carries an action/sensitive verb.

    These are the endpoints where an anonymous 200 is a real missing-auth signal
    (a public marketing page returning 200 to anon is expected, not a bug)."""
    path = urlsplit(url).path or "/"
    if _API_RE.search(path):
        return True
    segs = [s for s in path.split("/") if s]
    return any(s.lower() in _ACTION_WORDS for s in segs)


def _probe_score(url: str) -> int | None:
    """Score a concrete URL for probing worth. Returns None to SKIP it.

    Skips obvious public storefront browse pages (/products/<slug>, /categories/
    <slug>) unless they are also api endpoints. Otherwise prioritizes api
    endpoints, id-bearing paths, and action-verb / sensitive paths."""
    path = urlsplit(url).path or "/"
    api = bool(_API_RE.search(path))
    if _STOREFRONT_RE.search(path) and not api:
        return None  # public storefront page — low value, don't waste a live request
    score = 0
    if api:
        score += 3
    _, has_id = _normalize_path(path)
    if has_id:
        score += 2
    segs = [s for s in path.split("/") if s]
    if any(s.lower() in _ACTION_WORDS for s in segs):
        score += 2
    return score


def _concrete_probe_urls(recon_dir: str, limit: int = 40) -> list[str]:
    """Pick REAL (non-templated) recon URLs worth live-probing.

    Prioritizes api + id-bearing + action-verb + sensitive paths, explicitly
    skips obvious public storefront pages, and caps at `limit` so the live run
    stays small and responsible (no DoS)."""
    scored: list[tuple[int, str]] = []
    for u in _collect_urls(recon_dir):
        if not u.startswith("http"):
            continue
        s = _probe_score(u)
        if s is None:
            continue
        scored.append((s, u))
    # highest value first; stable sort preserves recon order within a score tier.
    scored.sort(key=lambda t: t[0], reverse=True)
    return [u for _, u in scored[:limit]]


def _account_headers(store: CredentialStore, prefix: str) -> dict:
    """Build auth headers for one account, preferring a bearer TOKEN over COOKIE."""
    token_key = f"{prefix}_TOKEN"
    cookie_key = f"{prefix}_COOKIE"
    if store.has(token_key):
        return store.as_headers(token_key, header_type="bearer")
    if store.has(cookie_key):
        return store.as_headers(cookie_key, header_type="cookie")
    return {}


def _len_ratio(len_a: int, len_b: int) -> float:
    """Length-similarity ratio in [0, 1]; 0 if either side is empty."""
    if len_a <= 0 or len_b <= 0:
        return 0.0
    return min(len_a, len_b) / max(len_a, len_b)


def _probe_fetch(url: str, headers: dict, timeout: int) -> tuple:
    """Real GET via the SSRF-safe wrapper. Returns (status, body).

    Network/DNS failures return (0, "") so one dead host never aborts the batch;
    HTTPError (4xx/5xx) still carries a status + body and is reported."""
    req_headers = {"User-Agent": USER_AGENT}
    req_headers.update(headers or {})
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    try:
        with safe_urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return (resp.status, body)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return (e.code, body)
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError):
        return (0, "")


def probe_auth(
    urls: list[str],
    store: CredentialStore,
    *,
    fetch: Fetch | None = None,
    limit: int = 40,
    sleep: float = 0.3,
    timeout: int = 12,
) -> dict:
    """Probe each URL as anon / account-A / account-B to find REAL auth gaps.

    SAFE + responsible: GET only, capped at `limit`, polite `sleep` between real
    requests. The HTTP layer is injectable via `fetch(url, headers) -> (status,
    body)` so tests never touch the network (default: a safe_urlopen GET).

    Flags two HIGH-priority anomalies:
      - missing_auth:  anon_status == 200 on an api/sensitive endpoint (real
                       unauthenticated access, not a guess).
      - cross_account: A=200 and B=200 with near-identical body length (ratio >
                       0.95) — account B may be seeing account A's data; flag it
                       for two-account validation.

    Returns {probed, results, anomalies, role_reachability}. If A/B creds are
    missing, returns {"skipped": "no ACCOUNT_A/B creds"}. NEVER returns raw
    tokens or response bodies — only statuses and body lengths."""
    a_headers = _account_headers(store, "ACCOUNT_A")
    b_headers = _account_headers(store, "ACCOUNT_B")
    if not a_headers or not b_headers:
        return {"skipped": "no ACCOUNT_A/B creds"}

    real = fetch is None
    if fetch is None:
        def fetch(u: str, h: dict) -> tuple:  # bind timeout for the real GET
            return _probe_fetch(u, h, timeout)

    results: list[dict] = []
    anomalies: list[dict] = []
    role = {"anon_reachable": 0, "auth_only": 0, "blocked": 0}

    first = True
    for url in urls[:limit]:
        if not first and real and sleep:
            time.sleep(sleep)
        first = False

        anon_status, anon_body = fetch(url, {})
        a_status, a_body = fetch(url, a_headers)
        b_status, b_body = fetch(url, b_headers)
        a_len, b_len = len(a_body), len(b_body)

        results.append({
            "url": url,
            "anon_status": anon_status,
            "a_status": a_status,
            "b_status": b_status,
        })

        # role reachability tally
        if anon_status == 200:
            role["anon_reachable"] += 1
        elif a_status == 200 or b_status == 200:
            role["auth_only"] += 1
        else:
            role["blocked"] += 1

        # missing_auth: anon already gets 200 on an api/sensitive endpoint.
        if anon_status == 200 and _is_api_or_sensitive(url):
            anomalies.append({
                "type": "missing_auth",
                "endpoint": url,
                "why": "anonymous request returns 200 on an api/sensitive endpoint -> real missing authentication",
                "priority": "high",
                "anon_status": anon_status,
            })

        # cross_account: A and B both 200 with near-identical body length.
        if a_status == 200 and b_status == 200 and _len_ratio(a_len, b_len) > _LEN_RATIO_THRESHOLD:
            anomalies.append({
                "type": "cross_account",
                "endpoint": url,
                "why": "account A and account B both get 200 with near-identical body size -> B may see A's data; validate with two-account IDOR harness",
                "priority": "high",
                "a_status": a_status,
                "b_status": b_status,
                "a_len": a_len,
                "b_len": b_len,
            })

    return {
        "probed": len(results),
        "results": results,
        "anomalies": anomalies,
        "role_reachability": role,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Attack-surface graph (Level 2 v2)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--json", action="store_true", help="print the graph JSON")
    ap.add_argument("--probe", action="store_true",
                    help="run live auth-probing (anon/A/B) after building the graph (needs ACCOUNT_A/B creds)")
    ap.add_argument("--env", default=".env", help="path to the .env credential file (default: .env)")
    ap.add_argument("--limit", type=int, default=40, help="max concrete URLs to live-probe (default: 40)")
    args = ap.parse_args(argv)
    try:
        graph = build_graph(args.target)
    except (ValueError, FileNotFoundError) as e:
        print(f"[-] {e}", file=sys.stderr)
        return 1

    if args.probe:
        store = CredentialStore(args.env)
        recon_dir = os.path.join(RECON_DIR, args.target)
        probe_urls = _concrete_probe_urls(recon_dir, args.limit)
        probe = probe_auth(probe_urls, store, limit=args.limit)
        graph["live_probe"] = probe
        # merge live anomalies into the graph's lead list + refresh the count.
        for a in probe.get("anomalies", []):
            graph["anomalies"].append(a)
        graph["anomalies"] = sorted(
            graph["anomalies"], key=lambda a: 0 if a["priority"] == "high" else 1
        )
        graph["stats"]["anomalies"] = len(graph["anomalies"])

    json_path, md_path = write_graph(args.target, graph)
    if args.json:
        print(json.dumps(graph, indent=2))
    else:
        s = graph["stats"]
        print(f"[+] Surface graph: {s['endpoints']} endpoints, {s['sibling_clusters']} "
              f"clusters, {s['anomalies']} leads")
        lp = graph.get("live_probe")
        if lp is not None:
            if lp.get("skipped"):
                print(f"    live auth-probing skipped: {lp['skipped']}")
            else:
                print(f"    live auth-probing: {lp['probed']} URLs, "
                      f"{len(lp['anomalies'])} auth anomalies")
        print(f"    {md_path}")
        print(f"    {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
