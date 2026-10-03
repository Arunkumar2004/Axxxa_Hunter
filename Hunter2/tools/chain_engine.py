#!/usr/bin/env python3
"""
Chain engine — auto-chain the next tests after a confirmed bug (Phase 2, Step #3).

When the hunter confirms bug A, an expert does not stop: they immediately look for
bugs B and C. Two heuristics drive that reflex (both documented in commands/hunt.md
"Phase 4: A->B Signal Method"):

  * Sibling Rule — the same object is almost always exposed through related
    endpoints (export/delete/share/...) and older API versions that share the same
    (broken) access-control code path. Test the siblings.
  * A->B signal table — one confirmed bug class implies specific neighbouring
    classes worth checking right now (e.g. IDOR on GET -> IDOR on PUT/DELETE).

Given a confirmed finding, this module produces a ranked list of concrete next
tests so the hunt loop can pivot from A straight into B and C.

Usage:
    python3 chain_engine.py --class idor --url https://t.com/api/user/123/orders
    python3 chain_engine.py --class idor --url https://t.com/... --json
    python3 chain_engine.py --json finding.json        # read finding from a file
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.parse import urlsplit, urlunsplit

# Last-segment swaps: the sibling operations that most often share the broken
# access-control / ownership check of the confirmed endpoint.
SIBLING_SUFFIXES = [
    "export", "delete", "share", "archive", "download",
    "restore", "transfer", "update", "invite", "settings",
]

# Version markers to swap — older API versions frequently miss checks added later.
VERSION_MARKERS = ["/v1/", "/v2/", "/v3/", "/api/v1/", "/api/v2/"]

# --------------------------------------------------------------------------- #
# A->B signal table (commands/hunt.md, Phase 4). Keyed by normalized vuln class.
# Each value is the [B, C] follow-ups, as {"check", "rationale"}.
# --------------------------------------------------------------------------- #
AB_TABLE: dict[str, list[dict[str, str]]] = {
    "idor": [
        {"check": "IDOR on PUT/DELETE at the same path",
         "rationale": "A missing ownership check on GET usually means the write "
                      "methods on the same resource are unprotected too."},
        {"check": "IDOR on sibling endpoints of the same object",
         "rationale": "The same object is exposed through related endpoints that "
                      "share the broken access-control code path."},
    ],
    "auth": [
        {"check": "Every sibling endpoint in the same controller",
         "rationale": "Auth is often wired per-controller; if one route is "
                      "unprotected its siblings usually are too."},
        {"check": "Older API version of the endpoint",
         "rationale": "Legacy API versions frequently lack the auth checks added "
                      "to the current version."},
    ],
    "xss": [
        {"check": "Does an admin view the stored payload? (privilege escalation)",
         "rationale": "Stored XSS that renders in an admin panel escalates to "
                      "admin account takeover."},
        {"check": "Email / export / PDF rendering of the same field",
         "rationale": "The stored value is often re-rendered in emails, exports "
                      "or PDFs where output encoding differs."},
    ],
    "ssrf": [
        {"check": "Internal services via 169.254.x.x and cloud metadata",
         "rationale": "A confirmed DNS callback proves outbound requests; pivot "
                      "to internal / metadata endpoints for real impact."},
        {"check": "SSRF via open redirect",
         "rationale": "URL allowlists are commonly bypassed by chaining an open "
                      "redirect to reach blocked internal hosts."},
    ],
    "s3": [
        {"check": "JS bundles in the bucket -> grep for secrets",
         "rationale": "Readable buckets often expose source / JS bundles with "
                      "hardcoded keys and internal endpoints."},
        {"check": ".env / config files in the bucket",
         "rationale": "Misconfigured buckets frequently leak .env and config "
                      "files containing live credentials."},
    ],
    "oauth": [
        {"check": "CSRF on the OAuth flow (missing / replayed state)",
         "rationale": "No PKCE often coincides with weak state handling, enabling "
                      "login CSRF and account linking attacks."},
        {"check": "Authorization code reuse",
         "rationale": "Without PKCE, an intercepted or replayed auth code may "
                      "still be exchangeable for tokens."},
    ],
    "race": [
        {"check": "Race condition on credits / wallet balance",
         "rationale": "The same non-atomic pattern behind a coupon race usually "
                      "affects other balance operations."},
        {"check": "Race condition on rate limits",
         "rationale": "Rate-limit counters are commonly non-atomic too, allowing "
                      "the limit to be bypassed under concurrency."},
    ],
}

# Generic A->B fallback appended to every plan (and returned alone for unknown
# classes), so a confirmed bug always yields at least one next test.
GENERIC_FOLLOWUP = {
    "check": "Test the same flaw on sibling endpoints + older API versions",
    "rationale": "Generic A->B: the same weakness usually recurs on related "
                 "endpoints and legacy API versions.",
}

# Ordered keyword -> table key. First substring match wins; "oauth" is checked
# before "auth" so it is not swallowed by the "auth" substring.
_KEYWORD_MAP = [
    ("idor", "idor"),
    ("bola", "idor"),
    ("oauth", "oauth"),
    ("auth", "auth"),
    ("bypass", "auth"),
    ("xss", "xss"),
    ("ssrf", "ssrf"),
    ("s3", "s3"),
    ("bucket", "s3"),
    ("race", "race"),
]

# Vuln classes for which sibling endpoints are the highest-value next test.
_ACCESS_CONTROL_KEYS = {"idor", "auth"}


def _normalize_class(vuln_class: str) -> str | None:
    """Map a free-form vuln class/type string to an AB_TABLE key, or None."""
    if not vuln_class:
        return None
    c = str(vuln_class).strip().lower()
    for keyword, key in _KEYWORD_MAP:
        if keyword in c:
            return key
    return None


def _version_family(marker: str) -> str:
    """Family key for a version marker, ignoring the version number (so
    ``/v1/`` and ``/v2/`` share a family, distinct from ``/api/v1/``)."""
    return re.sub(r"v\d+", "v", marker)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def sibling_endpoints(url: str) -> list[str]:
    """Generate sibling URLs for ``url`` per the Sibling Rule.

    Swaps the last path segment for each :data:`SIBLING_SUFFIXES` value and swaps
    any detected version marker for its siblings. Scheme/host/query/fragment are
    preserved. The original URL is excluded and results are deduped. Never raises;
    returns ``[]`` for empty/unparseable input or a URL with no path to work on.
    """
    if not url or not isinstance(url, str):
        return []
    url = url.strip()
    if not url:
        return []
    try:
        parts = urlsplit(url)
    except Exception:
        return []

    path = parts.path
    variant_paths: list[str] = []

    # 1) Sibling suffixes — swap (or, when there is no obvious last segment,
    #    append) the final path segment.
    segs = path.split("/")
    last_idx = None
    for i in range(len(segs) - 1, -1, -1):
        if segs[i] != "":
            last_idx = i
            break
    for suffix in SIBLING_SUFFIXES:
        if last_idx is not None:
            if segs[last_idx] == suffix:
                continue
            new_segs = list(segs)
            new_segs[last_idx] = suffix
            variant_paths.append("/".join(new_segs))
        else:
            base = path if path.endswith("/") else path + "/"
            variant_paths.append(base + suffix)

    # 2) Version markers — swap each detected marker for others in its family.
    for marker in VERSION_MARKERS:
        if marker in path:
            family = _version_family(marker)
            for other in VERSION_MARKERS:
                if other != marker and _version_family(other) == family:
                    variant_paths.append(path.replace(marker, other))

    # Reconstruct, exclude the original, dedupe (order-preserving).
    result: list[str] = []
    for p in variant_paths:
        new_url = urlunsplit((parts.scheme, parts.netloc, p, parts.query, parts.fragment))
        if new_url != url:
            result.append(new_url)
    return _dedupe(result)


def ab_followups(vuln_class: str) -> list[dict]:
    """Return the B and C follow-ups for ``vuln_class`` plus the generic
    fallback. Always non-empty (unknown classes yield just the fallback)."""
    key = _normalize_class(vuln_class)
    followups: list[dict] = []
    if key and key in AB_TABLE:
        followups.extend({"check": f["check"], "rationale": f["rationale"]}
                         for f in AB_TABLE[key])
    followups.append(dict(GENERIC_FOLLOWUP))
    return followups


def chain(finding: dict) -> dict:
    """Build a next-test plan from a confirmed ``finding``.

    ``finding`` supplies ``vuln_class`` (or ``vuln_type``) and ``url`` (or
    ``endpoint``). Returns a dict with the source, sibling tests, A->B follow-ups
    and a flat, deduped, priority-ordered ``ranked_next`` action list. For
    access-control classes siblings rank first; otherwise the A->B checks do.
    Never raises on odd input.
    """
    if not isinstance(finding, dict):
        finding = {}

    vuln_class = str(finding.get("vuln_class") or finding.get("vuln_type") or "").strip()
    url = str(finding.get("url") or finding.get("endpoint") or "").strip()

    try:
        siblings = sibling_endpoints(url) if url else []
    except Exception:
        siblings = []

    followups = ab_followups(vuln_class)
    key = _normalize_class(vuln_class)

    sibling_actions = [f"Test sibling endpoint: {u}" for u in siblings]
    ab_actions = [f["check"] for f in followups]

    if key in _ACCESS_CONTROL_KEYS:
        ranked = _dedupe(sibling_actions + ab_actions)
    else:
        ranked = _dedupe(ab_actions + sibling_actions)

    return {
        "source": {"class": vuln_class, "url": url},
        "sibling_tests": siblings,
        "ab_followups": followups,
        "ranked_next": ranked,
    }


def _print_human(plan: dict) -> None:
    src = plan["source"]
    print(f"\n=== Chain plan: confirmed {src['class'] or '(unknown class)'} ===")
    print(f"  source: {src['url'] or '(no url)'}")

    print(f"\n  A->B follow-ups ({len(plan['ab_followups'])}):")
    for f in plan["ab_followups"]:
        print(f"    - {f['check']}")
        print(f"        why: {f['rationale']}")

    sibs = plan["sibling_tests"]
    print(f"\n  Sibling endpoints to test ({len(sibs)}):")
    if sibs:
        for u in sibs:
            print(f"    - {u}")
    else:
        print("    (none derivable from the given URL)")

    print(f"\n  Ranked next actions ({len(plan['ranked_next'])}):")
    for i, action in enumerate(plan["ranked_next"], 1):
        print(f"    {i:>2}. {action}")
    print()


def _load_finding(path: str) -> dict:
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else {}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Auto-chain the next tests after a confirmed bug (A->B + Sibling Rule)")
    ap.add_argument("--class", dest="vuln_class", default="",
                    help="confirmed vuln class (idor, auth, xss, ssrf, s3, oauth, race, ...)")
    ap.add_argument("--url", default="", help="URL/endpoint of the confirmed finding")
    ap.add_argument("--json", nargs="?", const=True, default=False, metavar="FILE",
                    help="machine-readable JSON output; optionally pass a JSON "
                         "finding file to read the finding from")
    args = ap.parse_args(argv)

    json_output = bool(args.json)
    finding: dict = {"vuln_class": args.vuln_class, "url": args.url}

    # --json FILE: load the finding from a file (and emit JSON).
    if isinstance(args.json, str):
        try:
            finding = _load_finding(args.json)
        except (OSError, ValueError) as e:
            print(f"[-] could not read finding file {args.json!r}: {e}", file=sys.stderr)
            # Fall back to inline args so the tool still produces a plan.
            finding = {"vuln_class": args.vuln_class, "url": args.url}

    try:
        plan = chain(finding)
    except Exception as e:  # chain() should never raise; belt and suspenders.
        print(f"[-] chain failed: {e}", file=sys.stderr)
        return 0

    if json_output:
        print(json.dumps(plan, indent=2))
    else:
        _print_human(plan)
    return 0


if __name__ == "__main__":
    sys.exit(main())
