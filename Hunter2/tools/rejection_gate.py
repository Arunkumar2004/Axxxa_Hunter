#!/usr/bin/env python3
"""
rejection_gate.py — non-interactive auto-kill for invalid findings (Phase 1, Step #4).

Given a finding, decide whether it is on the bug-bounty "always-rejected /
never-submit" list so the toolkit does not waste time writing a report for a
finding that will come back N/A. This is the batch/CI complement to the
interactive ``tools/validate.py`` (which walks a human through the 4 gates).

The canonical rules come from ``skills/triage-validation/SKILL.md`` (the
NEVER SUBMIT list + the "conditionally valid — chain required" table). Each rule
is either:

* never valid (``chain_saver`` is ``None``) — e.g. tabnabbing, missing headers, or
* conditionally valid (``chain_saver`` is a string) — e.g. open redirect, which is
  only worth reporting when chained into an ATO / OAuth-token-theft flow.

Verdicts:

* ``PASSES``      — nothing matched; worth validating / reporting.
* ``REJECTED``    — matched a never-valid rule, is out of scope, or is purely
                    theoretical with no PoC. Do not submit.
* ``NEEDS_CHAIN`` — only matched conditionally-valid rules and no chain was
                    supplied (``has_chain`` is False). Build the chain first.

Usage::

    python3 rejection_gate.py --type "Open redirect" --desc "..."       # human
    python3 rejection_gate.py --type "IDOR" --desc "..." --has-poc      # human
    python3 rejection_gate.py --json finding.json                       # read a finding file
    python3 rejection_gate.py --json --type "Tabnabbing"               # machine-readable output

Exit code: 0 when the finding PASSES, 2 when it is REJECTED or NEEDS_CHAIN.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# ─── Rejection rules ────────────────────────────────────────────────────────────
# Each rule: {"id", "label", "patterns": [regex...], "chain_saver": str | None}.
# Patterns are matched case-insensitively against the finding's concatenated text.
# chain_saver is None when the class is never valid on its own, or a short string
# describing the chain that would make it worth reporting (in which case a finding
# carrying has_chain=True is NOT rejected by that rule).
REJECTION_RULES: list[dict] = [
    {
        "id": "missing_security_headers",
        "label": "Missing CSP/HSTS/security headers (no impact)",
        "patterns": [
            r"missing\s+(the\s+)?(csp|hsts|security\s+header|"
            r"content[-\s]security[-\s]policy|strict[-\s]transport[-\s]security|"
            r"x[-\s]frame[-\s]options|x[-\s]content[-\s]type[-\s]options)",
            r"\b(csp|hsts)\b[^.\n]{0,30}\b(missing|absent|not\s+(set|present|configured|enabled))",
            r"security\s+headers?\s+(are\s+)?(missing|absent|not\s+set)",
            r"\bno\b\s+(csp|hsts|security\s+headers?)\b",
        ],
        "chain_saver": None,
    },
    {
        "id": "missing_email_auth",
        "label": "Missing SPF/DKIM/DMARC records",
        "patterns": [
            r"missing\s+(the\s+)?(spf|dkim|dmarc)",
            r"\b(spf|dkim|dmarc)\b[^.\n]{0,30}\b(record\s+)?(missing|absent|not\s+(set|configured|present))",
            r"\bno\b\s+(spf|dkim|dmarc)\b",
        ],
        "chain_saver": None,
    },
    {
        "id": "graphql_introspection",
        "label": "GraphQL introspection alone (no auth bypass / IDOR demonstrated)",
        "patterns": [
            r"graphql\s+introspection",
            r"introspection\s+(query\s+)?(is\s+)?enabled",
        ],
        "chain_saver": "Chain with an auth-bypass mutation or an IDOR on node() to reach High.",
    },
    {
        "id": "version_disclosure",
        "label": "Banner / version disclosure without a working CVE exploit",
        "patterns": [
            r"banner\s+disclosure",
            r"version\s+disclosure",
            r"\bversion\b[^.\n]{0,30}\b(disclos|leak|expos)",
            r"(server|software)\s+(banner|version)[^.\n]{0,30}\b(disclos|leak|expos)",
        ],
        "chain_saver": "Only valid with a working CVE exploit executed against the disclosed version.",
    },
    {
        "id": "clickjacking",
        "label": "Clickjacking on non-sensitive pages (no sensitive-action PoC)",
        "patterns": [
            r"clickjack",
        ],
        "chain_saver": "Chain with a sensitive action + working framed PoC to reach Medium.",
    },
    {
        "id": "tabnabbing",
        "label": "Tabnabbing (reverse tabnabbing)",
        "patterns": [
            r"tab\s?nabbing",
            r"reverse\s+tabnabbing",
        ],
        "chain_saver": None,
    },
    {
        "id": "csv_injection",
        "label": "CSV injection (no code execution shown)",
        "patterns": [
            r"csv\s+injection",
            r"formula\s+injection",
            r"spreadsheet\s+(formula\s+)?injection",
        ],
        "chain_saver": "Only valid with actual code/command execution demonstrated.",
    },
    {
        "id": "self_xss",
        "label": "Self-XSS (only exploits own account)",
        "patterns": [
            r"self[-\s]?xss",
            r"xss[^.\n]{0,40}\bonly\b[^.\n]{0,20}\bown\s+account",
        ],
        "chain_saver": "Chain with CSRF to trigger it on a victim without their knowledge (Medium).",
    },
    {
        "id": "open_redirect",
        "label": "Open redirect alone (no ATO / OAuth-token-theft chain)",
        "patterns": [
            r"open[-\s_]?redirect",
        ],
        "chain_saver": "Chain into OAuth redirect_uri auth-code/token theft for ATO (Critical).",
    },
    {
        "id": "oauth_client_secret_mobile",
        "label": "OAuth client_secret in mobile app (known/expected)",
        "patterns": [
            r"client[_\s]secret[^.\n]{0,40}\b(mobile|app|apk|android|ios|ipa)\b",
            r"\b(mobile|android|ios|apk|ipa)\b[^.\n]{0,40}client[_\s]secret",
            r"oauth\s+client[_\s]secret",
        ],
        "chain_saver": None,
    },
    {
        "id": "public_api_key",
        "label": "Publishable/public API key (designed to be public - not a secret)",
        "patterns": [
            r"rzp_(live|test)_\w+",                 # Razorpay publishable key id
            r"\bpk_(live|test)_\w+",                # Stripe publishable key
            r"AIza[0-9A-Za-z_\-]{20,}",             # Google Maps browser / Firebase web apiKey
            r"firebase\s+(web\s+)?(config\s+)?api[_\s]?key",
            r"google\s+maps\s+(browser\s+)?(api\s+)?key",
            r"publishable\s+(api\s+)?key",
        ],
        "chain_saver": None,
    },
    {
        "id": "rate_limit_noncritical",
        "label": "Rate limit on non-critical forms (search/contact/login behind Cloudflare)",
        "patterns": [
            r"rate[-\s]?limit(ing)?[^.\n]{0,60}\b(search|contact\s+form|newsletter|sign[-\s]?up|non[-\s]?critical|behind\s+cloudflare)",
            r"\b(search|contact\s+form|newsletter|non[-\s]?critical)\b[^.\n]{0,40}rate[-\s]?limit",
            r"\bno\b\s+rate[-\s]?limit[^.\n]{0,40}\b(search|contact|login|cloudflare)",
        ],
        "chain_saver": None,
    },
    {
        "id": "session_management",
        "label": "Session not invalidated on logout / concurrent sessions",
        "patterns": [
            r"session\s+not\s+invalidated",
            r"not\s+invalidated\s+(up)?on\s+logout",
            r"concurrent\s+sessions?",
            r"logout[^.\n]{0,40}session[^.\n]{0,20}\b(still\s+(valid|active)|not\s+invalidated)",
        ],
        "chain_saver": None,
    },
    {
        "id": "nuclei_info_template",
        "label": "Nuclei info-severity template match (version detection, no CVE PoC)",
        "patterns": [
            r"nuclei[^.\n]{0,30}\binfo\b",
            r"\binfo[-\s]severity\b",
            r"severity\s*[:=]\s*info\b",
            r"template\s+severity[^.\n]{0,20}\binfo\b",
        ],
        "chain_saver": "Only valid with a CVE PoC executed against the live service.",
    },
    {
        "id": "mfa_rate_limit",
        "label": "MFA rate limit with no lockout / no OTP accepted",
        "patterns": [
            r"mfa\s+rate[-\s]?limit",
            r"\b(otp|2fa|mfa)\b[^.\n]{0,30}rate[-\s]?limit",
            r"rate[-\s]?limit[^.\n]{0,30}\b(otp|2fa|mfa)\b",
            r"mfa[^.\n]{0,30}no\s+lockout",
        ],
        "chain_saver": "Only valid if an OTP is actually accepted / the brute force succeeds (Medium/High).",
    },
    {
        "id": "admin_precondition_bypass",
        "label": "Auth bypass requiring the attacker to already be admin",
        "patterns": [
            r"admin\s+can\s+(do|perform|access|act)",
            r"requires?\s+(the\s+)?(attacker\s+)?(to\s+(be|already\s+be)\s+|being\s+)admin",
            r"attacker\s+must\s+(already\s+)?be\s+(an\s+)?admin",
            r"(auth\s+)?bypass[^.\n]{0,40}requires?\s+admin",
            r"already\s+(be\s+)?(an\s+)?admin",
        ],
        "chain_saver": None,
    },
    {
        "id": "out_of_scope",
        "label": "Out-of-scope asset",
        "patterns": [
            r"out[-\s]of[-\s]scope",
            r"not\s+in\s+scope",
        ],
        "chain_saver": None,
    },
]

# Purely-theoretical language — only a rejection when there is no PoC.
THEORETICAL_LANGUAGE = [
    r"could\s+potentially",
    r"may\s+allow",
    r"theoretically",
    r"might\s+be\s+able",
]
_THEORETICAL_RE = re.compile("|".join(THEORETICAL_LANGUAGE), re.IGNORECASE)

# Fields whose text is searched, in priority order.
_TEXT_FIELDS = ("vuln_type", "title", "class", "description", "summary", "impact", "evidence")


def _finding_text(finding: dict) -> str:
    """Concatenate all searchable text fields of a finding into one blob."""
    parts = []
    for key in _TEXT_FIELDS:
        val = finding.get(key)
        if val:
            parts.append(str(val))
    return "\n".join(parts)


def _rule_matches(rule: dict, text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in rule["patterns"])


def check_finding(finding: dict) -> dict:
    """Classify a finding against the never-submit / conditionally-valid rules.

    ``finding`` may contain: vuln_type/title/class, description/summary, impact,
    has_poc (bool), has_chain (bool), in_scope (bool, default True), evidence (str).

    Returns::

        {"verdict": "REJECTED" | "PASSES" | "NEEDS_CHAIN",
         "matched_rules": [ids],
         "reasons": [labels],
         "chain_savers": [str]}
    """
    text = _finding_text(finding)
    has_chain = bool(finding.get("has_chain"))
    has_poc = bool(finding.get("has_poc"))
    in_scope = finding.get("in_scope", True)

    matched_rules: list[str] = []
    reasons: list[str] = []
    chain_savers: list[str] = []
    hard_reject = False          # a never-valid / non-chain-savable rule fired
    needs_chain = False          # only chain-savable rules fired, lacking the chain

    for rule in REJECTION_RULES:
        if not _rule_matches(rule, text):
            continue
        if rule["chain_saver"] and has_chain:
            # A qualifying chain was supplied — this rule no longer rejects it.
            continue
        matched_rules.append(rule["id"])
        reasons.append(rule["label"])
        if rule["chain_saver"]:
            chain_savers.append(rule["chain_saver"])
            needs_chain = True
        else:
            hard_reject = True

    # Out-of-scope flag (independent of any text pattern). Dedupe against the
    # pattern-based out_of_scope rule above.
    if not in_scope:
        if "out_of_scope" not in matched_rules:
            matched_rules.append("out_of_scope")
            reasons.append("Out-of-scope asset")
        hard_reject = True

    # Purely theoretical with no proof-of-concept.
    if not has_poc and _THEORETICAL_RE.search(text):
        matched_rules.append("theoretical_no_poc")
        reasons.append("Purely theoretical impact with no PoC ('could potentially' / 'may allow')")
        hard_reject = True

    if hard_reject:
        verdict = "REJECTED"
    elif needs_chain:
        verdict = "NEEDS_CHAIN"
    else:
        verdict = "PASSES"

    return {
        "verdict": verdict,
        "matched_rules": matched_rules,
        "reasons": reasons,
        "chain_savers": chain_savers,
    }


# ─── CLI ────────────────────────────────────────────────────────────────────────

def _load_finding_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object, got {type(data).__name__}")
    return data


def _finding_from_args(args: argparse.Namespace) -> dict:
    return {
        "vuln_type": args.type or "",
        "description": args.desc or "",
        "impact": args.impact or "",
        "has_poc": bool(args.has_poc),
        "has_chain": bool(args.has_chain),
        "in_scope": bool(args.in_scope),
    }


def _print_human(finding: dict, result: dict) -> None:
    verdict = result["verdict"]
    title = finding.get("vuln_type") or finding.get("title") or finding.get("class") or "(untitled)"
    print(f"\n=== Rejection Gate: {title} ===")
    print(f"  Verdict: {verdict}")
    if result["reasons"]:
        print("  Reasons:")
        for rid, label in zip(result["matched_rules"], result["reasons"]):
            print(f"    - [{rid}] {label}")
    if result["chain_savers"]:
        print("  A qualifying chain would make it valid:")
        for saver in result["chain_savers"]:
            print(f"    -> {saver}")
    if verdict == "PASSES":
        print("  Nothing matched the never-submit list - worth validating / reporting.")
    elif verdict == "NEEDS_CHAIN":
        print("  Not submittable as-is - build and prove the chain first, then re-check.")
    else:
        print("  Do NOT submit - this is on the always-rejected list.")
    print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Auto-kill findings on the bug-bounty never-submit list (non-interactive).",
    )
    ap.add_argument(
        "--json", nargs="?", const="__STDOUT__", default=None, metavar="FILE",
        help="With a path: read the finding from that JSON object file. "
             "Without a value: emit machine-readable JSON output.",
    )
    ap.add_argument("--type", default="", help="vulnerability type / title / class")
    ap.add_argument("--desc", default="", help="description / summary text")
    ap.add_argument("--impact", default="", help="impact text")
    ap.add_argument("--has-poc", dest="has_poc", action="store_true",
                    help="a working proof-of-concept exists")
    ap.add_argument("--has-chain", dest="has_chain", action="store_true",
                    help="a qualifying exploit chain has been built and proven")
    scope = ap.add_mutually_exclusive_group()
    scope.add_argument("--in-scope", dest="in_scope", action="store_true", default=True,
                       help="asset is in scope (default)")
    scope.add_argument("--out-of-scope", dest="in_scope", action="store_false",
                       help="asset is out of scope -> auto-reject")
    args = ap.parse_args(argv)

    json_out = False
    if args.json is not None and args.json != "__STDOUT__":
        # A path was supplied: read the finding from it (and emit JSON).
        try:
            finding = _load_finding_file(args.json)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"[-] {e}", file=sys.stderr)
            return 1
        json_out = True
    else:
        finding = _finding_from_args(args)
        json_out = args.json == "__STDOUT__"

    result = check_finding(finding)

    if json_out:
        print(json.dumps({"finding": finding, **result}, indent=2))
    else:
        _print_human(finding, result)

    return 0 if result["verdict"] == "PASSES" else 2


if __name__ == "__main__":
    sys.exit(main())
