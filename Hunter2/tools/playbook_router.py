#!/usr/bin/env python3
"""
Playbook router (Phase 1, Step #1) — auto-load the real-world playbook per lead.

When a hunt classifies a lead to a vuln class, the agent uses this module to
auto-locate the matching playbook in skills/real-world-playbooks/references/<class>.md
and extract its test-flow checklist + rejection rules to inject into context.

Usage:
    python3 playbook_router.py --list                 # available class slugs
    python3 playbook_router.py idor                    # resolve alias -> load & show
    python3 playbook_router.py "server side request forgery" --json

Resolution is best-effort: exact slug, case-insensitive, curated aliases, then a
normalized fuzzy fallback (exact -> startswith -> contains). File reads are guarded
so odd formatting never raises; extractors return empty lists when nothing matches.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# repo root = parent of tools/
REFERENCES_DIR = Path(__file__).resolve().parent.parent / "skills" / "real-world-playbooks" / "references"

# Curated alias/synonym map (canonicalized at load). api-auth fallbacks are defined
# first so the idor-bola group below wins the shared "bola" key.
_RAW_ALIASES: dict[str, str] = {
    # api / mass assignment fallback
    "mass assignment": "api-auth",
    "bopla": "api-auth",
    "bola": "api-auth",
    # idor / bola (takes precedence over the fallback above)
    "idor": "idor-bola",
    "bfla": "idor-bola",
    "broken access control": "idor-bola",
    "insecure direct object": "idor-bola",
    "idor bola": "idor-bola",
    # account takeover
    "ato": "account-takeover",
    "account takeover": "account-takeover",
    # auth / session
    "auth": "auth-session",
    "authentication": "auth-session",
    "session": "auth-session",
    # ssrf
    "ssrf": "ssrf",
    "server side request forgery": "ssrf",
    # rce
    "rce": "rce",
    "remote code execution": "rce",
    # command injection
    "cmd injection": "command-injection",
    "command injection": "command-injection",
    "cmdi": "command-injection",
    # sqli
    "sqli": "sqli",
    "sql injection": "sqli",
    # xss
    "xss": "xss",
    "cross site scripting": "xss",
    # business logic
    "business logic": "business-logic",
    "logic": "business-logic",
    # race condition
    "race": "race-condition",
    "race condition": "race-condition",
    "toctou": "race-condition",
    # misc single-class
    "csrf": "csrf",
    "cors": "cors",
    "xxe": "xxe",
    "ssti": "ssti",
    "jwt": "jwt",
    "oauth": "oauth",
    # saml / sso
    "saml": "saml-sso",
    "sso": "saml-sso",
    # nosqli
    "nosqli": "nosqli",
    "nosql injection": "nosqli",
    # path traversal / lfi
    "lfi": "path-traversal-lfi",
    "path traversal": "path-traversal-lfi",
    "file inclusion": "path-traversal-lfi",
    # open redirect
    "open redirect": "open-redirect",
    # prototype pollution
    "prototype pollution": "prototype-pollution",
    # subdomain takeover
    "subdomain takeover": "subdomain-takeover",
    # file upload
    "file upload": "file-upload",
    # graphql
    "graphql": "graphql",
    # request smuggling
    "request smuggling": "request-smuggling",
    "smuggling": "request-smuggling",
    # web cache
    "cache poisoning": "web-cache",
    "web cache": "web-cache",
    # websocket
    "websocket": "websocket-cswsh",
    "cswsh": "websocket-cswsh",
    # deserialization
    "deserialization": "deserialization",
    "deser": "deserialization",
}


def _canon(text: str) -> str:
    """Canonicalize for alias lookup: lowercase, collapse [\\s_-] to single spaces."""
    return re.sub(r"[\s_\-]+", " ", text.strip().lower()).strip()


# alias table keyed by canonical form
_ALIASES: dict[str, str] = {_canon(k): v for k, v in _RAW_ALIASES.items()}


def list_playbooks() -> list[str]:
    """Sorted list of available class slugs (filenames without .md) present on disk."""
    try:
        return sorted(p.stem for p in REFERENCES_DIR.glob("*.md") if p.is_file())
    except OSError:
        return []


def resolve(vuln_class: str) -> str | None:
    """Map an arbitrary class name/alias to an available playbook slug, or None."""
    if not vuln_class or not str(vuln_class).strip():
        return None

    slugs = list_playbooks()
    slug_set = set(slugs)
    raw = str(vuln_class).strip()

    # 1. exact slug match
    if raw in slug_set:
        return raw

    # 2. case-insensitive slug match
    lower_map = {s.lower(): s for s in slugs}
    if raw.lower() in lower_map:
        return lower_map[raw.lower()]

    # 3. curated alias / synonym match (canonicalized both sides)
    canon = _canon(raw)
    if canon in _ALIASES and _ALIASES[canon] in slug_set:
        return _ALIASES[canon]
    # also try the alias value as a direct slug (alias may already be a slug)
    if canon in _ALIASES and _ALIASES[canon] in lower_map:
        return lower_map[_ALIASES[canon]]

    # 4. normalized fuzzy fallback: lowercase, spaces/underscores -> '-'
    dashed = re.sub(r"[\s_]+", "-", raw.lower()).strip("-")
    if dashed in slug_set:
        return dashed
    if dashed:
        for s in slugs:  # prefer startswith
            if s.startswith(dashed):
                return s
        for s in slugs:  # then contains (either direction)
            if dashed in s or s in dashed:
                return s

    return None


def _is_checklist_line(stripped: str, in_checklist_section: bool) -> bool:
    if not stripped:
        return False
    for marker in ("[ ]", "[]", "[x]", "[X]", "- [ ]", "- [x]", "- [X]", "* "):
        if stripped.startswith(marker):
            return True
    if in_checklist_section:
        if re.match(r"^\d+[.)]\s", stripped):
            return True
        if stripped.startswith("- ") or stripped.startswith("• "):
            return True
    return False


def _extract(content: str) -> tuple[list[str], list[str]]:
    """Best-effort extraction of (checklist, rejection_rules) from playbook text."""
    checklist: list[str] = []
    rejection: list[str] = []

    in_checklist_section = False
    in_rejection_section = False

    for line in content.splitlines():
        stripped = line.strip()

        # heading switches the active section
        if stripped.startswith("#"):
            heading = stripped.lstrip("#").strip().lower()
            in_checklist_section = ("test flow" in heading) or ("checklist" in heading)
            in_rejection_section = any(
                kw in heading for kw in ("reject", "never submit", "not submit", "false positive")
            )
            continue

        if _is_checklist_line(stripped, in_checklist_section):
            checklist.append(stripped)

        low = stripped.lower()
        line_is_reject = ("reject" in low) or ("kill it" in low) or ("do not submit" in low)
        if stripped and (in_rejection_section or line_is_reject):
            # skip code-fence markers inside a rejection section
            if not stripped.startswith("```"):
                rejection.append(stripped)

    # dedupe, preserve order
    def _dedupe(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for it in items:
            if it not in seen:
                seen.add(it)
                out.append(it)
        return out

    return _dedupe(checklist), _dedupe(rejection)


def load_playbook(vuln_class: str) -> dict | None:
    """Resolve then read the playbook file.

    Returns {"slug", "path", "content", "checklist", "rejection_rules"} or None
    if the class cannot be resolved or the file is missing/unreadable.
    """
    slug = resolve(vuln_class)
    if not slug:
        return None
    path = REFERENCES_DIR / f"{slug}.md"
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    checklist, rejection = _extract(content)
    return {
        "slug": slug,
        "path": str(path),
        "content": content,
        "checklist": checklist,
        "rejection_rules": rejection,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Auto-load the real-world playbook for a vuln class")
    ap.add_argument("vuln_class", nargs="?", help="class name or alias (e.g. idor, ssrf, 'account takeover')")
    ap.add_argument("--list", action="store_true", help="list available class slugs")
    ap.add_argument("--json", action="store_true", help="print the load_playbook dict as JSON")
    args = ap.parse_args(argv)

    if args.list:
        for slug in list_playbooks():
            print(slug)
        return 0

    if not args.vuln_class:
        ap.print_help()
        return 1

    pb = load_playbook(args.vuln_class)
    if pb is None:
        print(f"[-] no playbook resolved for {args.vuln_class!r}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(pb, indent=2))
        return 0

    print(f"slug: {pb['slug']}")
    print(f"path: {pb['path']}")
    print(f"\nchecklist (first 10 of {len(pb['checklist'])}):")
    for item in pb["checklist"][:10]:
        print(f"  {item}")
    print(f"\nrejection rules ({len(pb['rejection_rules'])}):")
    for item in pb["rejection_rules"]:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
