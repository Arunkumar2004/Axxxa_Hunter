#!/usr/bin/env python3
"""Chain builder for the Hunter Engine.

An expert never stops at bug A: they immediately look for B and C, and they
combine *all* findings - including low/info ones - into higher-impact chains.
This module does both for a list of :class:`Finding` objects:

1. **Per-finding next steps (A->B->C)** - reuses :mod:`tools.chain_engine`
   (``chain()``, which itself composes ``sibling_endpoints`` + ``ab_followups``)
   to turn each finding into concrete sibling tests and A->B follow-ups.
2. **Named single-finding escalations** - e.g. ``ssrf -> cloud-metadata ->
   creds`` or ``open-redirect -> oauth-token-theft`` - the textbook pivots a
   class invites even before a second finding exists.
3. **Cross-finding combos** - pairs two findings into one chain, e.g.
   ``idor + info-leak -> account takeover``.

It is pure and deterministic (no network, no randomness) and never raises on
odd input, so the engine can call it freely as findings accrue.
"""
from __future__ import annotations

import os
import sys

# Importable as ``tools.hunter.chain`` or runnable directly.
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.chain_engine import (  # noqa: E402
    ab_followups,
    chain as ce_chain,
    sibling_endpoints,
)

# --- helpers that tolerate a Finding dataclass OR a plain dict ---------------


def _get(obj, name, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _class_of(f) -> str:
    """The best free-form class string to hand the A->B engine."""
    return str(_get(f, "cls", "") or _get(f, "technique", "") or _get(f, "title", "") or "")


def _blob(f) -> str:
    """Lower-cased concatenation of a finding's class / technique / title / axis
    / chain hints, used for keyword matching in escalations and combos."""
    parts = []
    for k in ("cls", "technique", "title", "axis"):
        v = _get(f, k, "")
        if v:
            parts.append(str(v))
    for hint in (_get(f, "chain_hints", []) or []):
        parts.append(str(hint))
    return " ".join(parts).lower()


def _finding_ref(f) -> dict:
    """A compact, safe reference to a finding (no raw tokens or bodies)."""
    return {
        "cls": _get(f, "cls", ""),
        "title": _get(f, "title", ""),
        "url": _get(f, "url", ""),
        "severity": _get(f, "severity", "info"),
        "confidence": _get(f, "confidence", "tentative"),
        "verdict": _get(f, "verdict", ""),
    }


# --- named single-finding escalations ----------------------------------------
# Each fires when any of its ``keys`` appears in a finding's blob.
_ESCALATIONS = [
    {
        "keys": ("ssrf",),
        "name": "ssrf-to-cloud-metadata-to-creds",
        "impact": "Cloud credential theft via instance metadata",
        "severity": "critical",
        "steps": [
            "Confirm the parameter drives a server-side outbound request (OOB callback).",
            "Point it at 169.254.169.254 / metadata.google.internal.",
            "Read the IAM / instance credentials from the metadata response.",
        ],
    },
    {
        "keys": ("open-redirect", "open_redirect", "open redirect"),
        "name": "open-redirect-to-oauth-token-theft",
        "impact": "Account takeover via a stolen OAuth code/token",
        "severity": "high",
        "steps": [
            "Find an OAuth/SSO flow that trusts a redirect/callback parameter.",
            "Use the open redirect as the redirect_uri to leak the auth code/token.",
            "Exchange the leaked code/token for the victim's session.",
        ],
    },
    {
        "keys": ("idor", "bola"),
        "name": "idor-to-mass-enumeration",
        "impact": "Bulk exposure of other users' objects",
        "severity": "high",
        "steps": [
            "Confirm the cross-account read on a single object id.",
            "Enumerate the id space (sequential / zero-padded / wrapped / siblings).",
            "Quantify how many other tenants' records are reachable.",
        ],
    },
    {
        "keys": ("xss", "cross-site scripting"),
        "name": "stored-xss-to-admin-ato",
        "impact": "Admin account takeover if the payload renders in a staff view",
        "severity": "high",
        "steps": [
            "Confirm the payload is stored and reflected without output encoding.",
            "Identify an admin/staff view that renders the same field.",
            "Land a session-stealing payload in that privileged context.",
        ],
    },
]

# --- cross-finding combos (directional: left finding + right finding) --------
_COMBOS = [
    {
        "name": "idor-plus-info-leak-to-ato",
        "left": ("idor", "bola"),
        "right": ("info", "leak", "disclosure", "pii", "secret", "token"),
        "impact": "Account takeover",
        "severity": "critical",
        "rationale": (
            "A cross-account object read combined with leaked identifiers or "
            "secrets lets an attacker pivot from viewing a victim's data to "
            "taking over the account."
        ),
    },
    {
        "name": "ssrf-plus-open-redirect-to-metadata",
        "left": ("ssrf",),
        "right": ("open-redirect", "open_redirect", "redirect"),
        "impact": "SSRF allow-list bypass into internal / metadata services",
        "severity": "critical",
        "rationale": (
            "An open redirect on an in-scope host defeats an SSRF URL allow-list, "
            "reaching blocked internal and cloud-metadata endpoints."
        ),
    },
    {
        "name": "open-redirect-plus-oauth-to-token-theft",
        "left": ("open-redirect", "open_redirect", "redirect"),
        "right": ("oauth", "sso", "openid"),
        "impact": "OAuth token theft leading to account takeover",
        "severity": "critical",
        "rationale": (
            "An open redirect used as the OAuth redirect_uri exfiltrates the "
            "authorization code/token, yielding account takeover."
        ),
    },
    {
        "name": "info-leak-plus-auth-to-ato",
        "left": ("info", "leak", "disclosure", "pii"),
        "right": ("password reset", "reset", "mfa", "session", "login"),
        "impact": "Account takeover via leaked credentials / reset material",
        "severity": "high",
        "rationale": (
            "Leaked identifiers or reset tokens feed an authentication or "
            "password-reset weakness to take over accounts."
        ),
    },
]


def _escalations_for(blob: str) -> list:
    out = []
    for esc in _ESCALATIONS:
        if any(k in blob for k in esc["keys"]):
            out.append({
                "name": esc["name"],
                "impact": esc["impact"],
                "severity": esc["severity"],
                "steps": list(esc["steps"]),
            })
    return out


def _combo(a, b) -> "dict | None":
    """Return a combo chain dict when finding ``a`` matches a rule's left side
    and finding ``b`` its right side; otherwise ``None``."""
    blob_a, blob_b = _blob(a), _blob(b)
    for rule in _COMBOS:
        if any(k in blob_a for k in rule["left"]) and any(k in blob_b for k in rule["right"]):
            url = _get(a, "url", "") or _get(b, "url", "")
            return {
                "kind": "combo",
                "name": rule["name"],
                "impact": rule["impact"],
                "severity": rule["severity"],
                "rationale": rule["rationale"],
                "sources": [_finding_ref(a), _finding_ref(b)],
                "steps": [
                    f"Confirm finding A: {_get(a, 'title', '') or _get(a, 'cls', '')}",
                    f"Confirm finding B: {_get(b, 'title', '') or _get(b, 'cls', '')}",
                    f"Chain them: {rule['rationale']}",
                ],
                # After chaining A+B, the textbook follow-ups and related
                # endpoints for the primary class are the next things to test.
                "followups": ab_followups(_class_of(a)),
                "related_endpoints": sibling_endpoints(url) if url else [],
            }
    return None


def _next_steps(f) -> dict:
    """Per-finding A->B->C plan, reusing the existing chain engine."""
    plan = ce_chain({"vuln_class": _class_of(f), "url": _get(f, "url", "") or ""})
    return {
        "kind": "next-steps",
        "source": _finding_ref(f),
        "sibling_tests": plan["sibling_tests"],
        "ab_followups": plan["ab_followups"],
        "ranked_next": plan["ranked_next"],
    }


def build_chains(findings: list) -> list:
    """Turn a list of findings into structured chain dicts.

    Low/info findings are included on purpose - they are often the glue of a
    high-impact chain. The returned list mixes three ``kind`` values:

    * ``"next-steps"``  - one per finding: sibling tests + A->B follow-ups.
    * ``"escalation"``  - named single-finding pivots (ssrf->metadata->creds,
      open-redirect->oauth-token-theft, ...).
    * ``"combo"``       - a pair of findings chained into higher impact
      (idor + info-leak -> ATO, ...).
    """
    items = [f for f in (findings or []) if f is not None]
    chains: list = []

    # 1) + 2) per-finding next steps and named escalations.
    for f in items:
        chains.append(_next_steps(f))
        blob = _blob(f)
        ref = _finding_ref(f)
        for esc in _escalations_for(blob):
            chains.append({"kind": "escalation", "source": ref, **esc})

    # 3) cross-finding combos over every ordered pair (rules are directional).
    for i, a in enumerate(items):
        for j, b in enumerate(items):
            if i == j:
                continue
            combo = _combo(a, b)
            if combo is not None:
                chains.append(combo)

    return chains


if __name__ == "__main__":
    # Tiny, side-effect-free demonstration so the module is runnable.
    import json as _json

    demo = [
        {"cls": "idor-bola", "title": "Cross-account product read",
         "url": "https://api.example.com/api/product/2/", "severity": "high"},
        {"cls": "info-leak", "title": "User id + email disclosed in error",
         "severity": "low"},
    ]
    print(_json.dumps(build_chains(demo), indent=2))
