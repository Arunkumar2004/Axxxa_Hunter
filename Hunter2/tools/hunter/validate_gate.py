#!/usr/bin/env python3
"""The 7-Question validity gate for Hunter Engine findings.

Before anything is reported, every finding is run through seven deterministic
questions - the same discipline the interactive ``tools/validate.py`` walks a
human through, distilled into pure code so the engine can apply it in batch:

1. **reachable_now**        - is the endpoint live right now (not a 404 / not
                              the SPA catch-all shell)?
2. **real_impact**          - is there demonstrated impact (not bare info)?
3. **reproducible**         - repro steps or confirming evidence present?
4. **auth_boundary_crossed**- for access-control classes, did a non-owner
                              actually get in (not an ISOLATED hold)?
5. **not_public_by_design** - is it NOT a public/unauthenticated resource and
                              NOT on the never-submit list? (reuses
                              ``tools.rejection_gate.check_finding``)
6. **evidence_present**     - is any evidence attached at all?
7. **severity_justified**   - does the claimed severity match the confidence /
                              verdict?

:func:`gate` scores one finding; :func:`apply` splits a list into ``(kept,
killed)``, attaching the failed questions as ``kill_reasons`` on the killed
ones. Pure and deterministic: no network, no randomness.
"""
from __future__ import annotations

import os
import sys

# Importable as ``tools.hunter.validate_gate`` or runnable directly.
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter.contract import (  # noqa: E402
    SEVERITIES,
    V_CONFIRMED,
    V_FORBIDDEN,
    V_INCONCLUSIVE,
    V_ISOLATED,
    V_NOT_FOUND,
    V_POSSIBLE,
    V_PUBLIC,
)
from tools.rejection_gate import check_finding as _rejection_check  # noqa: E402

# Reuse tools/validate.py's auth-class detector when available (it powers that
# tool's required cross-account identity check); fall back to a local keyword
# set so this module never hard-depends on a private name.
try:  # pragma: no cover - import guard
    from tools.validate import _is_auth_related as _validate_is_auth_related
except Exception:  # noqa: BLE001
    _validate_is_auth_related = None

_ACCESS_KEYWORDS = (
    "idor", "bola", "bfla", "access", "privilege", "authz", "ownership",
    "auth-bypass", "takeover", "ato",
)

# A verdict that already says "not a bug" caps the defensible severity at info.
_NON_BUG_VERDICTS = (V_ISOLATED, V_PUBLIC, V_NOT_FOUND, V_FORBIDDEN)

# Highest severity each confidence level can justify on its own.
_CONFIDENCE_CAP = {"confirmed": "critical", "firm": "high", "tentative": "medium"}


def _get(obj, name, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _sev_rank(sev: str) -> int:
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 0


def _evidence(f) -> dict:
    ev = _get(f, "evidence", {}) or {}
    return ev if isinstance(ev, dict) else {}


def _is_access_class(f) -> bool:
    blob = " ".join(
        str(_get(f, k, "") or "") for k in ("cls", "title", "technique", "axis")
    ).lower()
    if _validate_is_auth_related is not None:
        try:
            if _validate_is_auth_related(blob):
                return True
        except Exception:  # noqa: BLE001
            pass
    return any(k in blob for k in _ACCESS_KEYWORDS)


# --- the seven questions. Each returns (passed: bool, reason_if_failed: str) --


def _q_reachable_now(f):
    verdict = _get(f, "verdict", V_INCONCLUSIVE)
    ev = _evidence(f)
    if verdict == V_NOT_FOUND:
        return False, "endpoint did not exist (verdict NOT_FOUND)"
    if ev.get("catchall") is True:
        return False, "response was the SPA catch-all shell, not a live endpoint"
    if ev.get("unreachable") is True:
        return False, "endpoint was unreachable at test time"
    return True, ""


def _q_real_impact(f):
    sev = _get(f, "severity", "info") or "info"
    verdict = _get(f, "verdict", V_INCONCLUSIVE)
    if sev == "info" and verdict != V_CONFIRMED:
        return False, "no demonstrated impact (info severity, not confirmed)"
    return True, ""


def _q_reproducible(f):
    ev = _evidence(f)
    verdict = _get(f, "verdict", V_INCONCLUSIVE)
    if ev.get("flaky") is True or ev.get("reproducible") is False:
        return False, "not reproducible (flaky / timing-dependent)"
    if _get(f, "repro", []) or verdict in (V_CONFIRMED, V_POSSIBLE) or ev.get("reproducible") is True:
        return True, ""
    return False, "no reproduction steps or confirming evidence"


def _q_auth_boundary_crossed(f):
    if not _is_access_class(f):
        return True, ""  # N/A for non-access classes
    verdict = _get(f, "verdict", V_INCONCLUSIVE)
    ev = _evidence(f)
    if verdict == V_ISOLATED:
        return False, "access control held (verdict ISOLATED) - boundary not crossed"
    if ev.get("cross_account") is False or ev.get("b_sees_a") is False:
        return False, "cross-account access did not succeed - boundary held"
    b_status = ev.get("b_status")
    if b_status in (401, 403) and not ev.get("b_sees_a"):
        return False, f"non-owner request was rejected (status {b_status}) - boundary held"
    if verdict == V_CONFIRMED or ev.get("b_sees_a") is True or ev.get("cross_account") is True:
        return True, ""
    return False, "no evidence the auth boundary was actually crossed"


def _q_not_public_by_design(f):
    verdict = _get(f, "verdict", V_INCONCLUSIVE)
    if verdict == V_PUBLIC:
        return False, "resource is public / unauthenticated - not an auth bug"
    ev = _evidence(f)
    if ev.get("anon_status") == 200 and (ev.get("anon_sees") or ev.get("public")):
        return False, "anonymous access already returns the resource - public, not a bug"
    rej = _rejection_check({
        "vuln_type": _get(f, "cls", "") or "",
        "title": _get(f, "title", "") or "",
        "description": " ".join(str(_get(f, k, "") or "") for k in ("technique", "axis")),
        "impact": str(ev.get("impact", "")),
        "evidence": str(ev.get("snippet", "") or ev.get("note", "")),
        "has_poc": bool(_get(f, "repro", [])) or verdict == V_CONFIRMED,
        "has_chain": bool(_get(f, "chain_hints", [])),
        "in_scope": ev.get("in_scope", True),
    })
    if rej.get("verdict") == "REJECTED":
        reason = "; ".join(rej.get("reasons", [])) or "on the never-submit list"
        return False, f"by-design / never-valid: {reason}"
    return True, ""


def _q_evidence_present(f):
    if _evidence(f) or _get(f, "repro", []):
        return True, ""
    return False, "no evidence captured"


def _q_severity_justified(f):
    sev = _get(f, "severity", "info") or "info"
    if sev not in SEVERITIES:
        return False, f"severity '{sev}' is not a recognised level"
    conf = _get(f, "confidence", "tentative") or "tentative"
    verdict = _get(f, "verdict", V_INCONCLUSIVE)
    cap = "info" if verdict in _NON_BUG_VERDICTS else _CONFIDENCE_CAP.get(conf, "medium")
    if _sev_rank(sev) > _sev_rank(cap):
        return False, (f"claimed severity '{sev}' exceeds what confidence '{conf}' / "
                       f"verdict '{verdict}' supports (max '{cap}')")
    return True, ""


_QUESTIONS = (
    ("reachable_now", _q_reachable_now),
    ("real_impact", _q_real_impact),
    ("reproducible", _q_reproducible),
    ("auth_boundary_crossed", _q_auth_boundary_crossed),
    ("not_public_by_design", _q_not_public_by_design),
    ("evidence_present", _q_evidence_present),
    ("severity_justified", _q_severity_justified),
)


def gate(finding) -> dict:
    """Run the 7-question gate over one finding.

    Returns ``{"passed", "questions", "kill_reasons", "verdict"}``. ``passed``
    is True only when all seven questions pass; ``kill_reasons`` lists the
    "<question>: <reason>" of each failure.
    """
    questions: dict = {}
    kill_reasons: list = []
    for key, fn in _QUESTIONS:
        try:
            ok, reason = fn(finding)
        except Exception as exc:  # noqa: BLE001 - a gate must never raise
            ok, reason = False, f"gate error: {exc}"
        questions[key] = {"passed": bool(ok), "reason": reason}
        if not ok:
            kill_reasons.append(f"{key}: {reason}")
    return {
        "passed": all(q["passed"] for q in questions.values()),
        "questions": questions,
        "kill_reasons": kill_reasons,
        "verdict": _get(finding, "verdict", V_INCONCLUSIVE),
    }


def apply(findings) -> tuple:
    """Split ``findings`` into ``(kept, killed)``.

    A finding passing all seven questions is kept unchanged. A failing one is
    moved to ``killed`` with the gate's reasons merged into its ``kill_reasons``
    (de-duplicated, existing reasons preserved).
    """
    kept: list = []
    killed: list = []
    for f in (findings or []):
        if f is None:
            continue
        result = gate(f)
        if result["passed"]:
            kept.append(f)
            continue
        merged = list(_get(f, "kill_reasons", []) or [])
        for reason in result["kill_reasons"]:
            if reason not in merged:
                merged.append(reason)
        if isinstance(f, dict):
            f["kill_reasons"] = merged
        else:
            try:
                f.kill_reasons = merged
            except Exception:  # noqa: BLE001 - frozen/odd objects: keep going
                pass
        killed.append(f)
    return kept, killed


if __name__ == "__main__":
    import json as _json

    demo = {
        "cls": "idor-bola", "title": "Cross-account product read",
        "severity": "high", "confidence": "confirmed", "verdict": V_CONFIRMED,
        "axis": "read", "evidence": {"b_sees_a": True, "anon_status": 403},
        "repro": ["Login as A", "GET /api/product/2/ with A's token"],
    }
    print(_json.dumps(gate(demo), indent=2))
