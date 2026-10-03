"""Tests for tools/rejection_gate.py — auto-kill invalid findings (Phase 1, Step #4)."""
import json

import pytest

from tools import rejection_gate
from tools.rejection_gate import check_finding, main

# Verdicts that mean "do not submit this as-is" (CLI exit code 2).
BLOCKED = ("REJECTED", "NEEDS_CHAIN")


def test_razorpay_publishable_key_rejected():
    res = check_finding({
        "vuln_type": "Information disclosure",
        "description": "Found a hardcoded key rzp_live_ABC123def in the bundled JS.",
    })
    assert res["verdict"] == "REJECTED"
    assert "public_api_key" in res["matched_rules"]


def test_missing_security_headers_rejected():
    res = check_finding({
        "vuln_type": "Missing security headers",
        "description": "Response is missing the Content-Security-Policy (CSP) and "
                       "Strict-Transport-Security (HSTS) headers.",
    })
    assert res["verdict"] == "REJECTED"
    assert "missing_security_headers" in res["matched_rules"]


def test_self_xss_no_chain_is_blocked():
    res = check_finding({
        "vuln_type": "Self-XSS",
        "description": "Self-XSS in the display name field; only affects the user's own account.",
    })
    # Standalone self-XSS is on the never-submit list — not submittable as-is.
    assert res["verdict"] in BLOCKED
    assert res["verdict"] != "PASSES"
    assert "self_xss" in res["matched_rules"]


def test_self_xss_with_chain_not_plain_rejected():
    res = check_finding({
        "vuln_type": "Self-XSS",
        "description": "Self-XSS in the display name field, chained with CSRF to fire on a victim.",
        "has_chain": True,
    })
    # A qualifying chain removes the self_xss rejection.
    assert res["verdict"] != "REJECTED"
    assert "self_xss" not in res["matched_rules"]


def test_open_redirect_alone_is_blocked():
    res = check_finding({
        "vuln_type": "Open redirect",
        "description": "Open redirect via the ?next= parameter, no further chain.",
    })
    assert res["verdict"] in BLOCKED
    assert res["verdict"] != "PASSES"
    assert "open_redirect" in res["matched_rules"]


def test_open_redirect_with_chain_not_plain_rejected():
    res = check_finding({
        "vuln_type": "Open redirect",
        "description": "Open redirect on the OAuth redirect_uri leaking the auth code for ATO.",
        "has_chain": True,
    })
    assert res["verdict"] != "REJECTED"
    assert "open_redirect" not in res["matched_rules"]


def test_out_of_scope_rejected():
    res = check_finding({
        "vuln_type": "IDOR",
        "description": "Cross-account read on another user's data.",
        "has_poc": True,
        "in_scope": False,
    })
    assert res["verdict"] == "REJECTED"
    assert "out_of_scope" in res["matched_rules"]


def test_solid_idor_passes():
    res = check_finding({
        "vuln_type": "IDOR",
        "description": "An authenticated attacker can read another user's invoices by "
                       "swapping the numeric id. Confirmed cross-account with two test "
                       "accounts; the response returns the victim's billing details.",
        "impact": "Cross-account read of other users' PII and billing records.",
        "has_poc": True,
        "has_chain": False,
        "in_scope": True,
    })
    assert res["verdict"] == "PASSES"
    assert res["matched_rules"] == []
    assert res["reasons"] == []


def test_theoretical_no_poc_rejected():
    res = check_finding({
        "vuln_type": "Business logic issue",
        "description": "This could potentially allow an attacker to escalate access.",
        "has_poc": False,
    })
    assert res["verdict"] == "REJECTED"
    assert "theoretical_no_poc" in res["matched_rules"]


def test_theoretical_language_ignored_when_poc_present():
    # The same wording must NOT reject when a working PoC exists.
    res = check_finding({
        "vuln_type": "Access control",
        "description": "This could potentially allow escalation — and here is the PoC.",
        "has_poc": True,
    })
    assert "theoretical_no_poc" not in res["matched_rules"]


def test_cli_rejects_razorpay_key(capsys):
    rc = main(["--type", "info disclosure", "--desc", "found rzp_live_abc123 key in JS"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "REJECTED" in out


def test_cli_passes_clean_finding(capsys):
    rc = main(["--type", "IDOR", "--desc", "cross-account read of another user's orders",
               "--has-poc"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PASSES" in out


def test_cli_json_output(capsys):
    rc = main(["--json", "--type", "Tabnabbing", "--desc", "reverse tabnabbing on outbound link"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 2
    assert payload["verdict"] == "REJECTED"
    assert "tabnabbing" in payload["matched_rules"]


def test_cli_reads_json_file(tmp_path, capsys):
    fp = tmp_path / "finding.json"
    fp.write_text(json.dumps({
        "vuln_type": "GraphQL introspection",
        "description": "Introspection query is enabled on /graphql.",
    }), encoding="utf-8")
    rc = main(["--json", str(fp)])
    payload = json.loads(capsys.readouterr().out)
    # Introspection alone is chain-savable -> blocked (exit 2) but not a hard reject.
    assert rc == 2
    assert payload["verdict"] in BLOCKED
    assert "graphql_introspection" in payload["matched_rules"]


def test_rejection_rules_shape():
    assert isinstance(rejection_gate.REJECTION_RULES, list)
    for rule in rejection_gate.REJECTION_RULES:
        assert set(rule) >= {"id", "label", "patterns", "chain_saver"}
        assert isinstance(rule["patterns"], list) and rule["patterns"]
        assert rule["chain_saver"] is None or isinstance(rule["chain_saver"], str)
