"""Tests for tools/hunt_memory.py — learning memory that compounds across hunts.

Storage is redirected to a tmp_path via the HUNT_OUTCOMES_PATH env override so
these tests never touch real hunt memory.
"""

import json

import pytest

from tools import hunt_memory


@pytest.fixture
def outcomes_path(tmp_path, monkeypatch):
    """Redirect the outcomes store to a temp file for the duration of a test."""
    path = tmp_path / "hunt_outcomes.jsonl"
    monkeypatch.setenv(hunt_memory.OUTCOMES_ENV_VAR, str(path))
    # No BBHUNT_SESSION_ID unless a test opts in — keeps records deterministic.
    monkeypatch.delenv("BBHUNT_SESSION_ID", raising=False)
    return path


def test_record_then_load_round_trip(outcomes_path):
    assert hunt_memory.record_outcome(
        "target.com", "idor", "two-account swap", "worked",
        endpoint_pattern="/api/user/{id}/orders", reason="v2 missing ownership check",
    ) is True

    records = hunt_memory.load_target_memory("target.com")
    assert len(records) == 1
    rec = records[0]
    assert rec["target"] == "target.com"
    assert rec["vuln_class"] == "idor"
    assert rec["technique"] == "two-account swap"
    assert rec["outcome"] == "worked"
    assert rec["endpoint_pattern"] == "/api/user/{id}/orders"
    assert rec["reason"] == "v2 missing ownership check"
    assert rec["schema_version"] == hunt_memory.CURRENT_SCHEMA_VERSION
    assert outcomes_path.exists()


def test_load_class_memory_filters_across_targets(outcomes_path):
    hunt_memory.record_outcome("alpha.com", "idor", "id_swap", "worked")
    hunt_memory.record_outcome("beta.com", "idor", "uuid_bruteforce", "dead_end")
    hunt_memory.record_outcome("beta.com", "ssrf", "dns_rebinding", "rejected")

    idor = hunt_memory.load_class_memory("idor")
    assert len(idor) == 2
    assert {r["target"] for r in idor} == {"alpha.com", "beta.com"}
    assert all(r["vuln_class"] == "idor" for r in idor)

    ssrf = hunt_memory.load_class_memory("ssrf")
    assert len(ssrf) == 1
    assert ssrf[0]["target"] == "beta.com"


def test_summarize_for_hunt_groups_outcomes(outcomes_path):
    hunt_memory.record_outcome("t.com", "idor", "two-account swap", "worked",
                               endpoint_pattern="/api/user/{id}")
    hunt_memory.record_outcome("t.com", "xss", "reflected param", "rejected",
                               reason="WAF blocks angle brackets")
    hunt_memory.record_outcome("t.com", "ssrf", "gopher smuggling", "dead_end",
                               reason="egress firewalled")
    hunt_memory.record_outcome("t.com", "csrf", "token replay", "inconclusive")
    # A different target must not bleed into the summary.
    hunt_memory.record_outcome("other.com", "idor", "id_swap", "worked")

    summary = hunt_memory.summarize_for_hunt("t.com")
    assert set(summary.keys()) == {"worked", "rejected", "dead_ends"}
    assert len(summary["worked"]) == 1
    assert summary["worked"][0]["vuln_class"] == "idor"
    assert summary["worked"][0]["technique"] == "two-account swap"
    assert summary["worked"][0]["endpoint_pattern"] == "/api/user/{id}"
    assert len(summary["rejected"]) == 1
    assert summary["rejected"][0]["reason"] == "WAF blocks angle brackets"
    assert len(summary["dead_ends"]) == 1
    assert summary["dead_ends"][0]["vuln_class"] == "ssrf"
    # inconclusive is intentionally omitted from all three buckets.
    all_techniques = [
        item["technique"]
        for bucket in summary.values()
        for item in bucket
    ]
    assert "token replay" not in all_techniques


def test_invalid_outcome_rejected_no_write(outcomes_path):
    assert hunt_memory.record_outcome(
        "t.com", "idor", "id_swap", "success",  # not a valid outcome
    ) is False
    # Nothing should have been written.
    assert not outcomes_path.exists()
    assert hunt_memory.load_target_memory("t.com") == []


def test_missing_required_fields_rejected(outcomes_path):
    assert hunt_memory.record_outcome("", "idor", "id_swap", "worked") is False
    assert hunt_memory.record_outcome("t.com", "", "id_swap", "worked") is False
    assert hunt_memory.record_outcome("t.com", "idor", "", "worked") is False
    assert not outcomes_path.exists()


def test_no_secrets_only_allowed_keys_persisted(outcomes_path):
    # Even if a caller stuffs a token-like value into a free-text field, the
    # stored record must only ever carry the allowed keys — no blob can widen it.
    token_like = "Bearer eyJhbGciOiJIUzI1NiJ9.aaaa.bbbb password=hunter2 sk_live_ABC"
    assert hunt_memory.record_outcome(
        "t.com", "idor", token_like, "worked", reason=token_like,
    ) is True

    lines = outcomes_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    stored = json.loads(lines[0])
    assert set(stored.keys()) <= hunt_memory.ALLOWED_KEYS
    # Specifically, none of the forbidden field names ever appear.
    for forbidden in ("cookie", "token", "authorization", "password", "body",
                      "request", "response", "headers"):
        assert forbidden not in stored


def test_session_id_recorded_when_authenticated(outcomes_path, monkeypatch):
    monkeypatch.setenv("BBHUNT_SESSION_ID", "abc123def456")
    assert hunt_memory.record_outcome("t.com", "idor", "id_swap", "worked") is True
    rec = hunt_memory.load_target_memory("t.com")[0]
    assert rec["session_id"] == "abc123def456"
    assert set(rec.keys()) <= hunt_memory.ALLOWED_KEYS


def test_load_missing_file_returns_empty(outcomes_path):
    # File never created yet.
    assert not outcomes_path.exists()
    assert hunt_memory.load_target_memory("t.com") == []
    assert hunt_memory.load_class_memory("idor") == []
    assert hunt_memory.summarize_for_hunt("t.com") == {
        "worked": [], "rejected": [], "dead_ends": [],
    }
