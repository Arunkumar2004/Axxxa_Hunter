"""Tests for tools/playbook_router.py — auto-load playbook per lead (Phase 1 #1)."""
import pytest

from tools import playbook_router


def test_list_playbooks_nonempty_and_known_slugs():
    slugs = playbook_router.list_playbooks()
    assert isinstance(slugs, list)
    assert len(slugs) > 0
    for expected in ("idor-bola", "ssrf", "xss"):
        assert expected in slugs
    # sorted output
    assert slugs == sorted(slugs)


def test_resolve_exact_slug():
    assert playbook_router.resolve("idor-bola") == "idor-bola"
    assert playbook_router.resolve("ssrf") == "ssrf"


def test_resolve_case_insensitive():
    assert playbook_router.resolve("IDOR-BOLA") == "idor-bola"
    assert playbook_router.resolve("SSRF") == "ssrf"


@pytest.mark.parametrize(
    "alias,expected",
    [
        ("IDOR", "idor-bola"),
        ("account takeover", "account-takeover"),
        ("server side request forgery", "ssrf"),
        ("command injection", "command-injection"),
        ("race condition", "race-condition"),
    ],
)
def test_resolve_aliases(alias, expected):
    assert playbook_router.resolve(alias) == expected


def test_resolve_unknown_returns_none():
    assert playbook_router.resolve("totally-not-a-real-vuln-xyz") is None
    assert playbook_router.resolve("") is None


def test_load_playbook_idor():
    pb = playbook_router.load_playbook("idor-bola")
    assert pb is not None
    assert pb["slug"] == "idor-bola"
    assert pb["content"]
    assert pb["path"].endswith("idor-bola.md")
    assert isinstance(pb["checklist"], list)
    assert isinstance(pb["rejection_rules"], list)
    # idor-bola has many "[ ]" checklist items
    assert len(pb["checklist"]) > 0


def test_load_playbook_via_alias():
    pb = playbook_router.load_playbook("idor")
    assert pb is not None
    assert pb["slug"] == "idor-bola"


def test_load_playbook_missing_returns_none():
    assert playbook_router.load_playbook("nonexistent-xyz") is None
