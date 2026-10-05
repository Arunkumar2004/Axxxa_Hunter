"""Tests for the Hunter Engine knowledge base (tools/hunter/kb).

The loader reads the hand-authored per-class checklists and serves them as
ordered test steps, bypass techniques and false-positive kill rules. These tests
pin the contract the engine and kits rely on: every advertised class loads, the
three sections are populated and deep enough to be useful, the specific anchors
the engine looks for are present, and unknown classes degrade to empty lists
rather than raising.
"""
from tools.hunter.kb.loader import KnowledgeBase
from tools.hunter.kb import KnowledgeBase as KBFromPackage

# The classes the knowledge base must ship. Kept in the test so a dropped or
# renamed checklist fails loudly.
EXPECTED_CLASSES = {
    "idor-bola", "bfla", "sqli", "nosqli", "ssti", "xss", "cmdi", "xxe",
    "ssrf", "lfi-path-traversal", "file-upload", "business-logic",
    "race-condition", "request-smuggling", "cache-poisoning", "cors", "crlf",
    "host-header", "open-redirect", "prototype-pollution", "deserialization",
    "graphql", "websocket-cswsh", "clickjacking", "jwt", "oauth",
    "auth-session", "mfa", "ato",
}


def _kb():
    return KnowledgeBase()


def test_loader_finds_all_expected_classes():
    found = set(_kb().classes())
    missing = EXPECTED_CLASSES - found
    assert not missing, f"knowledge base is missing classes: {sorted(missing)}"


def test_package_reexports_loader_class():
    # ``from tools.hunter.kb import KnowledgeBase`` must be the loader class.
    assert KBFromPackage is KnowledgeBase


def test_every_class_has_all_three_sections_populated():
    kb = _kb()
    for cls in sorted(EXPECTED_CLASSES):
        assert kb.checklist(cls), f"{cls}: empty checklist"
        assert kb.bypasses(cls), f"{cls}: empty bypasses"
        assert kb.kill_rules(cls), f"{cls}: empty kill rules"


def test_checklists_are_deep_enough_to_be_useful():
    # The brief asks for genuinely deep checklists (8-20 concrete steps).
    kb = _kb()
    for cls in sorted(EXPECTED_CLASSES):
        steps = kb.checklist(cls)
        assert len(steps) >= 8, f"{cls}: only {len(steps)} checklist steps (<8)"


def test_idor_checklist_is_non_empty_and_includes_a_write_or_bola_step():
    kb = _kb()
    steps = kb.checklist("idor-bola")
    assert steps, "idor-bola checklist is empty"
    joined = " ".join(steps).lower()
    assert any(token in joined for token in ("write", "bola", "put", "patch", "delete")), (
        "idor-bola checklist should cover a cross-account write / BOLA step"
    )


def test_ssrf_bypasses_mention_an_ip_encoding_technique():
    kb = _kb()
    joined = " ".join(kb.bypasses("ssrf")).lower()
    assert joined, "ssrf bypasses are empty"
    assert any(token in joined for token in
               ("decimal", "octal", "hex", "2130706433", "ipv6", "dword")), (
        "ssrf bypasses should mention an IP-encoding technique"
    )


def test_missing_class_returns_empty_without_error():
    kb = _kb()
    assert kb.checklist("does-not-exist") == []
    assert kb.bypasses("does-not-exist") == []
    assert kb.kill_rules("does-not-exist") == []
    assert kb.raw("does-not-exist") == ""
    assert kb.has("does-not-exist") is False


def test_lookup_is_case_insensitive():
    kb = _kb()
    assert kb.checklist("IDOR-BOLA") == kb.checklist("idor-bola")


def test_raw_returns_source_with_section_headers():
    kb = _kb()
    raw = kb.raw("idor-bola")
    assert raw, "raw source for idor-bola is empty"
    assert "## Checklist" in raw
    assert "## Bypasses" in raw
    assert "## Kill rules" in raw


def test_accessors_return_fresh_lists_callers_cannot_mutate():
    kb = _kb()
    first = kb.checklist("sqli")
    first.append("tampered")
    assert "tampered" not in kb.checklist("sqli")


def test_every_class_has_kill_rules_for_false_positive_control():
    # Kill rules are what let a kit reject a false positive, so each class needs
    # at least a couple.
    kb = _kb()
    for cls in sorted(EXPECTED_CLASSES):
        assert len(kb.kill_rules(cls)) >= 3, f"{cls}: fewer than 3 kill rules"
