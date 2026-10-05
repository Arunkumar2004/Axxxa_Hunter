"""Unit tests for the coverage ledger state machine."""
import pytest

from tools.hunter.contract import (
    BLOCKED,
    FOUND,
    IN_PROGRESS,
    NA,
    PENDING,
    TESTED_DEEP,
)
from tools.hunter.ledger import CANONICAL_CLASSES, CoverageLedger


def test_seeded_all_pending_and_not_complete():
    led = CoverageLedger()
    assert len(led.classes()) == len(CANONICAL_CLASSES)
    # Every canonical class starts PENDING.
    for cls in CANONICAL_CLASSES:
        assert led.state(cls) == PENDING
    # A fresh ledger with outstanding classes is not complete.
    assert led.is_complete() is False
    assert set(led.pending()) == set(CANONICAL_CLASSES)


def test_start_moves_to_in_progress():
    led = CoverageLedger()
    led.start("sqli")
    assert led.state("sqli") == IN_PROGRESS
    assert "sqli" in led.pending()


def test_found_and_tested_transitions():
    led = CoverageLedger()
    led.start("xss").found("xss")
    assert led.state("xss") == FOUND
    led.start("ssrf").tested("ssrf")
    assert led.state("ssrf") == TESTED_DEEP
    # Resolved classes drop out of pending.
    assert "xss" not in led.pending()
    assert "ssrf" not in led.pending()


def test_found_beats_tested_no_downgrade():
    led = CoverageLedger()
    led.found("jwt")
    led.tested("jwt")  # a second kit must not erase a real finding
    assert led.state("jwt") == FOUND
    # na/blocked also refuse to override a FOUND class.
    led.na("jwt", "irrelevant")
    led.blocked("jwt", "irrelevant")
    assert led.state("jwt") == FOUND


def test_na_carries_reason():
    led = CoverageLedger()
    led.na("mobile", "no mobile app in scope")
    assert led.state("mobile") == NA
    assert led.reason("mobile") == "no mobile app in scope"


def test_blocked_carries_reason():
    led = CoverageLedger()
    led.blocked("ato", "login wall / OTP — refusing to guess credentials")
    assert led.state("ato") == BLOCKED
    assert led.reason("ato") == "login wall / OTP — refusing to guess credentials"


def test_na_and_blocked_require_a_reason():
    led = CoverageLedger()
    with pytest.raises(ValueError):
        led.na("cors", "")
    with pytest.raises(ValueError):
        led.na("cors", "   ")
    with pytest.raises(ValueError):
        led.blocked("cors", "")


def test_is_complete_only_when_nothing_outstanding():
    led = CoverageLedger(classes=("a", "b", "c", "d"))
    assert led.is_complete() is False
    led.found("a")
    led.tested("b")
    led.na("c", "surface does not expose it")
    assert led.is_complete() is False  # "d" still PENDING
    led.blocked("d", "auth wall")
    assert led.is_complete() is True
    assert led.pending() == []


def test_unknown_class_is_auto_added():
    led = CoverageLedger(classes=("sqli",))
    # A kit may declare a class the ledger was not seeded with; touching it
    # registers it rather than silently dropping it.
    led.start("brand-new-class")
    assert led.state("brand-new-class") == IN_PROGRESS
    assert "brand-new-class" in led.classes()


def test_summary_shape_and_table():
    led = CoverageLedger(classes=("sqli", "xss"))
    led.found("sqli")
    led.na("xss", "no HTML sink reachable")
    summary = led.summary()
    assert isinstance(summary, dict)
    assert summary["total"] == 2
    assert summary["complete"] is True
    assert summary["by_state"][FOUND] == 1
    assert summary["by_state"][NA] == 1
    assert summary["classes"]["sqli"]["state"] == FOUND
    assert summary["classes"]["xss"]["reason"] == "no HTML sink reachable"
    # The printable table is a plain string carrying the class names.
    table = summary["table"]
    assert isinstance(table, str)
    assert "CLASS" in table and "STATE" in table
    assert "sqli" in table and "xss" in table
    assert led.table() == table


def test_by_state_counts_sum_to_total():
    led = CoverageLedger()
    counts = led.by_state()
    assert sum(counts.values()) == len(CANONICAL_CLASSES)
    assert counts[PENDING] == len(CANONICAL_CLASSES)
