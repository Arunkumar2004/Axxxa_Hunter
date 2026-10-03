import json

import pytest

from tools import coverage_matrix


def test_canonical_registry_reads_matrix():
    classes = coverage_matrix.canonical_classes()
    assert len(classes) >= 35
    assert any(item["id"] == "ssrf" for item in classes)
    assert any("IDOR" in item["name"] for item in classes)


def test_initialize_and_update_persist_atomically(tmp_path, monkeypatch):
    monkeypatch.setattr(coverage_matrix, "STORE", tmp_path)
    matrix = coverage_matrix.initialize("example.com")
    coverage_matrix.save(matrix)
    coverage_matrix.update(
        "example.com",
        "SSRF",
        "TESTED",
        reason="controlled callback probe completed",
        evidence=["findings/example.com/ssrf/callback.txt"],
    )
    loaded = coverage_matrix.load("example.com")
    assert loaded["classes"]["ssrf"]["status"] == "TESTED"
    assert coverage_matrix.summary(loaded)["counts"]["TESTED"] == 1


def test_na_and_blocked_require_reasons(tmp_path, monkeypatch):
    monkeypatch.setattr(coverage_matrix, "STORE", tmp_path)
    coverage_matrix.save(coverage_matrix.initialize("example.com"))
    with pytest.raises(ValueError):
        coverage_matrix.update("example.com", "SSRF", "N/A")
    with pytest.raises(ValueError):
        coverage_matrix.update("example.com", "SSRF", "BLOCKED")


def test_found_status_is_not_downgraded(tmp_path, monkeypatch):
    monkeypatch.setattr(coverage_matrix, "STORE", tmp_path)
    coverage_matrix.save(coverage_matrix.initialize("example.com"))
    coverage_matrix.update("example.com", "SSRF", "FOUND", reason="validated finding")
    coverage_matrix.update("example.com", "SSRF", "N/A", reason="later note")
    assert coverage_matrix.load("example.com")["classes"]["ssrf"]["status"] == "FOUND"
