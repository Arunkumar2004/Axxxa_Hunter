"""Tests for tools/recon_diff.py — recon freshness diffing (Rule 12)."""
import os

import pytest

from tools import recon_diff


@pytest.fixture
def recon_root(tmp_path, monkeypatch):
    root = tmp_path / "recon"
    root.mkdir()
    monkeypatch.setattr(recon_diff, "RECON_DIR", str(root))
    return root


def _write(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def test_first_run_flags_no_delta(recon_root):
    d = recon_root / "example.com"
    _write(str(d / "subdomains" / "all.txt"), ["a.example.com", "b.example.com"])
    _write(str(d / "live" / "urls.txt"), ["https://a.example.com/"])

    res = recon_diff.diff_target("example.com")
    assert res["subdomains"]["first_run"] is True
    assert res["subdomains"]["total"] == 2
    # snapshot now exists
    assert os.path.isfile(str(d / ".snapshot" / "subdomains.txt"))


def test_detects_new_items_on_second_run(recon_root):
    d = recon_root / "example.com"
    subs = str(d / "subdomains" / "all.txt")
    _write(subs, ["a.example.com"])
    recon_diff.diff_target("example.com")  # snapshot baseline

    _write(subs, ["a.example.com", "new.example.com", "fresh.example.com"])
    res = recon_diff.diff_target("example.com")

    assert res["subdomains"]["first_run"] is False
    assert res["subdomains"]["new_count"] == 2
    assert set(res["subdomains"]["new"]) == {"new.example.com", "fresh.example.com"}
    # fresh file written for the hunt loop
    fresh = (d / "fresh" / "subdomains.txt").read_text().split()
    assert "new.example.com" in fresh


def test_no_save_leaves_snapshot_untouched(recon_root):
    d = recon_root / "example.com"
    subs = str(d / "subdomains" / "all.txt")
    _write(subs, ["a.example.com"])
    recon_diff.diff_target("example.com")

    _write(subs, ["a.example.com", "x.example.com"])
    res = recon_diff.diff_target("example.com", save=False)
    assert res["subdomains"]["new_count"] == 1
    # snapshot NOT updated, so the next diff still sees x as new
    res2 = recon_diff.diff_target("example.com", save=False)
    assert res2["subdomains"]["new_count"] == 1


def test_missing_recon_dir_raises(recon_root):
    with pytest.raises(FileNotFoundError):
        recon_diff.diff_target("nonexistent.com")


def test_rejects_path_traversal(recon_root):
    with pytest.raises(ValueError):
        recon_diff.diff_target("../etc")
