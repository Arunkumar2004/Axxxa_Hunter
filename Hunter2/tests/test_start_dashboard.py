"""Tests for tools/start.py — the AXXX HUNTER start dashboard."""
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import start  # noqa: E402


def test_glyphs_cover_banner_letters():
    # every letter in "AXXX HUNTER" must have a glyph so the banner never breaks
    for ch in "AXXX HUNTER":
        assert ch in start._G, f"missing glyph for {ch!r}"


def test_compose_returns_six_rows_equal_width():
    rows = start._compose("AXXX HUNTER")
    assert len(rows) == 6
    # all rows same length (aligned block art)
    assert len({len(r) for r in rows}) == 1
    assert rows[0].strip()  # not blank


class _FakeStream:
    """Stream with a settable .encoding (StringIO's is read-only)."""
    def __init__(self, encoding):
        self.encoding = encoding
        self._parts = []

    def write(self, s):
        self._parts.append(s)
        return len(s)

    def getvalue(self):
        return "".join(self._parts)


def test_banner_writes_utf8_block():
    buf = _FakeStream("utf-8")  # force the block-art path
    start.print_banner("example.com", stream=buf)
    out = buf.getvalue()
    assert "TARGET: example.com" in out
    assert "█" in out  # block art rendered


def test_banner_ascii_fallback_no_unicode():
    buf = _FakeStream("cp1252")  # force the ASCII fallback path
    start.print_banner(None, stream=buf)
    out = buf.getvalue()
    # fallback must be encodable in cp1252 (no block chars)
    out.encode("cp1252")
    assert "HUNTER" in out.replace(" ", "")  # ASCII logo spells it spaced


def test_playwright_ready_returns_tuple():
    ok, hint = start._playwright_ready()
    assert isinstance(ok, bool)
    assert isinstance(hint, str) and hint


def test_main_runs_and_shows_board(capsys):
    rc = start.main(["example.com"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "HUNTER2 PREFLIGHT" in out          # board rendered
    assert "browser MCP" in out                 # browser-login line present
    assert "NEXT:" in out
