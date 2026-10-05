"""Loader for the Hunter Engine's offline knowledge base.

It reads every ``*.md`` file under ``checklists/`` (one file per vulnerability
class, the file stem is the class slug) and exposes the parsed sections as
ordered lists the engine and kits can reason over. It does no network I/O and
imports only the standard library, so it is safe to load anywhere.

Markdown format (simple and fixed; sections may appear in any order and any may
be absent)::

    # Human Title (class-slug)

    Optional free-text intro. The parser ignores everything that is not a
    recognised section heading followed by ``-`` bullets.

    ## Checklist
    - ordered test step one
    - ordered test step two

    ## Bypasses
    - an evasion / filter-bypass technique

    ## Kill rules
    - a reason to reject the finding as a false positive

Parsing rules:

* The class slug is the file stem, lower-cased (``idor-bola.md`` -> ``idor-bola``).
* Section headings are ``##`` (or deeper) and are matched case-insensitively
  with a few aliases, so "Bypass", "Kill-rules" and "False positives" all work.
* A bullet is any line whose first non-space character is ``-`` or ``*``. A
  leading markdown checkbox (``[ ]``) is stripped; thematic breaks (``---``)
  are ignored.
* Lines inside fenced code blocks (``` ``` ```/``~~~``) are skipped, so a
  bullet-looking line in an example never leaks into a section.
* A missing section yields an empty list; an unknown class yields an empty list
  (and ``raw`` yields ``""``) rather than raising.

CLI::

    python tools/hunter/kb/loader.py --list
    python tools/hunter/kb/loader.py --class idor-bola
    python tools/hunter/kb/loader.py --class ssrf --raw
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Canonical section keys the loader exposes.
CHECKLIST = "checklist"
BYPASSES = "bypasses"
KILL_RULES = "kill_rules"
_SECTIONS = (CHECKLIST, BYPASSES, KILL_RULES)

# Exact heading aliases (compared after normalisation: lower-cased, with ``-``
# and ``_`` turned into spaces and runs of whitespace collapsed).
_HEADING_ALIASES = {
    "checklist": CHECKLIST,
    "checklists": CHECKLIST,
    "test steps": CHECKLIST,
    "test flow": CHECKLIST,
    "steps": CHECKLIST,
    "bypass": BYPASSES,
    "bypasses": BYPASSES,
    "bypass techniques": BYPASSES,
    "evasions": BYPASSES,
    "kill rules": KILL_RULES,
    "kill rule": KILL_RULES,
    "kill": KILL_RULES,
    "false positives": KILL_RULES,
    "false positive": KILL_RULES,
}

# Prefix fallbacks, so "Checklist (ordered)" or "Bypass tricks" still classify.
_HEADING_PREFIXES = (
    ("checklist", CHECKLIST),
    ("test step", CHECKLIST),
    ("test flow", CHECKLIST),
    ("bypass", BYPASSES),
    ("evasion", BYPASSES),
    ("kill", KILL_RULES),
    ("false positive", KILL_RULES),
)

_FENCE_RE = re.compile(r"^(```|~~~)")
_HEADING_RE = re.compile(r"^(#+)\s+(.*)$")
_RULE_RE = re.compile(r"^[-*_ ]{3,}$")
_CHECKBOX_RE = re.compile(r"^\[[ xX]\]\s*")


def _norm_heading(text: str) -> str:
    text = text.strip().lower().replace("_", " ").replace("-", " ")
    return " ".join(text.split())


def _classify_heading(norm: str) -> str | None:
    """Map a normalised ``##`` heading onto a canonical section key, or None."""
    if norm in _HEADING_ALIASES:
        return _HEADING_ALIASES[norm]
    for prefix, key in _HEADING_PREFIXES:
        if norm.startswith(prefix):
            return key
    return None


def _parse(text: str) -> tuple[str, dict[str, list[str]]]:
    """Return ``(title, {section_key: [items]})`` for one checklist document."""
    sections: dict[str, list[str]] = {k: [] for k in _SECTIONS}
    title = ""
    current: str | None = None
    in_fence = False

    for raw_line in text.splitlines():
        stripped = raw_line.strip()

        if _FENCE_RE.match(stripped):
            in_fence = not in_fence
            continue
        if in_fence or not stripped:
            continue

        heading = _HEADING_RE.match(stripped)
        if heading:
            level = len(heading.group(1))
            body = heading.group(2).strip()
            if level == 1:
                if not title:
                    title = body
                current = None  # a top-level heading closes any open section
            else:
                current = _classify_heading(_norm_heading(body))
            continue

        if current is None:
            continue

        # Bullet line within a recognised section.
        if stripped[0] in "-*":
            if _RULE_RE.match(stripped):  # thematic break such as --- / ***
                continue
            item = stripped[1:].strip()
            item = _CHECKBOX_RE.sub("", item).strip()
            if item:
                sections[current].append(item)

    return title, sections


class KnowledgeBase:
    """Loads and serves the per-class checklists.

    Parameters
    ----------
    checklists_dir:
        Directory of ``*.md`` checklist files. Defaults to ``checklists/`` next
        to this module, so the engine can construct it with no arguments.
    """

    def __init__(self, checklists_dir: str | Path | None = None) -> None:
        if checklists_dir is None:
            checklists_dir = Path(__file__).resolve().parent / "checklists"
        self.dir = Path(checklists_dir)
        self._raw: dict[str, str] = {}
        self._title: dict[str, str] = {}
        self._parsed: dict[str, dict[str, list[str]]] = {}
        self._load()

    # -- loading -----------------------------------------------------------
    def _load(self) -> None:
        self._raw.clear()
        self._title.clear()
        self._parsed.clear()
        if not self.dir.is_dir():
            return
        for path in sorted(self.dir.glob("*.md")):
            slug = path.stem.strip().lower()
            if not slug:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            title, sections = _parse(text)
            self._raw[slug] = text
            self._title[slug] = title or slug
            self._parsed[slug] = sections

    def reload(self) -> None:
        """Re-read the directory (useful after checklists are edited)."""
        self._load()

    # -- queries -----------------------------------------------------------
    @staticmethod
    def _key(cls: str) -> str:
        return (cls or "").strip().lower()

    def classes(self) -> list[str]:
        """Every loaded class slug, sorted."""
        return sorted(self._parsed)

    def has(self, cls: str) -> bool:
        return self._key(cls) in self._parsed

    def title(self, cls: str) -> str:
        return self._title.get(self._key(cls), "")

    def checklist(self, cls: str) -> list[str]:
        """Ordered test steps for ``cls`` (``[]`` if unknown/absent)."""
        return list(self._parsed.get(self._key(cls), {}).get(CHECKLIST, []))

    def bypasses(self, cls: str) -> list[str]:
        """Filter/WAF bypass techniques for ``cls`` (``[]`` if unknown/absent)."""
        return list(self._parsed.get(self._key(cls), {}).get(BYPASSES, []))

    def kill_rules(self, cls: str) -> list[str]:
        """False-positive kill rules for ``cls`` (``[]`` if unknown/absent)."""
        return list(self._parsed.get(self._key(cls), {}).get(KILL_RULES, []))

    def section(self, cls: str, name: str) -> list[str]:
        """Generic accessor by section name or alias."""
        key = _classify_heading(_norm_heading(name)) or self._key(name)
        return list(self._parsed.get(self._key(cls), {}).get(key, []))

    def raw(self, cls: str) -> str:
        """The full markdown source for ``cls`` (``""`` if unknown)."""
        return self._raw.get(self._key(cls), "")


# --- CLI --------------------------------------------------------------------
def _configure_stdout() -> None:
    """Make stdout/stderr UTF-8 safe on Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def _emit(text: str = "") -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write((text + "\n").encode("utf-8", "replace"))


def main(argv: list[str] | None = None) -> int:
    _configure_stdout()
    parser = argparse.ArgumentParser(
        prog="kb/loader.py",
        description="Inspect the Hunter Engine's offline vuln-class checklists.",
    )
    parser.add_argument("--list", action="store_true",
                        help="list every checklist class with its section counts")
    parser.add_argument("--class", dest="cls", metavar="SLUG",
                        help="print the checklist, bypasses and kill rules for one class")
    parser.add_argument("--raw", action="store_true",
                        help="with --class, print the raw markdown instead")
    parser.add_argument("--dir", dest="dir", default=None,
                        help="override the checklists directory")
    args = parser.parse_args(argv)

    kb = KnowledgeBase(args.dir)

    if args.cls:
        slug = kb._key(args.cls)
        if not kb.has(slug):
            _emit(f"unknown class: {args.cls}")
            known = kb.classes()
            if known:
                _emit("known classes: " + ", ".join(known))
            return 2
        if args.raw:
            _emit(kb.raw(slug))
            return 0
        _emit(f"# {kb.title(slug)}  [{slug}]")
        for label, items in (
            ("Checklist", kb.checklist(slug)),
            ("Bypasses", kb.bypasses(slug)),
            ("Kill rules", kb.kill_rules(slug)),
        ):
            _emit("")
            _emit(f"## {label} ({len(items)})")
            for i, item in enumerate(items, 1):
                _emit(f"  {i:>2}. {item}")
        return 0

    # Default action (also --list): the catalogue.
    classes = kb.classes()
    _emit(f"{len(classes)} checklist classes in {kb.dir}:")
    for slug in classes:
        counts = (
            f"checklist:{len(kb.checklist(slug)):>2} "
            f"bypasses:{len(kb.bypasses(slug)):>2} "
            f"kill:{len(kb.kill_rules(slug)):>2}"
        )
        _emit(f"  {slug:<22} {counts}  {kb.title(slug)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
