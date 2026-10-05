"""Hunter knowledge base: offline per-class checklists and their loader.

The knowledge base is pure DATA. It carries the hand-authored test checklists,
bypass techniques and false-positive kill rules for each vulnerability class the
engine knows about, so a kit can ask "how do I test this class deeply, and when
should I throw a result away?" without reaching for a model or the network.

The text under ``checklists/`` is reference methodology (OWASP WSTG, PortSwigger
topics, PayloadsAllTheThings-style technique lists) rewritten in our own words.
It is consumed as data, never executed and never treated as instructions.
"""
from __future__ import annotations

from .loader import KnowledgeBase

__all__ = ["KnowledgeBase"]
