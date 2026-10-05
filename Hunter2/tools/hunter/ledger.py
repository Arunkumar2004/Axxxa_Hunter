"""Coverage ledger — the state machine that keeps a hunt honest.

Every reachable vulnerability class is tracked through the lifecycle
``PENDING -> IN_PROGRESS -> {FOUND | TESTED_DEEP | N/A(reason) | BLOCKED(reason)}``.
The point is: no silent skips and nothing "queued" forever. A hunt is complete
only when nothing is still PENDING or IN_PROGRESS.

The state constants are imported from ``tools.hunter.contract`` so the engine,
the kits and this ledger all agree on the vocabulary.
"""
from __future__ import annotations

import os
import sys

# Make the repo root importable so ``from tools.hunter.contract import ...``
# works whether this module is loaded as part of the package or on its own.
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter.contract import (  # noqa: E402
    BLOCKED,
    FOUND,
    IN_PROGRESS,
    LEDGER_STATES,
    NA,
    PENDING,
    TESTED_DEEP,
)

# The canonical class list every hunt is seeded with. Order is preserved in the
# ledger so the printable table always reads the same way.
CANONICAL_CLASSES: tuple = (
    "idor-bola",
    "bfla",
    "sqli",
    "nosqli",
    "ssti",
    "xss",
    "cmdi",
    "xxe",
    "ldap",
    "ssrf",
    "lfi-path-traversal",
    "file-upload",
    "business-logic",
    "race-condition",
    "request-smuggling",
    "cache-poisoning",
    "cors",
    "crlf",
    "host-header",
    "open-redirect",
    "prototype-pollution",
    "deserialization",
    "graphql",
    "websocket-cswsh",
    "clickjacking",
    "hpp",
    "subdomain-takeover",
    "auth-session",
    "jwt",
    "oauth",
    "saml",
    "mfa",
    "ato",
    "cloud",
    "cicd",
    "k8s",
    "dependency-confusion",
    "mobile",
    "web3",
    "llm",
)

# States that mean "still outstanding" — a hunt is not finished while any class
# sits in one of these.
_OUTSTANDING = (PENDING, IN_PROGRESS)


class CoverageLedger:
    """Tracks the state of every vulnerability class during a hunt.

    Seeded with :data:`CANONICAL_CLASSES` (all PENDING). Any class touched that
    was not seeded is added on first use (PENDING), so a kit that declares a
    novel class never makes the ledger lie by omission.
    """

    CANONICAL_CLASSES = CANONICAL_CLASSES

    def __init__(self, classes: "tuple | list | None" = None):
        seed = tuple(classes) if classes is not None else CANONICAL_CLASSES
        self._state: dict[str, str] = {}
        self._reason: dict[str, str] = {}
        self._order: list[str] = []
        for cls in seed:
            if cls not in self._state:
                self._state[cls] = PENDING
                self._order.append(cls)

    # -- internals ----------------------------------------------------------
    def _ensure(self, cls: str) -> None:
        if cls not in self._state:
            self._state[cls] = PENDING
            self._order.append(cls)

    @staticmethod
    def _require_reason(reason: str, where: str) -> str:
        reason = (reason or "").strip()
        if not reason:
            raise ValueError(f"{where} requires a non-empty reason")
        return reason

    # -- transitions --------------------------------------------------------
    def start(self, cls: str) -> "CoverageLedger":
        """Mark a class as being worked on (PENDING -> IN_PROGRESS)."""
        self._ensure(cls)
        if self._state[cls] == PENDING:
            self._state[cls] = IN_PROGRESS
        return self

    def found(self, cls: str) -> "CoverageLedger":
        """Record a confirmed/likely finding for a class. FOUND always wins."""
        self._ensure(cls)
        self._state[cls] = FOUND
        self._reason.pop(cls, None)
        return self

    def tested(self, cls: str) -> "CoverageLedger":
        """Record that a class was tested deeply with nothing to show.

        Does not downgrade a class already marked FOUND (a second kit covering
        the same class must not erase a real finding).
        """
        self._ensure(cls)
        if self._state[cls] != FOUND:
            self._state[cls] = TESTED_DEEP
            self._reason.pop(cls, None)
        return self

    def na(self, cls: str, reason: str) -> "CoverageLedger":
        """Mark a class not applicable to this surface. Reason is mandatory."""
        self._ensure(cls)
        reason = self._require_reason(reason, "na()")
        if self._state[cls] != FOUND:
            self._state[cls] = NA
            self._reason[cls] = reason
        return self

    def blocked(self, cls: str, reason: str) -> "CoverageLedger":
        """Mark a class blocked (auth wall, captcha, OTP, ...). Reason mandatory."""
        self._ensure(cls)
        reason = self._require_reason(reason, "blocked()")
        if self._state[cls] != FOUND:
            self._state[cls] = BLOCKED
            self._reason[cls] = reason
        return self

    # -- queries ------------------------------------------------------------
    def state(self, cls: str) -> "str | None":
        return self._state.get(cls)

    def reason(self, cls: str) -> str:
        return self._reason.get(cls, "")

    def classes(self) -> list:
        return list(self._order)

    def pending(self) -> list:
        """Classes still outstanding (PENDING or IN_PROGRESS), in seed order."""
        return [c for c in self._order if self._state[c] in _OUTSTANDING]

    def in_state(self, state: str) -> list:
        return [c for c in self._order if self._state[c] == state]

    def is_complete(self) -> bool:
        """True only when no class is still PENDING or IN_PROGRESS."""
        return not self.pending()

    def by_state(self) -> dict:
        counts = {s: 0 for s in LEDGER_STATES}
        for s in self._state.values():
            counts[s] = counts.get(s, 0) + 1
        return counts

    # -- output -------------------------------------------------------------
    def table(self) -> str:
        """A plain, aligned, printable table of class -> state (-> reason)."""
        header = ("CLASS", "STATE", "REASON")
        rows = [header]
        for cls in self._order:
            rows.append((cls, self._state[cls], self._reason.get(cls, "")))
        w_cls = max(len(r[0]) for r in rows)
        w_state = max(len(r[1]) for r in rows)
        lines = []
        for i, (a, b, c) in enumerate(rows):
            lines.append(f"{a.ljust(w_cls)}  {b.ljust(w_state)}  {c}".rstrip())
            if i == 0:
                lines.append(f"{'-' * w_cls}  {'-' * w_state}  {'-' * 6}")
        return "\n".join(lines)

    def summary(self) -> dict:
        """A machine-readable summary dict (also carries the printable table)."""
        return {
            "total": len(self._state),
            "by_state": self.by_state(),
            "complete": self.is_complete(),
            "pending": self.pending(),
            "classes": {
                cls: {"state": self._state[cls], "reason": self._reason.get(cls, "")}
                for cls in self._order
            },
            "table": self.table(),
        }

    def __repr__(self) -> str:
        counts = self.by_state()
        parts = ", ".join(f"{s}={counts[s]}" for s in LEDGER_STATES if counts.get(s))
        return f"CoverageLedger({len(self._state)} classes: {parts})"
