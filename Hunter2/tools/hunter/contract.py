"""Shared contract for the Hunter Engine and its depth kits.

EVERY kit and the engine import their shared types from THIS module only (plus
the existing tools/ they reuse). Pinning the interface here is what lets the
kits be built in parallel and still interoperate.

Nothing in here does network I/O. Kits receive a ``HuntContext`` and must make
every request through ``ctx.fetch`` (an injected, SSRF-safe, mockable fetcher),
so the whole engine is unit-testable offline against a fake target.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, runtime_checkable

# --- vocabularies -----------------------------------------------------------
SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCE = ("tentative", "firm", "confirmed")

# Coverage-ledger states. A hunt is NOT done while any reachable class is
# PENDING or IN_PROGRESS. "N/A" and "BLOCKED" must always carry a reason.
PENDING = "PENDING"
IN_PROGRESS = "IN_PROGRESS"
FOUND = "FOUND"
TESTED_DEEP = "TESTED_DEEP"
NA = "N/A"
BLOCKED = "BLOCKED"
LEDGER_STATES = (PENDING, IN_PROGRESS, FOUND, TESTED_DEEP, NA, BLOCKED)

# Verdicts a kit may assign to a probe result.
V_CONFIRMED = "CONFIRMED"
V_POSSIBLE = "POSSIBLE"
V_ISOLATED = "ISOLATED"      # access control held — not a bug
V_PUBLIC = "PUBLIC"          # unauthenticated resource — not a bug
V_NOT_FOUND = "NOT_FOUND"
V_FORBIDDEN = "FORBIDDEN"
V_INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class Resp:
    """One HTTP response, as the kits reason over it."""
    status: int
    body: str = ""
    headers: dict = field(default_factory=dict)
    elapsed_ms: float = 0.0

    def header(self, name: str) -> Optional[str]:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return None


# Fetch(method, url, headers=None, body=None) -> Resp | None
# Returning None means a network/DNS error (a dead host must never abort a run).
# ``body`` may be a dict (sent as JSON) or a str. Implementations MUST be
# SSRF-safe (the default one wraps tools/safe_http.safe_urlopen).
Fetch = Callable[..., Optional[Resp]]


@dataclass
class Account:
    """One authenticated identity the operator owns (A or B)."""
    name: str
    headers: dict = field(default_factory=dict)   # bearer/cookie auth headers
    user_id: str = ""

    def __bool__(self) -> bool:
        return bool(self.headers)


@dataclass
class HuntContext:
    """Everything a kit needs. Kits read it; only the engine writes it."""
    base_url: str = ""
    scope_hosts: tuple = ()                 # in-scope hostnames (safety gate)
    account_a: Account = field(default_factory=lambda: Account("A"))
    account_b: Account = field(default_factory=lambda: Account("B"))
    endpoints: list = field(default_factory=list)   # [{"method","url",...}]
    tech: dict = field(default_factory=dict)         # target model (see target_model.py)
    allow_write: bool = False               # gate for state-changing probes
    timeout: int = 15
    rate_limit_s: float = 0.3
    baseline: object = None                 # spa_baseline.Baseline or None
    kb: object = None                       # KnowledgeBase or None
    fetch: Optional[Fetch] = None           # INJECTED — kits must use this
    notes: list = field(default_factory=list)

    def in_scope(self, host: str) -> bool:
        if not self.scope_hosts:
            return True
        host = (host or "").lower().rstrip(".")
        return any(host == h or host.endswith("." + h)
                   for h in (s.lower().lstrip("*.") for s in self.scope_hosts))


@dataclass
class Finding:
    """A structured finding. ``kill_reasons`` feed the validation gate; empty
    kill_reasons + confidence 'confirmed' is report-ready."""
    cls: str                                # vuln class slug, e.g. "idor-bola"
    title: str
    severity: str = "info"
    confidence: str = "tentative"
    axis: str = ""                          # read / write / bfla / idmut / ...
    technique: str = ""
    method: str = "GET"
    url: str = ""
    evidence: dict = field(default_factory=dict)   # statuses, lens, snippet, reverted
    verdict: str = V_INCONCLUSIVE
    repro: list = field(default_factory=list)      # ordered human repro steps
    kill_reasons: list = field(default_factory=list)
    chain_hints: list = field(default_factory=list)


@runtime_checkable
class Kit(Protocol):
    """A depth kit for one family of classes. ``applicable`` decides from the
    target model whether the surface warrants it (match class to surface);
    ``run`` performs the deep, many-technique test and returns findings."""
    name: str
    classes: tuple

    def applicable(self, ctx: HuntContext) -> bool: ...
    def run(self, ctx: HuntContext) -> list: ...


# --- kit registry (self-registration; engine discovers modules by scan) -----
_REGISTRY: "dict[str, Kit]" = {}


def register(kit: "Kit") -> "Kit":
    """Register a kit instance. Idempotent on name."""
    _REGISTRY[kit.name] = kit
    return kit


def registry() -> "dict[str, Kit]":
    return dict(_REGISTRY)
