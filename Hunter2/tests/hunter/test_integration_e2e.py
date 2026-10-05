"""End-to-end deep test: the whole Hunter Engine against the offline mock target.

This is the proof that the expert loop actually works as a system, not just as
nine isolated units. It drives the REAL engine + REAL kits against the
socket-free :class:`MockApp`, and checks:

* breadth  — the kits, driven by one shared context, find the planted BOLA read,
  the confirmed cross-account WRITE (with auto-revert), reflected XSS, open
  redirect and permissive CORS;
* no false positives — the properly isolated order and the public endpoint are
  NOT flagged;
* orchestration — the engine chains the survivors, the coverage ledger completes
  with no class left PENDING, and no auth token leaks into the report.
"""
import json

import pytest

from tools.hunter import engine
from tools.hunter.contract import (
    Account,
    HuntContext,
    V_CONFIRMED,
)
from tests.hunter.mock_target import MockApp

BASE = "https://mock.test/"
SCOPE = ("mock.test",)

ENDPOINTS = [
    {"method": "GET", "url": "https://mock.test/api/product/1/"},    # BOLA read (A owns)
    {"method": "GET", "url": "https://mock.test/api/order/10/"},     # isolated (B denied)
    {"method": "GET", "url": "https://mock.test/api/profile/500/"},  # write BOLA (A owns)
    {"method": "GET", "url": "https://mock.test/api/report/1000/"},  # report object
    {"method": "GET", "url": "https://mock.test/api/echo?q=hello"},  # reflected XSS
    {"method": "GET", "url": "https://mock.test/api/redirect?next=/home"},  # open redirect
    {"method": "GET", "url": "https://mock.test/api/account/me"},    # permissive CORS
    {"method": "GET", "url": "https://mock.test/api/public/info"},   # public (no bug)
]


def _ctx(mock):
    """A context wired to the mock, with two owned accounts and write enabled."""
    ctx = HuntContext(
        base_url=BASE,
        scope_hosts=SCOPE,
        account_a=Account("A", {"Authorization": "Bearer A"}, "A"),
        account_b=Account("B", {"Authorization": "Bearer B"}, "B"),
        endpoints=[dict(e) for e in ENDPOINTS],
        allow_write=True,
        fetch=mock.fetch,
    )
    return ctx


# --------------------------------------------------------------------------- #
# Breadth: every kit, driven by the engine's context, finds its planted bug.  #
# --------------------------------------------------------------------------- #
def _breadth_findings():
    mock = MockApp()
    ctx = _ctx(mock)
    from tools.hunter import target_model
    target_model.build(ctx)                      # sets ctx.baseline (SPA probe)
    kits = engine.discover_kits()
    out = []
    for kit in kits.values():
        try:
            if kit.applicable(ctx):
                out.extend(kit.run(ctx) or [])
        except Exception as exc:  # a kit must never crash the sweep
            pytest.fail(f"kit {getattr(kit, 'name', '?')} raised: {exc}")
    return out


def test_breadth_covers_the_core_classes():
    findings = _breadth_findings()
    classes = {f.cls for f in findings}
    for expected in ("idor-bola", "xss", "open-redirect", "cors"):
        assert expected in classes, f"expected a {expected} finding; got {sorted(classes)}"


def test_confirmed_cross_account_write_with_revert():
    findings = _breadth_findings()
    writes = [f for f in findings
              if f.cls == "idor-bola" and f.axis == "write" and f.verdict == V_CONFIRMED]
    assert writes, "expected a CONFIRMED cross-account write BOLA finding"
    w = writes[0]
    assert w.evidence.get("reverted") is True, "the write probe must auto-revert its change"
    # severity should reflect a cross-tenant data tamper
    assert w.severity in ("critical", "high")


def test_isolated_and_public_endpoints_are_not_flagged():
    findings = _breadth_findings()
    for f in findings:
        assert "/api/order/" not in f.url, (
            f"the properly isolated order endpoint was wrongly flagged: {f.cls} {f.url}")
        assert "/api/public/info" not in f.url, (
            f"the public endpoint was wrongly flagged: {f.cls} {f.url}")


def test_write_probe_restores_mock_state():
    """After the write axis runs, the mutated profile must be back to its seed."""
    mock = MockApp()
    before = mock.fetch("GET", BASE + "api/profile/500/",
                        headers={"Authorization": "Bearer A"}).body
    ctx = _ctx(mock)
    from tools.hunter import target_model
    target_model.build(ctx)
    for kit in engine.discover_kits().values():
        if getattr(kit, "name", "") == "access-control" and kit.applicable(ctx):
            kit.run(ctx)
    after = mock.fetch("GET", BASE + "api/profile/500/",
                       headers={"Authorization": "Bearer A"}).body
    assert json.loads(before) == json.loads(after), "write axis left the target mutated"


# --------------------------------------------------------------------------- #
# Orchestration: the full engine run.                                          #
# --------------------------------------------------------------------------- #
def test_full_engine_run_chains_validates_and_completes_the_ledger():
    mock = MockApp()
    ctx = _ctx(mock)
    report = engine.run_hunt(ctx)

    assert set(report) >= {"target", "tech", "findings", "chains", "ledger_summary"}

    # The target was understood as an SPA (catch-all shell fingerprinted).
    assert report["tech"].get("is_spa") is True

    # A real access-control finding survived the 7-question gate.
    survivors = {f.cls for f in report["findings"]}
    assert "idor-bola" in survivors, f"no idor-bola survived the gate: {sorted(survivors)}"

    # Survivors were chained into next-step hypotheses.
    assert report["chains"], "expected at least one chain from the surviving findings"

    # The coverage ledger is complete: nothing left PENDING / IN_PROGRESS.
    assert report["ledger_summary"].get("complete") is True, (
        f"ledger not complete: {report['ledger_summary'].get('pending')}")


def test_no_auth_token_leaks_into_the_report():
    mock = MockApp()
    report = engine.run_hunt(_ctx(mock))
    blob = json.dumps(engine._to_jsonable(report))
    assert "Bearer A" not in blob and "Bearer B" not in blob, "an auth token leaked into the report"
