"""Unit tests for the Hunter Engine driver.

The engine is exercised offline: a dummy kit is injected (or registered) and a
fake ``fetch`` returns :class:`Resp` objects, so ``run_hunt`` runs end-to-end
with no network and no sibling harness modules present.
"""
import pytest

import tools.hunter.contract as contract
from tools.hunter import engine
from tools.hunter.contract import FOUND, NA, TESTED_DEEP, Finding, HuntContext, Resp


@pytest.fixture(autouse=True)
def _clean_registry():
    """Keep the shared kit registry isolated between tests."""
    saved = dict(contract._REGISTRY)
    try:
        yield
    finally:
        contract._REGISTRY.clear()
        contract._REGISTRY.update(saved)


class DummyKit:
    def __init__(self, name="dummy", classes=("idor-bola", "xss"), findings=None):
        self.name = name
        self.classes = classes
        self._findings = list(findings or [])

    def applicable(self, ctx):
        return True

    def run(self, ctx):
        return list(self._findings)


def _fake_fetch(method, url, headers=None, body=None):
    # Minimal JSON responder — enough for target_model.build to run offline.
    return Resp(200, '{"ok":true}', {"Content-Type": "application/json", "Server": "nginx"})


# --------------------------------------------------------------------------- #
# run_hunt                                                                    #
# --------------------------------------------------------------------------- #
def test_run_hunt_returns_report_and_reflects_kit_classes():
    # A solid, report-ready finding (survives the 7-question gate when
    # validate_gate is present, and passes straight through when it is absent).
    finding = Finding(
        cls="idor-bola",
        title="Cross-account order read",
        severity="high",
        confidence="confirmed",
        verdict="CONFIRMED",
        axis="read",
        evidence={"b_sees_a": True, "anon_status": 403, "snippet": "order #1001"},
        repro=["Login as A", "GET /api/orders/1001 with B's token returns A's order"],
    )
    dummy = DummyKit(name="dummy", classes=("idor-bola", "xss"), findings=[finding])
    ctx = HuntContext(base_url="https://api.target.test/", fetch=_fake_fetch)

    report = engine.run_hunt(ctx, kits={dummy.name: dummy})

    # Report shape is exactly the contracted keys.
    assert set(report) == {"target", "tech", "findings", "chains", "ledger_summary"}
    assert report["target"] == "https://api.target.test/"
    assert isinstance(report["tech"], dict)

    # The dummy kit's finding flows through to the report. The validate gate
    # only ever removes findings, never invents them, so anything present must
    # be one of the kit's own.
    assert isinstance(report["findings"], list)
    assert {f.cls for f in report["findings"]} <= {"idor-bola"}
    assert any(f.cls == "idor-bola" for f in report["findings"])

    # Ledger reflects the dummy kit's classes: one FOUND, one TESTED_DEEP.
    classes = report["ledger_summary"]["classes"]
    assert classes["idor-bola"]["state"] == FOUND
    assert classes["xss"]["state"] == TESTED_DEEP

    # Classes no kit covers are resolved N/A with a reason (no silent skips),
    # so the whole hunt comes out complete.
    assert classes["ssrf"]["state"] == NA
    assert classes["ssrf"]["reason"]
    assert report["ledger_summary"]["complete"] is True


def test_run_hunt_inapplicable_kit_leaves_classes_na():
    class _Inapplicable(DummyKit):
        def applicable(self, ctx):
            return False

    kit = _Inapplicable(name="skip", classes=("sqli",))
    ctx = HuntContext(base_url="https://api.target.test/", fetch=_fake_fetch)
    report = engine.run_hunt(ctx, kits={kit.name: kit})

    sqli = report["ledger_summary"]["classes"]["sqli"]
    assert sqli["state"] == NA
    assert "not applicable" in sqli["reason"]
    assert report["findings"] == []


def test_run_hunt_survives_a_crashing_kit():
    class _Boom(DummyKit):
        def run(self, ctx):
            raise RuntimeError("kit blew up")

    kit = _Boom(name="boom", classes=("cmdi",))
    ctx = HuntContext(base_url="https://api.target.test/", fetch=_fake_fetch)
    report = engine.run_hunt(ctx, kits={kit.name: kit})

    # A kit that raises is marked BLOCKED, not fatal to the run.
    assert report["ledger_summary"]["classes"]["cmdi"]["state"] == "BLOCKED"
    assert report["chains"] == []  # chain.py absent -> degrades to []


def test_run_hunt_discovers_kits_when_none_passed():
    # No kit files exist yet, but a registered kit still shows up via the
    # registry that discover_kits() returns.
    contract.register(DummyKit(name="reg", classes=("cors",)))
    ctx = HuntContext(base_url="https://api.target.test/", fetch=_fake_fetch)
    report = engine.run_hunt(ctx)
    assert report["ledger_summary"]["classes"]["cors"]["state"] in (FOUND, TESTED_DEEP)


# --------------------------------------------------------------------------- #
# discover_kits                                                               #
# --------------------------------------------------------------------------- #
def test_discover_kits_returns_registry_including_registered():
    kit = DummyKit(name="reg-dummy", classes=("graphql",))
    contract.register(kit)
    found = engine.discover_kits()
    assert isinstance(found, dict)
    assert "reg-dummy" in found
    assert found["reg-dummy"] is kit


_GOOD_KIT = (
    "from tools.hunter.contract import register\n"
    "class _G:\n"
    "    name = 'tmp_good'\n"
    "    classes = ('xss',)\n"
    "    def applicable(self, ctx):\n"
    "        return True\n"
    "    def run(self, ctx):\n"
    "        return []\n"
    "register(_G())\n"
)
_BROKEN_KIT = "import a_module_that_does_not_exist_zzzz  # noqa\n"


def test_discover_kits_skips_broken_and_underscore(tmp_path):
    (tmp_path / "good_kit.py").write_text(_GOOD_KIT, encoding="utf-8")
    (tmp_path / "broken_kit.py").write_text(_BROKEN_KIT, encoding="utf-8")
    (tmp_path / "_private.py").write_text("raise RuntimeError('must be skipped')\n", encoding="utf-8")

    found = engine.discover_kits(tmp_path)  # must not raise

    assert "tmp_good" in found  # the importable kit self-registered
    # The broken module and the underscore-prefixed file were skipped silently.


def test_discover_kits_missing_dir_is_not_fatal(tmp_path):
    found = engine.discover_kits(tmp_path / "does-not-exist")
    assert isinstance(found, dict)


# --------------------------------------------------------------------------- #
# build_context                                                               #
# --------------------------------------------------------------------------- #
def test_build_context_defaults_without_credentials(tmp_path):
    ctx = engine.build_context(
        "https://ex.test/",
        scope_hosts=("ex.test",),
        env=str(tmp_path / "missing.env"),
    )
    assert ctx.base_url == "https://ex.test/"
    assert ctx.scope_hosts == ("ex.test",)
    assert ctx.allow_write is False
    assert callable(ctx.fetch)
    # No credentials on disk -> empty (falsy) accounts.
    assert not ctx.account_a
    assert not ctx.account_b


def test_build_context_loads_accounts_from_env(tmp_path):
    env = tmp_path / "creds.env"
    env.write_text(
        "ACCOUNT_A_TOKEN=aaa\nACCOUNT_B_COOKIE=sid=bbb\nACCOUNT_A_ID=42\n",
        encoding="utf-8",
    )
    ctx = engine.build_context("https://ex.test/", env=str(env))
    assert ctx.account_a  # truthy: has auth headers
    assert ctx.account_a.headers.get("Authorization") == "Bearer aaa"
    assert ctx.account_b.headers.get("Cookie") == "sid=bbb"
    assert ctx.account_a.user_id == "42"


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #
def test_main_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        engine.main(["--help"])
    assert exc.value.code == 0


def test_main_requires_base_url():
    with pytest.raises(SystemExit) as exc:
        engine.main([])
    assert exc.value.code == 2
