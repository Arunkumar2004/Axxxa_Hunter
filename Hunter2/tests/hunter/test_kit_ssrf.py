"""Offline unit tests for the SSRF / INFRA depth kit (tools/hunter/kits/ssrf_infra.py).

Every test drives the kit with an inline fake ``fetch`` that returns
``contract.Resp`` objects, so no network is touched. Coverage:

  * SSRF param whose response differs for an internal target -> finding, with a
    *bypass* technique recorded (decimal/octal/hex/@-confusion);
  * SSRF with a cloud-metadata signature -> CONFIRMED + no secret leakage;
  * blind SSRF (no in-band signal) -> OOB marker emitted, needs-OOB flagged;
  * open redirect reflected as the Location host -> finding;
  * open redirect false-positive guard (attacker host only in a query param) -> none;
  * CRLF payload producing an injected Set-Cookie header -> finding;
  * host-header injection reflected into a body link -> finding;
  * registration and ``applicable`` gating.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools.hunter import contract  # noqa: E402
from tools.hunter.kits.ssrf_infra import SsrfInfraKit  # noqa: E402
from tools.crlf_scanner import CANARY  # noqa: E402


def _ctx(**kw) -> contract.HuntContext:
    return contract.HuntContext(**kw)


# --------------------------------------------------------------------- SSRF
def test_ssrf_param_diff_records_bypass_technique():
    baseline = "home page baseline content " * 5
    differ = "internal service banner -- a totally different response body " * 10

    def fake(method, url, headers=None, body=None):
        # Only the filter-BYPASS forms reach the (fake) internal service and
        # change the response; the plain metadata host returns the baseline.
        if ("2852039166" in url or "0251.0376" in url or "0xA9FEA9FE" in url
                or "allowed.example@169.254.169.254" in url):
            return contract.Resp(status=200, body=differ, headers={})
        return contract.Resp(status=200, body=baseline, headers={})

    ctx = _ctx(
        base_url="https://app.example/",
        endpoints=[{"method": "GET", "url": "https://app.example/api/fetch?url=http://old"}],
        fetch=fake,
    )
    ssrf = [f for f in SsrfInfraKit().run(ctx) if f.cls == "ssrf"]
    assert len(ssrf) == 1
    f = ssrf[0]
    assert f.verdict == contract.V_POSSIBLE
    assert f.severity == "high"
    # A bypass technique is recorded (not the plain metadata hostname).
    assert f.technique == "decimal-ip"
    assert "decimal-ip" in f.evidence["bypasses_hit"]
    assert {"octal-ip", "hex-ip", "at-confusion"} <= set(f.evidence["bypasses_hit"])
    assert any("ssrf->cloud-metadata->creds" in h for h in f.chain_hints)
    # Detection-only: no internal pivot claimed, just reachability by diff.
    assert f.kill_reasons


def test_ssrf_metadata_signature_is_confirmed_and_redacted():
    secret = "AccessKeyId AKIAEXAMPLEKEY / SecretAccessKey supersecretvalue"

    def fake(method, url, headers=None, body=None):
        if ("169.254.169.254" in url or "metadata.google" in url
                or "2852039166" in url):
            return contract.Resp(
                status=200,
                body="iam/security-credentials/web-role\n" + secret,
                headers={})
        return contract.Resp(status=200, body="external ok", headers={})

    ctx = _ctx(
        base_url="https://app.example/",
        endpoints=[{"method": "GET", "url": "https://app.example/img?image_url=http://x"}],
        fetch=fake,
    )
    ssrf = [f for f in SsrfInfraKit().run(ctx) if f.cls == "ssrf"]
    assert len(ssrf) == 1
    f = ssrf[0]
    assert f.verdict == contract.V_CONFIRMED
    assert f.confidence == "confirmed"
    assert f.severity == "critical"
    assert not f.kill_reasons
    assert f.evidence["signature"]  # a signature label is recorded
    # The response body (which may hold live credentials) must not leak anywhere.
    blob = "".join(repr(x) for x in (f.evidence, f.repro, f.title, f.chain_hints))
    assert "supersecret" not in blob and "AKIAEXAMPLE" not in blob


def test_blind_ssrf_emits_oob_marker():
    def fake(method, url, headers=None, body=None):
        # Alive, but identical regardless of target -> no in-band signal (blind).
        return contract.Resp(status=200, body="static shell page", headers={})

    ctx = _ctx(
        base_url="https://app.example/",
        endpoints=[{"method": "GET", "url": "https://app.example/proxy?webhook=http://x"}],
        fetch=fake,
    )
    ssrf = [f for f in SsrfInfraKit().run(ctx) if f.cls == "ssrf"]
    assert len(ssrf) == 1
    f = ssrf[0]
    assert f.technique == "blind-oob"
    assert f.evidence.get("needs_oob") is True
    assert f.evidence.get("oob_marker")
    assert f.verdict == contract.V_INCONCLUSIVE
    assert f.kill_reasons


# ------------------------------------------------------------- open redirect
def test_open_redirect_reflected_in_location():
    def fake(method, url, headers=None, body=None):
        hdrs = {k.lower(): str(v) for k, v in (headers or {}).items()}
        spoof = any("evil.example" in v for v in hdrs.values())
        if not spoof and "evil.example" in url:
            return contract.Resp(status=302, body="",
                                 headers={"Location": "https://evil.example/"})
        return contract.Resp(status=200, body="ok", headers={})

    ctx = _ctx(
        base_url="https://app.example/",
        endpoints=[{"method": "GET", "url": "https://app.example/login?next=/home"}],
        fetch=fake,
    )
    red = [f for f in SsrfInfraKit().run(ctx) if f.cls == "open-redirect"]
    assert len(red) == 1
    f = red[0]
    assert f.verdict == contract.V_CONFIRMED
    assert f.evidence["attacker_host"] == "evil.example"
    assert f.evidence["reflected_in"] == "Location"
    assert not f.kill_reasons


def test_open_redirect_safe_param_not_flagged():
    def fake(method, url, headers=None, body=None):
        hdrs = {k.lower(): str(v) for k, v in (headers or {}).items()}
        spoof = any("evil.example" in v for v in hdrs.values())
        if not spoof and "evil.example" in url:
            # evil.example appears ONLY as a query parameter of a same-origin
            # Location -- it is not the redirect host, so it must NOT be flagged.
            return contract.Resp(
                status=302, body="",
                headers={"Location": "https://app.example/landing?u=https://evil.example/x"})
        return contract.Resp(status=200, body="ok", headers={})

    ctx = _ctx(
        base_url="https://app.example/",
        endpoints=[{"method": "GET", "url": "https://app.example/go?to=/dashboard"}],
        fetch=fake,
    )
    findings = SsrfInfraKit().run(ctx)
    assert [f for f in findings if f.cls == "open-redirect"] == []
    # The same query-only mention must not trip the host-header reflection guard.
    assert [f for f in findings if f.cls == "host-header"] == []


# --------------------------------------------------------------------- CRLF
def test_crlf_injected_setcookie_detected():
    def fake(method, url, headers=None, body=None):
        # The CRLF payload carries the canary "Set-Cookie:crlftest=1" into the path.
        if CANARY in url:
            return contract.Resp(status=200, body="",
                                 headers={"Set-Cookie": f"{CANARY}=1; Path=/"})
        return contract.Resp(status=200, body="ok", headers={})

    ctx = _ctx(
        endpoints=[{"method": "GET", "url": "https://app.example/page?q=1"}],
        fetch=fake,
    )
    crlf = [f for f in SsrfInfraKit().run(ctx) if f.cls == "crlf"]
    assert len(crlf) >= 1
    f = crlf[0]
    assert f.verdict == contract.V_CONFIRMED
    assert f.technique == "response-splitting"
    assert CANARY in f.evidence["injected_header"]
    assert not f.kill_reasons


# -------------------------------------------------------------- host header
def test_host_header_reflected_in_body_link():
    def fake(method, url, headers=None, body=None):
        hdrs = {k.lower(): str(v) for k, v in (headers or {}).items()}
        spoofed = any("evil.example" in hdrs.get(k, "")
                      for k in ("host", "x-forwarded-host", "x-host", "forwarded"))
        if spoofed:
            return contract.Resp(
                status=200,
                body='<html><a href="https://evil.example/reset?token=xxx">reset</a></html>',
                headers={})
        return contract.Resp(status=200, body='<a href="/home">home</a>', headers={})

    ctx = _ctx(
        base_url="https://app.example/",
        endpoints=[{"method": "GET", "url": "https://app.example/account"}],
        fetch=fake,
    )
    hh = [f for f in SsrfInfraKit().run(ctx) if f.cls == "host-header"]
    assert len(hh) >= 1
    f = hh[0]
    assert f.evidence["attacker_host"] == "evil.example"
    assert f.evidence["reflected_in"] == "body-link"
    assert f.verdict == contract.V_POSSIBLE
    assert f.kill_reasons  # active reset-poisoning is gated behind allow_write
    assert any("password-reset" in h for h in f.chain_hints)


# -------------------------------------------------------- registry / gating
def test_kit_registers_and_is_applicable():
    reg = contract.registry()
    assert "ssrf-infra" in reg
    kit = reg["ssrf-infra"]
    assert set(kit.classes) == {
        "ssrf", "request-smuggling", "cache-poisoning", "open-redirect",
        "host-header", "crlf",
    }
    assert kit.applicable(_ctx(endpoints=[{"method": "GET", "url": "https://x/y?url=z"}]))
    assert kit.applicable(_ctx(base_url="https://x/"))
    assert not kit.applicable(_ctx())
