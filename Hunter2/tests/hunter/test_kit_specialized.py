"""Tests for tools/hunter/kits/specialized.py (LLM / web3 / mobile)."""
import json
import re

from tools.hunter.kits.specialized import SpecializedKit
from tools.hunter.contract import Account, HuntContext, Resp, V_CONFIRMED

_CHAT = [{"method": "POST", "url": "https://t.test/api/chat"}]


def _ctx(endpoints=None, tech=None, fetch=None):
    return HuntContext(
        base_url="https://t.test/", scope_hosts=("t.test",),
        account_a=Account("A", {}, ""),
        endpoints=endpoints or [], tech=tech or {},
        fetch=fetch or (lambda *a, **k: Resp(200, "ok", {})),
    )


def test_llm_prompt_injection_confirmed():
    def fetch(method, url, headers=None, body=None):
        s = body if isinstance(body, str) else json.dumps(body)
        m = re.search(r"HUNTER-LLM-[0-9a-f]+", s or "")
        if m:                       # vulnerable: obeys the injected instruction
            return Resp(200, json.dumps({"reply": m.group(0)}), {})
        return Resp(200, json.dumps({"reply": "hello"}), {})

    findings = SpecializedKit().run(_ctx(endpoints=_CHAT, fetch=fetch))
    llm = [f for f in findings if f.cls == "llm" and "prompt-injection" in f.technique]
    assert llm, "expected a confirmed prompt-injection finding"
    assert llm[0].verdict == V_CONFIRMED


def test_llm_refusal_is_not_flagged():
    def fetch(method, url, headers=None, body=None):
        return Resp(200, json.dumps({"reply": "I can't help with that."}), {})

    assert not [f for f in SpecializedKit().run(_ctx(endpoints=_CHAT, fetch=fetch))
                if f.cls == "llm"]


def test_not_applicable_without_surface():
    kit = SpecializedKit()
    ctx = _ctx(endpoints=[], tech={})
    assert kit.applicable(ctx) is False
    assert kit.run(ctx) == []


def test_web3_review_when_contract_present():
    kit = SpecializedKit()
    ctx = _ctx(tech={"contract": "0xDEADBEEF"})
    assert kit.applicable(ctx) is True
    assert [f for f in kit.run(ctx) if f.cls == "web3"]


def test_mobile_review_when_apk_present():
    kit = SpecializedKit()
    ctx = _ctx(tech={"apk": "/tmp/app.apk"})
    assert kit.applicable(ctx) is True
    assert [f for f in kit.run(ctx) if f.cls == "mobile"]
