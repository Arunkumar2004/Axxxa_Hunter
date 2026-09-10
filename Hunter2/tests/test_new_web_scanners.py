"""Unit tests for the item-4 web scanners: CSRF, XXE, prototype pollution,
CSWSH (WebSocket hijack), and HPP/postMessage.

Only the pure classifier / parser logic is exercised — none of these touch the
network, matching the pattern in test_cors_scanner.py etc.
"""
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from tools.csrf_scanner import parse_forms, classify_form, samesite_strength
from tools.xxe_scanner import classify as xxe_classify, build_payloads
from tools.prototype_pollution_scanner import analyze_js, classify_active
from tools.websocket_scanner import classify as ws_classify
from tools.hpp_postmessage_scanner import analyze_postmessage, classify_hpp


# ---------------------------------------------------------------- CSRF
class TestCsrf:
    def test_unprotected_state_form_is_high(self):
        forms = parse_forms('<form method="post" action="/pay"><input name="amount"><input name="to"></form>')
        f = classify_form(forms[0], None, "u")
        assert f.severity == "HIGH"

    def test_token_and_samesite_is_info(self):
        html = '<form method="post"><input type="hidden" name="csrf_token" value="a1b2c3d4e5f6a7b8"><input name="email"></form>'
        f = classify_form(parse_forms(html)[0], "strict", "u")
        assert f.severity == "INFO"

    def test_no_token_but_samesite_lax_is_medium(self):
        html = '<form method="post"><input name="new_password"></form>'
        f = classify_form(parse_forms(html)[0], "lax", "u")
        assert f.severity == "MEDIUM"

    def test_static_token_is_low(self):
        html = '<form method="post"><input type="hidden" name="csrf_token" value="1"><input name="amount"></form>'
        f = classify_form(parse_forms(html)[0], "strict", "u")
        assert f.severity == "LOW"

    def test_non_state_get_form_ignored(self):
        html = '<form method="get" action="/search"><input name="q"></form>'
        assert classify_form(parse_forms(html)[0], None, "u") is None

    def test_samesite_picks_weakest(self):
        assert samesite_strength(["sid=x; SameSite=Strict", "a=b"]) == "none"
        assert samesite_strength(["sid=x; SameSite=Lax"]) == "lax"
        assert samesite_strength([]) is None

    def test_unclosed_form_still_parsed(self):
        assert len(parse_forms('<form method="post"><input name="pass">')) == 1


# ---------------------------------------------------------------- XXE
class TestXxe:
    def test_internal_entity_expansion_medium(self):
        r = xxe_classify("XXEC0DE", {"internal_entity": (200, "<a>XXEC0DE</a>")}, None)
        assert r.severity == "MEDIUM"

    def test_file_leak_is_high(self):
        body = "root:x:0:0:root:/root:/bin/bash"
        r = xxe_classify("C", {"error_based": (200, body)}, None)
        assert r.severity == "HIGH"

    def test_path_leak_is_medium(self):
        r = xxe_classify("C", {"error_based": (500, "failed to load external entity /etc/shadow")}, None)
        assert r.severity == "MEDIUM"

    def test_parses_xml_but_no_expansion_low(self):
        r = xxe_classify("C", {"wellformed": (200, "ok"), "malformed": (400, "bad"), "internal_entity": (200, "no canary")}, None)
        assert r.severity == "LOW"

    def test_no_signal_returns_none(self):
        assert xxe_classify("C", {"wellformed": (200, "x"), "malformed": (200, "x")}, None) is None

    def test_oob_payload_present_when_requested(self):
        assert "oob_blind" in build_payloads("C", "http://x.oast.fun")
        assert "oob_blind" not in build_payloads("C", None)


# ---------------------------------------------------------------- prototype pollution
class TestPrototypePollution:
    def test_source_and_sink_is_medium(self):
        js = 'var p = new URLSearchParams(location.search); $.extend(true, cfg, p);'
        r = analyze_js(js, "a.js")
        assert r[0].severity == "MEDIUM"

    def test_sink_only_is_medium(self):
        assert analyze_js("_.merge(target, data)", "a.js")[0].severity == "MEDIUM"

    def test_source_only_is_low(self):
        assert analyze_js("var x = location.hash;", "a.js")[0].severity == "LOW"

    def test_clean_js_no_finding(self):
        assert analyze_js("console.log('hello')", "a.js") == []

    def test_active_reflection_is_high(self):
        r = classify_active("ppc0de", '{"ppc0de":"ppc0de"}', 200, 200)
        assert r.severity == "HIGH"

    def test_active_500_is_medium(self):
        assert classify_active("x", "", 500, 200).severity == "MEDIUM"

    def test_active_no_signal_none(self):
        assert classify_active("x", "{}", 200, 200) is None


# ---------------------------------------------------------------- CSWSH
class TestCswsh:
    def test_forged_accept_with_cookie_is_high(self):
        assert ws_classify(101, 101, True).severity == "HIGH"

    def test_forged_accept_no_cookie_is_medium(self):
        assert ws_classify(101, 101, False).severity == "MEDIUM"

    def test_forged_rejected_legit_ok_is_low(self):
        assert ws_classify(403, 101, True).severity == "LOW"

    def test_both_rejected_none(self):
        assert ws_classify(403, 403, True) is None


# ---------------------------------------------------------------- HPP / postMessage
class TestHppPostMessage:
    def test_pm_dangerous_sink_no_origin_high(self):
        js = 'window.addEventListener("message", function(e){ el.innerHTML = e.data; });'
        assert analyze_postmessage(js, "a.js")[0].severity == "HIGH"

    def test_pm_no_origin_no_sink_medium(self):
        js = 'window.addEventListener("message", function(e){ store(e.data); });'
        assert analyze_postmessage(js, "a.js")[0].severity == "MEDIUM"

    def test_pm_with_origin_check_safe(self):
        js = 'window.addEventListener("message", function(e){ if(e.origin==="https://ok"){ el.innerHTML=e.data; }});'
        assert analyze_postmessage(js, "a.js") == []

    def test_pm_no_listener_no_finding(self):
        assert analyze_postmessage("var x=1;", "a.js") == []

    def test_hpp_positional_divergence_medium(self):
        assert classify_hpp("q", "base", "respA", "respB").severity == "MEDIUM"

    def test_hpp_baseline_change_low(self):
        assert classify_hpp("q", "base", "same", "same_changed").severity in ("MEDIUM", "LOW")

    def test_hpp_no_change_none(self):
        assert classify_hpp("q", "same", "same", "same") is None
