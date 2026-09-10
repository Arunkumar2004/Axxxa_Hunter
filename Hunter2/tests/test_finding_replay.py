"""Unit tests for finding_replay.evaluate (pure verdict logic)."""
import os, sys
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)
from tools.finding_replay import evaluate

class TestEvaluate:
    def test_all_conditions_hold_is_vulnerable(self):
        v,_ = evaluate({"status":200,"contains":["victim@"]},200,"...victim@x.com...")
        assert v == "VULNERABLE"
    def test_none_hold_is_fixed(self):
        v,_ = evaluate({"status":200,"contains":["victim@"]},403,"Forbidden")
        assert v == "FIXED"
    def test_partial_is_changed(self):
        v,_ = evaluate({"status":200,"contains":["victim@"],"absent":["err"]},200,"err victim@")
        assert v == "CHANGED"
    def test_absent_condition(self):
        v,_ = evaluate({"absent":["Forbidden"]},200,"ok")
        assert v == "VULNERABLE"
    def test_absent_violated_is_fixed(self):
        v,_ = evaluate({"absent":["Forbidden"]},403,"Forbidden")
        assert v == "FIXED"
    def test_no_spec_is_changed(self):
        v,_ = evaluate({},200,"x")
        assert v == "CHANGED"
    def test_status_only(self):
        assert evaluate({"status":500},500,"")[0] == "VULNERABLE"
        assert evaluate({"status":500},200,"")[0] == "FIXED"
