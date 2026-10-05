"""Tests for tools/api_security_scanner.py — local/URL spec loading + SPA filter.

Old behaviour reduced every --spec value to its URL path and refetched it from
the base host, so a local swagger.json saved during recon could never be used.
"""
import json

from tools import api_security_scanner as api

SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/users/{id}": {"get": {}},
        "/orders/{oid}": {"get": {}, "post": {}},
    },
}


def test_load_spec_from_local_file(tmp_path):
    f = tmp_path / "swagger.json"
    f.write_text(json.dumps(SPEC), encoding="utf-8")
    sc = api.Session("https://example.test")
    loaded = api.load_spec(sc, str(f))
    assert loaded == SPEC
    paths = api.extract_paths(loaded)
    assert {"method": "GET", "path": "/users/{id}"} in paths
    assert sum(1 for p in paths if p["path"] == "/orders/{oid}") == 2


def test_load_spec_missing_file_falls_back_to_base(tmp_path, monkeypatch):
    sc = api.Session("https://example.test")
    monkeypatch.setattr(sc, "get", lambda p, **k: None)  # base unreachable
    assert api.load_spec(sc, "/not/a/real/file.json") is None


def test_is_noise_skips_catchall_and_none():
    sc = api.Session("https://example.test")

    class _Baseline:
        def is_catchall(self, status, text):
            return text == "SHELL"

    sc.baseline = _Baseline()

    class _R:
        def __init__(self, status, text):
            self.status_code = status
            self.text = text

    assert sc.is_noise(None) is True
    assert sc.is_noise(_R(200, "SHELL")) is True
    assert sc.is_noise(_R(200, '{"real": 1}')) is False


def test_is_noise_without_baseline_only_flags_none():
    sc = api.Session("https://example.test")
    assert sc.baseline is None

    class _R:
        status_code = 200
        text = "anything"

    assert sc.is_noise(None) is True
    assert sc.is_noise(_R()) is False


def test_bola_probe_substitutes_non_numeric_id():
    """--id now accepts UUIDs/slugs, substituted verbatim into {id} paths."""
    import re
    uuid = "42cb5e60-1111-2222-3333-444455556666"
    probe = re.sub(r"\{(\w+)\}", str(uuid), "/product/{pid}/v2/")
    assert probe == f"/product/{uuid}/v2/"
