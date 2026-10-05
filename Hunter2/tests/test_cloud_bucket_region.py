"""Regression tests for tools/cloud_bucket_enum.py — the KeyError: 'r' crash.

The digitalocean provider's list_url carries a {r} region placeholder, but
check_provider formatted it with b= only, raising KeyError: 'r' on every run.
"""
import pytest

from tools import cloud_bucket_enum as cbe


class _Resp:
    def __init__(self, status=404, text="NoSuchBucket"):
        self.status_code = status
        self.text = text


class _Session:
    def get(self, url, **kw):
        return _Resp(404, "NoSuchBucket")

    def put(self, url, **kw):
        return _Resp(403, "")

    def delete(self, url, **kw):
        return _Resp(204, "")


def test_every_provider_checks_without_keyerror(monkeypatch):
    # resolve() does real DNS; stub it so the test is offline and fast.
    monkeypatch.setattr(cbe, "resolve", lambda host: False)
    sc = _Session()
    for prov in cbe.PROVIDERS:
        res = cbe.check_provider(sc, "examplebucket", prov)  # must not raise
        assert res["provider"] == prov["name"]
        assert "status" in res


def test_digitalocean_list_url_needs_region():
    """Guard the exact bug: the DO template has {r}, so formatting with b= only
    raises KeyError, and formatting with b= and r= must succeed."""
    do = next(p for p in cbe.PROVIDERS if p["name"] == "digitalocean")
    assert "{r}" in do["list_url"]
    with pytest.raises(KeyError):
        do["list_url"].format(b="x")                 # the old, broken call
    assert do["list_url"].format(b="x", r="us-east-1")  # the fixed call


def test_resolve_has_no_invalid_timeout_kwarg(monkeypatch):
    """resolve() must call getaddrinfo without the unsupported timeout kwarg."""
    captured = {}

    def fake_getaddrinfo(host, port, *args, **kwargs):
        captured["kwargs"] = kwargs
        return [(2, 1, 6, "", ("1.2.3.4", 0))]

    monkeypatch.setattr(cbe.socket, "getaddrinfo", fake_getaddrinfo)
    assert cbe.resolve("example.com") is True
    assert captured["kwargs"] == {}  # no timeout= passed -> no TypeError
