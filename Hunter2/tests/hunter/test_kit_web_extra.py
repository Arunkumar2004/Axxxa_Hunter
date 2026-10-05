"""Tests for tools/hunter/kits/web_extra.py (LFI / upload / deser / GraphQL)."""
from tools.hunter.kits.web_extra import WebExtraKit
from tools.hunter.contract import Account, HuntContext, Resp, V_CONFIRMED

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _ctx(endpoints, fetch, allow_write=False, base="https://t.test/"):
    return HuntContext(
        base_url=base, scope_hosts=("t.test",),
        account_a=Account("A", {"Authorization": "Bearer A"}, "A"),
        endpoints=endpoints, allow_write=allow_write, fetch=fetch,
    )


def test_lfi_detects_passwd_read():
    def fetch(method, url, headers=None, body=None):
        if "etc/passwd" in url or "etc%2fpasswd" in url.lower():
            return Resp(200, PASSWD, {"Content-Type": "text/plain"})
        return Resp(200, "normal page body", {"Content-Type": "text/html"})

    ctx = _ctx([{"method": "GET", "url": "https://t.test/read?file=report"}], fetch)
    findings = WebExtraKit().run(ctx)
    lfi = [f for f in findings if f.cls == "lfi-path-traversal"]
    assert lfi, "expected an LFI finding on the file= parameter"
    assert lfi[0].verdict == V_CONFIRMED


def test_lfi_safe_param_not_flagged():
    def fetch(method, url, headers=None, body=None):
        return Resp(200, "nothing sensitive here", {"Content-Type": "text/html"})

    ctx = _ctx([{"method": "GET", "url": "https://t.test/read?file=report"}], fetch)
    assert not [f for f in WebExtraKit().run(ctx) if f.cls == "lfi-path-traversal"]


def test_graphql_introspection_flagged():
    def fetch(method, url, headers=None, body=None):
        if url.rstrip("/").endswith("/graphql") and method == "POST":
            if "__schema" in (body or ""):
                return Resp(200, '{"data":{"__schema":{"queryType":{"name":"Query"},'
                                 '"types":[{"name":"User"},{"name":"Order"}]}}}',
                            {"Content-Type": "application/json"})
            return Resp(200, '{"data":{"__typename":"Query"}}', {"Content-Type": "application/json"})
        return None  # other probed paths don't answer

    ctx = _ctx([], fetch)
    findings = WebExtraKit().run(ctx)
    gql = [f for f in findings if f.cls == "graphql" and "introspection" in f.technique]
    assert gql, "expected a GraphQL introspection finding"
    assert gql[0].verdict == V_CONFIRMED


def test_deserialization_blob_in_query_flagged():
    def fetch(method, url, headers=None, body=None):
        return Resp(200, "ok", {})

    ctx = _ctx([{"method": "GET",
                 "url": "https://t.test/session?data=rO0ABXNyABFqYXZhLnV0aWwu"}], fetch)
    deser = [f for f in WebExtraKit().run(ctx) if f.cls == "deserialization"]
    assert deser, "expected a deserialization sink finding for the Java blob"
    assert deser[0].evidence.get("format")


def test_file_upload_hypothesis_without_allow_write():
    def fetch(method, url, headers=None, body=None):
        return Resp(200, "ok", {})

    ctx = _ctx([{"method": "POST", "url": "https://t.test/api/upload"}], fetch,
               allow_write=False)
    up = [f for f in WebExtraKit().run(ctx) if f.cls == "file-upload"]
    assert up and "hypothesis" in up[0].technique
    assert up[0].verdict  # a POSSIBLE hypothesis, no write performed


def test_file_upload_active_under_allow_write():
    seen = {}

    def fetch(method, url, headers=None, body=None):
        if "upload" in url:   # record only the upload call (graphql probes run after)
            seen["ct"] = (headers or {}).get("Content-Type", "")
        return Resp(201, '{"stored":"/uploads/hunter-probe.php.jpg"}', {})

    ctx = _ctx([{"method": "POST", "url": "https://t.test/api/upload"}], fetch,
               allow_write=True)
    up = [f for f in WebExtraKit().run(ctx) if f.cls == "file-upload"]
    assert up and "double-extension" in up[0].technique
    assert "multipart/form-data" in seen.get("ct", "")
