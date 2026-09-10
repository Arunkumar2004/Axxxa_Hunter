"""Unit tests for item-9 recon tools: favicon-hash, source-map extraction,
API-spec IDOR generation. Pure logic only (no network)."""
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from tools.favicon_hash import murmur3_x86_32, shodan_favicon_hash, queries
from tools.sourcemap_extract import parse_sourcemap, scan_sources, find_map_url
from tools.apispec_idor import extract_idor_endpoints, build_curls, _looks_like_id


class TestFaviconHash:
    def test_murmur3_known_vectors(self):
        assert murmur3_x86_32(b"") == 0
        assert murmur3_x86_32(b"hello") == 613153351
        assert murmur3_x86_32(b"foo") == -156908512

    def test_shodan_recipe_is_deterministic(self):
        raw = b"\x00\x01\x02fake-icon-bytes"
        assert shodan_favicon_hash(raw) == shodan_favicon_hash(raw)
        assert isinstance(shodan_favicon_hash(raw), int)

    def test_queries_contain_hash(self):
        q = queries(12345)
        assert "12345" in q["shodan"]
        assert "12345" in q["fofa"]


class TestSourceMap:
    def test_parse_normalises_webpack_paths(self):
        sm = '{"version":3,"sources":["webpack:///./src/a.js","../b.js"],"sourcesContent":["x","y"]}'
        files = parse_sourcemap(sm)
        assert "src/a.js" in files and files["src/a.js"] == "x"
        assert "b.js" in files

    def test_scan_finds_secret_and_endpoint(self):
        files = {"a.js": 'const K="sk_live_abcdefghij"; fetch("/api/v2/admin");'}
        r = scan_sources(files)
        assert any("sk_live_" in s for s in r["secrets"])
        assert "/api/v2/admin" in r["endpoints"]

    def test_find_map_url_resolves_relative(self):
        js = "console.log(1)\n//# sourceMappingURL=app.min.js.map"
        assert find_map_url("https://t.com/static/app.min.js", js) == "https://t.com/static/app.min.js.map"

    def test_find_map_url_none_when_absent(self):
        assert find_map_url("https://t.com/a.js", "console.log(1)") is None

    def test_path_traversal_stripped(self):
        files = parse_sourcemap('{"version":3,"sources":["../../../etc/passwd"],"sourcesContent":["x"]}')
        assert all(".." not in k for k in files)


class TestApiSpecIdor:
    def test_extracts_path_and_query_id_params(self):
        spec = {"basePath": "/api", "paths": {
            "/users/{id}": {"get": {"summary": "get user"}},
            "/health": {"get": {}},
            "/orders": {"get": {"parameters": [{"name": "account_id", "in": "query"}]}},
        }}
        eps = extract_idor_endpoints(spec)
        paths = {(e["method"], e["path"]) for e in eps}
        assert ("GET", "/api/users/{id}") in paths
        assert ("GET", "/api/orders") in paths
        assert all("/api/health" != e["path"] for e in eps)  # no id -> skipped

    def test_openapi3_servers_and_multiple_methods(self):
        spec = {"servers": [{"url": "https://api.t.com"}], "paths": {
            "/doc/{docId}": {"get": {}, "delete": {}},
        }}
        eps = extract_idor_endpoints(spec)
        assert {e["method"] for e in eps} == {"GET", "DELETE"}

    def test_id_hint_matcher(self):
        assert _looks_like_id("id") and _looks_like_id("account_id") and _looks_like_id("orderId")
        assert not _looks_like_id("q") and not _looks_like_id("search")

    def test_build_curls_pairs_a_and_b(self):
        eps = [{"method": "GET", "path": "/users/{id}", "id_params": ["id"], "summary": ""}]
        lines = build_curls(eps, "https://api.t.com", "TA", "TB")
        joined = "\n".join(lines)
        assert "OBJECT_ID" in joined
        assert "TA" in joined and "TB" in joined
