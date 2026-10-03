"""Tests for tools/surface_graph.py — attack-surface graph v1 + v2 live probing."""
import json
import os

import pytest

from tools import surface_graph
from tools.credential_store import CredentialStore


@pytest.fixture
def recon(tmp_path, monkeypatch):
    root = tmp_path / "recon"
    root.mkdir()
    find = tmp_path / "findings"
    find.mkdir()
    monkeypatch.setattr(surface_graph, "RECON_DIR", str(root))
    monkeypatch.setattr(surface_graph, "FINDINGS_DIR", str(find))
    return root


def _write(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def test_builds_and_templates_ids(recon):
    d = recon / "acme.com"
    _write(str(d / "urls" / "all.txt"), [
        "https://api.acme.com/api/user/123/orders",
        "https://api.acme.com/api/user/456/orders",   # same family as above
        "https://api.acme.com/api/user/123/export",    # sibling action
        "https://acme.com/about",
    ])
    g = surface_graph.build_graph("acme.com")
    # the two /user/{id}/orders collapse into one templated endpoint
    assert "api.acme.com/api/user/{id}/orders" in g["endpoints"]
    # id-bearing endpoints flagged as IDOR candidates
    idor = [a for a in g["anomalies"] if a["type"] == "idor_candidate"]
    assert any("{id}" in a["endpoint"] for a in idor)
    # the export action flagged as sensitive_action
    assert any(a["type"] == "sensitive_action" and "export" in a["endpoint"]
               for a in g["anomalies"])


def test_sibling_cluster_detected(recon):
    d = recon / "acme.com"
    _write(str(d / "urls" / "all.txt"), [
        "https://acme.com/api/account/profile",
        "https://acme.com/api/account/delete",
        "https://acme.com/api/account/export",
    ])
    g = surface_graph.build_graph("acme.com")
    clusters = g["sibling_clusters"]
    assert clusters and clusters[0]["size"] >= 3


def test_multiple_api_versions_flagged(recon):
    d = recon / "acme.com"
    _write(str(d / "urls" / "all.txt"), [
        "https://api.acme.com/v1/orders",
        "https://api.acme.com/v2/orders",
    ])
    g = surface_graph.build_graph("acme.com")
    assert any(a["type"] == "multiple_api_versions" for a in g["anomalies"])


def test_writes_outputs(recon):
    d = recon / "acme.com"
    _write(str(d / "urls" / "all.txt"), ["https://acme.com/api/x/1/y"])
    g = surface_graph.build_graph("acme.com")
    jp, mp = surface_graph.write_graph("acme.com", g)
    assert os.path.isfile(jp) and os.path.isfile(mp)


def test_missing_recon_raises(recon):
    with pytest.raises(FileNotFoundError):
        surface_graph.build_graph("nope.com")


def test_rejects_traversal(recon):
    with pytest.raises(ValueError):
        surface_graph.build_graph("../etc")


# --------------------------------------------------------------------------
# v2 live auth-probing — all tests use an injected fake fetch (no network).
# --------------------------------------------------------------------------

def _store_with_ab(tmp_path, a="SUPERSECRET_A", b="SUPERSECRET_B"):
    env = tmp_path / ".env"
    env.write_text(f"ACCOUNT_A_TOKEN={a}\nACCOUNT_B_TOKEN={b}\n", encoding="utf-8")
    return CredentialStore(str(env))


def test_probe_missing_auth_flagged_high(tmp_path):
    store = _store_with_ab(tmp_path)

    def fake(url, headers):  # anon + everyone gets 200 on the api endpoint
        return (200, "order list body")

    res = surface_graph.probe_auth(
        ["https://api.acme.com/api/orders/1"], store, fetch=fake
    )
    assert res["probed"] == 1
    missing = [a for a in res["anomalies"] if a["type"] == "missing_auth"]
    assert missing and missing[0]["priority"] == "high"
    assert res["role_reachability"]["anon_reachable"] == 1


def test_probe_cross_account_flagged(tmp_path):
    store = _store_with_ab(tmp_path)

    def fake(url, headers):
        if not headers.get("Authorization"):   # anon denied
            return (401, "")
        return (200, "same shared body xyz")   # A and B both see identical data

    res = surface_graph.probe_auth(
        ["https://api.acme.com/api/orders/1"], store, fetch=fake
    )
    cross = [a for a in res["anomalies"] if a["type"] == "cross_account"]
    assert cross and cross[0]["priority"] == "high"
    # anon was 401 -> not a missing_auth finding
    assert not any(a["type"] == "missing_auth" for a in res["anomalies"])


def test_probe_proper_isolation_not_flagged(tmp_path):
    store = _store_with_ab(tmp_path)

    def fake(url, headers):
        auth = headers.get("Authorization", "")
        if not auth:
            return (401, "")                # anon denied
        if "SUPERSECRET_A" in auth:
            return (200, "account A data")  # A sees its own
        return (403, "")                    # B is blocked

    res = surface_graph.probe_auth(
        ["https://api.acme.com/api/orders/1"], store, fetch=fake
    )
    assert res["anomalies"] == []
    assert res["role_reachability"]["auth_only"] == 1


def test_probe_skipped_without_creds(tmp_path):
    store = CredentialStore(str(tmp_path / "empty.env"))  # file absent -> no creds

    def fake(url, headers):
        return (200, "x")

    res = surface_graph.probe_auth(
        ["https://api.acme.com/api/orders/1"], store, fetch=fake
    )
    assert res == {"skipped": "no ACCOUNT_A/B creds"}


def test_probe_leaks_no_tokens_or_bodies(tmp_path):
    store = _store_with_ab(tmp_path)

    def fake(url, headers):  # fire both anomalies, with a distinctive secret body
        return (200, "SECRET_BODY_CONTENTS_12345")

    res = surface_graph.probe_auth(
        ["https://api.acme.com/api/orders/1"], store, fetch=fake
    )
    blob = json.dumps(res)
    assert res["anomalies"]  # anomalies present, so the check is meaningful
    assert "SUPERSECRET_A" not in blob
    assert "SUPERSECRET_B" not in blob
    assert "SECRET_BODY_CONTENTS_12345" not in blob
