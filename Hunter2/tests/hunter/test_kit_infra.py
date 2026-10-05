"""Tests for tools/hunter/kits/infra_recon.py. Offline: DNS + npm are monkeypatched."""
from tools.hunter.kits import infra_recon
from tools.hunter.kits.infra_recon import InfraReconKit
from tools.hunter.contract import Account, HuntContext, Resp


def _ctx(fetch, base="https://app.test/", scope=("app.test",), endpoints=None):
    return HuntContext(
        base_url=base, scope_hosts=scope,
        account_a=Account("A", {}, ""),
        endpoints=endpoints or [], fetch=fetch,
    )


def test_subdomain_takeover_detected(monkeypatch):
    monkeypatch.setattr(infra_recon, "_resolve_cname",
                        lambda host: [host + ".github.io"])

    def fetch(method, url, headers=None, body=None):
        return Resp(404, "There isn't a GitHub Pages site here.", {})

    findings = InfraReconKit().run(_ctx(fetch))
    takeover = [f for f in findings if f.cls == "subdomain-takeover"]
    assert takeover, "expected a subdomain-takeover candidate"
    assert takeover[0].evidence.get("cname_fragment") == "github.io"


def test_no_takeover_when_resource_is_live(monkeypatch):
    monkeypatch.setattr(infra_recon, "_resolve_cname", lambda host: [host + ".github.io"])

    def fetch(method, url, headers=None, body=None):
        return Resp(200, "<html>a real site</html>", {})

    assert not [f for f in InfraReconKit().run(_ctx(fetch)) if f.cls == "subdomain-takeover"]


def test_public_s3_bucket_flagged(monkeypatch):
    monkeypatch.setattr(infra_recon, "_resolve_cname", lambda host: [])

    def fetch(method, url, headers=None, body=None):
        if ".s3.amazonaws.com" in url:
            return Resp(200, '<?xml version="1.0"?><ListBucketResult><Contents>'
                             '<Key>secret.txt</Key></Contents></ListBucketResult>', {})
        return Resp(404, "", {})

    findings = InfraReconKit().run(_ctx(fetch, base="https://shop.test/", scope=("shop.test",)))
    assert [f for f in findings if f.cls == "cloud"], "expected a public-bucket finding"


def test_k8s_api_exposed(monkeypatch):
    monkeypatch.setattr(infra_recon, "_resolve_cname", lambda host: [])

    def fetch(method, url, headers=None, body=None):
        if url.endswith("/api/v1/namespaces"):
            return Resp(200, '{"kind":"NamespaceList","apiVersion":"v1","items":[]}', {})
        return Resp(404, "", {})

    findings = InfraReconKit().run(_ctx(fetch))
    assert [f for f in findings if f.cls == "k8s"], "expected a k8s exposure finding"


def test_dependency_confusion_unclaimed(monkeypatch):
    monkeypatch.setattr(infra_recon, "_resolve_cname", lambda host: [])
    monkeypatch.setattr(infra_recon, "_npm_claimed", lambda name: False)

    def fetch(method, url, headers=None, body=None):
        if url.endswith("package.json"):
            return Resp(200, '{"dependencies":{"@corp/internal-lib":"^1.2.0",'
                             '"react":"^18.0.0"}}', {})
        return Resp(404, "", {})

    findings = InfraReconKit().run(_ctx(fetch))
    dep = [f for f in findings if f.cls == "dependency-confusion"]
    assert dep, "expected an unclaimed internal-package finding"
    assert dep[0].evidence.get("package") == "@corp/internal-lib"


def test_dependency_confusion_claimed_name_not_flagged(monkeypatch):
    monkeypatch.setattr(infra_recon, "_resolve_cname", lambda host: [])
    monkeypatch.setattr(infra_recon, "_npm_claimed", lambda name: True)   # all claimed

    def fetch(method, url, headers=None, body=None):
        if url.endswith("package.json"):
            return Resp(200, '{"dependencies":{"@corp/internal-lib":"^1.2.0"}}', {})
        return Resp(404, "", {})

    assert not [f for f in InfraReconKit().run(_ctx(fetch)) if f.cls == "dependency-confusion"]
