#!/usr/bin/env python3
"""infra-recon depth kit — subdomain-takeover, cloud, cicd, k8s, dependency-confusion.

These are infrastructure/recon classes. HTTP probing goes through ``ctx.fetch``;
DNS (CNAME) and npm-registry lookups go through the module-level helpers
``_resolve_cname`` / ``_npm_claimed`` so tests monkeypatch them and run offline.
Everything is DETECT-AND-REPORT ONLY — the kit never claims a dangling resource,
never writes to a bucket, never mutates anything.

Follows the pattern of ``tools/hunter/kits/ssrf_infra.py``.
"""
from __future__ import annotations

import os
import re
import socket
import sys
from urllib.parse import urljoin, urlparse

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter.contract import Finding, V_CONFIRMED, V_POSSIBLE, register  # noqa: E402

try:
    from tools import cloud_bucket_enum as _cbe  # noqa: E402
except Exception:  # pragma: no cover
    _cbe = None

# CNAME provider fragment -> dangling-resource body fingerprint.
_TAKEOVER = [
    ("github.io", re.compile(r"There isn't a GitHub Pages site here", re.I)),
    ("s3.amazonaws.com", re.compile(r"NoSuchBucket", re.I)),
    ("herokuapp.com", re.compile(r"No such app|herokucdn.com/error", re.I)),
    ("cloudfront.net", re.compile(r"ERROR: The request could not be satisfied", re.I)),
    ("azurewebsites.net", re.compile(r"404 Web Site not found", re.I)),
    ("ghost.io", re.compile(r"Domain error", re.I)),
    ("fastly", re.compile(r"Fastly error: unknown domain", re.I)),
    ("pantheonsite.io", re.compile(r"The gods are wise|404 error unknown site", re.I)),
    ("readthedocs.io", re.compile(r"unknown to Read the Docs", re.I)),
]

_K8S_PATHS = ("/api/v1/namespaces", "/api", "/version", "/healthz", "/apis")
_K8S_SIG = re.compile(r'"kind"\s*:\s*"(?:APIVersions|NamespaceList|Status)"|'
                      r'"gitVersion"|"major"\s*:\s*"1"', re.I)

_PKG_NAME = re.compile(r'"(@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*|[a-z0-9][\w.-]{2,})"\s*:\s*"[\^~>=<*\d]', re.I)
_INTERNAL_HINT = re.compile(r"(internal|private|corp|intranet|-infra|-core|-common|^@)", re.I)
_GITHUB_REF = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", re.I)


# --- injectable I/O (monkeypatched in tests) --------------------------------
def _resolve_cname(host: str) -> list:
    """Best-effort CNAME/alias list for a host (DNS). Returns [] on failure."""
    try:
        name, aliases, _ = socket.gethostbyname_ex(host)
        return [name] + list(aliases or [])
    except Exception:
        return []


def _npm_claimed(name: str) -> bool:
    """True if a package name is registered on the public npm registry."""
    import urllib.request
    try:
        from tools.safe_http import safe_urlopen
    except Exception:
        safe_urlopen = None
    url = "https://registry.npmjs.org/" + name.replace("/", "%2f")
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "hunter/infra"})
    try:
        resp = (safe_urlopen or urllib.request.urlopen)(req, timeout=8)
        return getattr(resp, "status", 200) == 200
    except Exception as exc:
        code = getattr(exc, "code", None)
        if code == 404:
            return False          # definitively unclaimed
        return True               # unknown -> assume claimed (avoid false positive)


# --- helpers ----------------------------------------------------------------
def _hosts(ctx) -> list:
    out = []
    for h in (ctx.scope_hosts or ()):
        s = str(h).lstrip("*.").rstrip(".")
        if s:
            out.append(s)
    for ep in (ctx.endpoints or []):
        if isinstance(ep, dict):
            h = urlparse(ep.get("url", "")).hostname
            if h:
                out.append(h.lower())
    base_h = urlparse(getattr(ctx, "base_url", "") or "").hostname
    if base_h:
        out.append(base_h.lower())
    seen, res = set(), []
    for h in out:
        if h and h not in seen:
            seen.add(h)
            res.append(h)
    return res


def _fetch(ctx, method, url):
    f = getattr(ctx, "fetch", None)
    if f is None:
        return None
    try:
        return f(method, url, headers=None, body=None)
    except Exception:
        return None


def _mk(cls, title, url, technique, *, severity="medium", confidence="firm",
        verdict=V_POSSIBLE, evidence=None, repro=None, kill=None, chain=None):
    return Finding(cls=cls, title=title, severity=severity, confidence=confidence,
                   axis=technique.split(":")[0], technique=technique, method="GET",
                   url=url, evidence=evidence or {}, verdict=verdict,
                   repro=repro or [], kill_reasons=kill or [], chain_hints=chain or [])


# --- probes -----------------------------------------------------------------
def _probe_takeover(ctx):
    out = []
    for host in _hosts(ctx):
        cnames = " ".join(_resolve_cname(host)).lower()
        if not cnames:
            continue
        for frag, sig in _TAKEOVER:
            if frag not in cnames:
                continue
            for scheme in ("https://", "http://"):
                r = _fetch(ctx, "GET", scheme + host + "/")
                if r is not None and sig.search(r.body or ""):
                    out.append(_mk(
                        "subdomain-takeover",
                        f"Dangling {frag} record — subdomain takeover candidate",
                        scheme + host + "/", f"takeover:{frag}",
                        severity="high", confidence="firm", verdict=V_POSSIBLE,
                        evidence={"host": host, "cname_fragment": frag},
                        repro=[f"{host} CNAMEs to {frag} but the resource is unclaimed "
                               "(dangling fingerprint in the response).",
                               "DETECT-ONLY: do not register the resource."],
                        kill=["verify the record is truly unclaimed before reporting"],
                        chain=["subdomain takeover -> phishing / OAuth-redirect / cookie theft"],
                    ))
                    break
            break
    return out


def _probe_cloud(ctx):
    out = []
    if _cbe is None:
        return out
    base_h = urlparse(getattr(ctx, "base_url", "") or "").hostname or ""
    try:
        names = _cbe.candidates_for_domain(base_h) if base_h else []
    except Exception:
        names = []
    for name in names[:20]:
        url = f"https://{name}.s3.amazonaws.com/"
        r = _fetch(ctx, "GET", url)
        if r is None:
            continue
        body = r.body or ""
        if "<ListBucketResult" in body:
            out.append(_mk(
                "cloud", "Public S3 bucket is listable", url, "cloud:s3-public-read",
                severity="high", confidence="confirmed", verdict=V_CONFIRMED,
                evidence={"bucket": name},
                repro=[f"GET {url} returns an object listing (public-read)."],
                chain=["public bucket -> data exposure / JS tamper"],
            ))
    return out


def _probe_k8s(ctx):
    out = []
    base = getattr(ctx, "base_url", "") or ""
    if not base:
        return out
    for path in _K8S_PATHS:
        url = urljoin(base, path.lstrip("/"))
        if not ctx.in_scope(urlparse(url).hostname or ""):
            continue
        r = _fetch(ctx, "GET", url)
        if r is None or r.status not in (200, 401, 403):
            continue
        if r.status == 200 and _K8S_SIG.search(r.body or ""):
            out.append(_mk(
                "k8s", "Kubernetes API/endpoint reachable", url, "k8s:exposed-api",
                severity="high", confidence="firm", verdict=V_POSSIBLE,
                evidence={"path": path, "status": r.status},
                repro=[f"GET {url} returns a Kubernetes API response.",
                       "Check for unauthenticated access to namespaces/secrets."],
                chain=["exposed k8s API -> secrets / workload compromise"],
            ))
            break
    return out


def _probe_dependency_confusion(ctx):
    out = []
    base = getattr(ctx, "base_url", "") or ""
    texts = []
    for path in ("package.json", ".npmrc", "yarn.lock"):
        r = _fetch(ctx, "GET", urljoin(base, path)) if base else None
        if r is not None and r.status == 200 and r.body:
            texts.append(r.body)
    # also mine the base page for inline package names
    rb = _fetch(ctx, "GET", base) if base else None
    if rb is not None and rb.body:
        texts.append(rb.body)
    seen = set()
    for text in texts:
        for m in _PKG_NAME.findall(text):
            name = m.strip()
            if name in seen or name in ("react", "lodash", "axios", "express", "vue"):
                continue
            if not _INTERNAL_HINT.search(name) and not name.startswith("@"):
                continue
            seen.add(name)
            if not _npm_claimed(name):
                out.append(_mk(
                    "dependency-confusion",
                    f"Internal package '{name}' is unclaimed on the public npm registry",
                    base, "dependency-confusion:unclaimed-npm",
                    severity="high", confidence="firm", verdict=V_POSSIBLE,
                    evidence={"package": name},
                    repro=[f"The app references '{name}', which is NOT registered on "
                           "the public npm registry.",
                           "An attacker could publish it to hijack the build (do not actually publish)."],
                    chain=["dependency confusion -> build/CI RCE"],
                ))
    return out


def _probe_cicd(ctx):
    out = []
    base = getattr(ctx, "base_url", "") or ""
    r = _fetch(ctx, "GET", base) if base else None
    body = (r.body or "") if r is not None else ""
    for org, repo in set(_GITHUB_REF.findall(body)):
        if org.lower() in ("features", "about", "pricing", "login", "sponsors"):
            continue
        out.append(_mk(
            "cicd", f"Public GitHub repo referenced: {org}/{repo}", base,
            "cicd:github-repo", severity="info", confidence="tentative",
            verdict=V_POSSIBLE,
            evidence={"org": org, "repo": repo},
            repro=[f"The site references github.com/{org}/{repo}.",
                   "Review its Actions workflows for injection / secret exfil / "
                   "self-hosted runner poisoning (detect-only)."],
            kill=["reference only; CI risk not confirmed"],
            chain=["CI/CD workflow injection -> secret exfiltration -> supply chain"],
        ))
        break
    return out


class InfraReconKit:
    name = "infra-recon"
    classes = ("subdomain-takeover", "cloud", "cicd", "k8s", "dependency-confusion")

    def applicable(self, ctx) -> bool:
        if ctx is None or getattr(ctx, "fetch", None) is None:
            return False
        return bool(_hosts(ctx))

    def run(self, ctx) -> list:
        if getattr(ctx, "fetch", None) is None:
            return []
        findings = []
        for probe in (_probe_takeover, _probe_cloud, _probe_k8s,
                      _probe_dependency_confusion, _probe_cicd):
            try:
                findings += probe(ctx)
            except Exception:
                continue
        seen, out = set(), []
        for f in findings:
            key = (f.cls, f.technique, f.url, str(f.evidence))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out


register(InfraReconKit())
