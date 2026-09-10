#!/usr/bin/env python3
"""
CSRF (Cross-Site Request Forgery) scanner.

Fetches a page, extracts state-changing HTML forms, and classifies each on
whether it is protected against cross-site forgery. Also inspects Set-Cookie
attributes (SameSite) which are the browser-side defence.

The classification logic (form parsing + verdict) is pure and unit-tested;
only `scan()` touches the network.

Severity model:
  HIGH    state-changing form (POST/PUT/DELETE or password/email/money field)
          with NO anti-CSRF token AND session cookie lacks SameSite=Lax/Strict.
  MEDIUM  state-changing form with no token but SameSite=Lax present (still
          exploitable via top-level GET->POST tricks / method override).
  LOW     token present but predictable/static, or GET-based state change.
  INFO    protected form (token + SameSite) — reported for completeness.

Usage:
  tools/csrf_scanner.py https://target.com/account
  tools/csrf_scanner.py -l urls.txt --json
  tools/csrf_scanner.py https://target.com/account --cookie "session=..."
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.safe_http import safe_urlopen  # noqa: E402

# Field/name hints that mark a form as state-changing / sensitive.
_SENSITIVE = re.compile(
    r"(pass|pwd|email|mail|token|amount|price|balance|transfer|delete|"
    r"role|admin|owner|address|phone|payment|card|iban|withdraw|api[_-]?key)",
    re.I,
)
# Common anti-CSRF token field names.
_CSRF_FIELD = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|"
    r"nonce|anti[-_]?forgery|request_token)",
    re.I,
)
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class FormInfo:
    action: str
    method: str
    input_names: list[str] = field(default_factory=list)
    hidden_token_values: list[str] = field(default_factory=list)


@dataclass
class CsrfFinding:
    url: str
    form_action: str
    method: str
    severity: str
    reason: str


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[FormInfo] = []
        self._cur: FormInfo | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = FormInfo(
                action=a.get("action", ""),
                method=(a.get("method", "GET").upper() or "GET"),
            )
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name", "")
            if name:
                self._cur.input_names.append(name)
                if _CSRF_FIELD.search(name) and a.get("type", "").lower() == "hidden":
                    self._cur.hidden_token_values.append(a.get("value", ""))

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def parse_forms(html: str) -> list[FormInfo]:
    """Pure: extract forms + their inputs from an HTML document."""
    p = _FormParser()
    try:
        p.feed(html)
    except Exception:
        pass
    if p._cur is not None:  # unclosed <form>
        p.forms.append(p._cur)
    return p.forms


def samesite_strength(set_cookie_headers: list[str]) -> str | None:
    """Pure: return the weakest SameSite across session cookies.

    Returns 'none' (or None when no cookie is set) for the weakest protection,
    'lax' or 'strict' otherwise. A missing SameSite attribute is treated as
    'none' — modern browsers default to Lax, but many targets still run on the
    old permissive behaviour, so we flag conservatively.
    """
    if not set_cookie_headers:
        return None
    order = {"none": 0, "lax": 1, "strict": 2}
    best = None
    for h in set_cookie_headers:
        m = re.search(r"samesite\s*=\s*(strict|lax|none)", h, re.I)
        val = m.group(1).lower() if m else "none"
        if best is None or order[val] < order[best]:
            best = val
    return best


def classify_form(form: FormInfo, samesite: str | None, page_url: str) -> CsrfFinding | None:
    """Pure verdict for a single form. Returns None if not state-changing."""
    has_token = bool(form.hidden_token_values) or any(_CSRF_FIELD.search(n) for n in form.input_names)
    sensitive = any(_SENSITIVE.search(n) for n in form.input_names)
    state_changing = form.method in _STATE_METHODS or sensitive
    if not state_changing:
        return None

    static_token = has_token and bool(form.hidden_token_values) and all(
        v and re.fullmatch(r"[0-9]+|true|false|1|0|on|off", v) for v in form.hidden_token_values
    )
    weak_ss = samesite in (None, "none")

    if form.method not in _STATE_METHODS and sensitive:
        return CsrfFinding(page_url, form.action, form.method, "LOW",
                           "sensitive fields on a non-POST form — verify state actually changes via GET")
    if not has_token and weak_ss:
        return CsrfFinding(page_url, form.action, form.method, "HIGH",
                           "state-changing form has no anti-CSRF token and no SameSite cookie protection")
    if not has_token and not weak_ss:
        return CsrfFinding(page_url, form.action, form.method, "MEDIUM",
                           f"no anti-CSRF token; only SameSite={samesite} protects it (bypassable via method/redirect tricks)")
    if static_token:
        return CsrfFinding(page_url, form.action, form.method, "LOW",
                           "anti-CSRF field present but value looks static/predictable — verify it is validated server-side")
    return CsrfFinding(page_url, form.action, form.method, "INFO",
                       "anti-CSRF token present; confirm the server rejects requests with it removed/altered")


def scan(url: str, cookie: str | None = None, timeout: int = 15) -> list[CsrfFinding]:
    headers = {"User-Agent": "Mozilla/5.0 (BugHunter CSRF scanner)"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        resp = safe_urlopen(req, timeout=timeout)
        body = resp.read(2_000_000).decode("utf-8", "replace")
        set_cookie = resp.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        body = e.read(500_000).decode("utf-8", "replace") if hasattr(e, "read") else ""
        set_cookie = e.headers.get_all("Set-Cookie") if e.headers else []
    except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError):
        return []
    samesite = samesite_strength(set_cookie)
    out = []
    for form in parse_forms(body):
        f = classify_form(form, samesite, url)
        if f:
            out.append(f)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CSRF scanner")
    ap.add_argument("url", nargs="?", help="target URL")
    ap.add_argument("-l", "--list", help="file of URLs (one per line)")
    ap.add_argument("--cookie", help="Cookie header (test authenticated forms)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    urls = []
    if args.list:
        with open(args.list) as fh:
            urls = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    elif args.url:
        urls = [args.url]
    else:
        ap.error("provide a URL or -l <file>")

    findings = []
    for u in urls:
        findings.extend(scan(u, cookie=args.cookie, timeout=args.timeout))

    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        if not findings:
            print("[csrf] no state-changing forms flagged")
        for f in findings:
            print(f"[{f.severity}] {f.url} -> form action={f.form_action or '(self)'} [{f.method}]: {f.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
