#!/usr/bin/env python3
"""Autonomous hunt — one command that runs the full expert engine end to end.

    python tools/hunter/autohunt.py https://target.com

What it does, with no further input unless it genuinely needs you:

  1. scope      — derive the in-scope hosts from the target.
  2. recon      — gather the attack surface (swagger / recon dir / surface graph
                  / a light in-scope crawl) and hand it to the engine.
  3. auth       — if the target needs a login and no credentials are on file, it
                  opens a REAL browser (Chromium) so YOU can log in (email / OTP /
                  MFA / SSO are typed into the site, never into this tool). That
                  browser hand-off is the ONLY thing it asks of you. If creds are
                  already in .env, or --no-auth is given, no browser opens.
  4. hunt       — run every applicable depth kit at full power across all classes.
  5. chain/gate — chain the survivors, drop false positives (7-question gate).
  6. report     — write a JSON + Markdown report under findings/<host>/.

Safety: writes (cross-account tamper, uploads, races) are on by default so the
hunt is complete, but every write captures-then-reverts, never DELETEs a foreign
object, and never leaves the browser's own credentials. Pass --safe for a
read-only hunt. Everything stays inside the scoped hosts.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from urllib.parse import urlparse

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter import engine, recon_feed  # noqa: E402
from tools.hunter.contract import Account, HuntContext  # noqa: E402


# --------------------------------------------------------------------------- #
# target + scope
# --------------------------------------------------------------------------- #
def _normalise(target: str) -> "tuple[str, str]":
    """Return (base_url, host). Accepts bare hosts or full URLs."""
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    p = urlparse(t)
    host = (p.hostname or "").lower()
    base = f"{p.scheme}://{p.netloc}/"
    return base, host


def _safe_name(host: str) -> str:
    return host.replace(":", "_").replace("/", "_") or "target"


# --------------------------------------------------------------------------- #
# accounts (the only step that may open a browser)
# --------------------------------------------------------------------------- #
def _headers_from_payload(payload: dict) -> dict:
    """Build auth headers from a login_capture payload ({bearer}/{cookie})."""
    if not isinstance(payload, dict):
        return {}
    if payload.get("bearer"):
        return {"Authorization": f"Bearer {payload['bearer']}"}
    if payload.get("cookie"):
        return {"Cookie": payload["cookie"]}
    return {}


def _headers_from_env(store, prefix: str) -> dict:
    if store.has(prefix + "_TOKEN"):
        return store.as_headers(prefix + "_TOKEN", header_type="bearer")
    if store.has(prefix + "_COOKIE"):
        return store.as_headers(prefix + "_COOKIE", header_type="cookie")
    return {}


def _default_login(login_url: str, name: str, out_dir: str = ".private") -> dict:
    """Open a real browser for the operator to log in; return the captured
    payload. Isolated here so tests can inject a fake and never open a browser."""
    from tools import login_capture
    rc = login_capture.capture(login_url, name, out_dir)
    path = os.path.join(out_dir, f"{name}.json")
    if rc == 0 and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except OSError:
            return {}
    return {}


def resolve_accounts(base_url: str, host: str, *, auth: bool, two_accounts: bool,
                     env: str, login_fn, log) -> "tuple[Account, Account]":
    """Decide A/B credentials. Prefer .env; only open a browser when auth is
    needed AND nothing is on file. Returns (account_a, account_b)."""
    from tools.credential_store import CredentialStore
    store = CredentialStore(env)

    a_hdr = _headers_from_env(store, "ACCOUNT_A")
    b_hdr = _headers_from_env(store, "ACCOUNT_B")

    if a_hdr:
        log("auth: using ACCOUNT_A from %s (no browser needed)" % env)
    elif auth and login_fn is not None:
        log("auth: no stored credentials -> opening a browser for you to log in (account A)")
        a_hdr = _headers_from_payload(login_fn(base_url, f"{_safe_name(host)}-A"))
        if two_accounts:
            log("auth: opening a browser for a SECOND account (B) to enable cross-account tests")
            b_hdr = b_hdr or _headers_from_payload(login_fn(base_url, f"{_safe_name(host)}-B"))
    else:
        log("auth: running UNAUTHENTICATED (no creds on file and auth disabled)")

    return (Account("A", a_hdr, store.get("ACCOUNT_A_ID", "") or ""),
            Account("B", b_hdr, store.get("ACCOUNT_B_ID", "") or ""))


# --------------------------------------------------------------------------- #
# report writing
# --------------------------------------------------------------------------- #
def _report_markdown(report: dict) -> str:
    tech = report.get("tech") or {}
    findings = report.get("findings") or []
    chains = report.get("chains") or []
    summary = report.get("ledger_summary") or {}
    lines = [
        f"# Hunt report — {report.get('target', '')}",
        "",
        f"- SPA: {tech.get('is_spa')}  |  JSON API: {tech.get('json_api')}  "
        f"|  server: {tech.get('server') or '-'}",
        f"- Findings: {len(findings)}  |  Chains: {len(chains)}  "
        f"|  Ledger complete: {summary.get('complete')}",
        "",
        "## Findings",
    ]
    if not findings:
        lines.append("_None survived validation._")
    for f in findings:
        sev = getattr(f, "severity", "info")
        conf = getattr(f, "confidence", "")
        cls = getattr(f, "cls", "?")
        title = getattr(f, "title", "")
        method = getattr(f, "method", "GET")
        url = getattr(f, "url", "")
        lines.append(f"- **[{sev}/{conf}] {cls}** — {title} (`{method} {url}`)")
    lines += ["", "## Coverage ledger", "```", summary.get("table", ""), "```"]
    return "\n".join(lines)


def _write_report(out_dir: str, report: dict, log) -> "tuple[str, str]":
    os.makedirs(out_dir, exist_ok=True)
    stamp = _dt.date.today().isoformat()
    json_path = os.path.join(out_dir, f"engine-report-{stamp}.json")
    md_path = os.path.join(out_dir, f"engine-report-{stamp}.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(engine._to_jsonable(report), fh, indent=2)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(_report_markdown(report))
    log("report: wrote %s and %s" % (json_path, md_path))
    return json_path, md_path


# --------------------------------------------------------------------------- #
# the orchestrator
# --------------------------------------------------------------------------- #
def run(target: str, *, scope_hosts=(), swagger=None, recon_dir=None,
        surface_graph=None, allow_write=True, auth=True, two_accounts=True,
        env=".env", out_dir=None, fetch=None, login_fn=_default_login,
        logger=None) -> dict:
    """Run the full autonomous hunt and return the engine report dict."""
    log = logger or (lambda m: print(f"[autohunt] {m}"))

    base_url, host = _normalise(target)
    scope = tuple(scope_hosts) or (host,)
    log(f"target: {base_url}  scope: {', '.join(scope)}  "
        f"mode: {'READ-ONLY' if not allow_write else 'FULL (writes capture+revert)'}")

    if fetch is None:
        fetch = engine._resolve_fetch(scope, engine._DEFAULT_TIMEOUT)

    # 2. recon -> endpoints
    endpoints = recon_feed.collect(base_url, scope, swagger=swagger,
                                   recon_dir=recon_dir, surface_graph=surface_graph,
                                   fetch=fetch)
    log(f"recon: {len(endpoints)} in-scope endpoint(s) gathered")

    # 3. auth (may open a browser — the only operator touchpoint)
    account_a, account_b = resolve_accounts(
        base_url, host, auth=auth, two_accounts=two_accounts,
        env=env, login_fn=login_fn, log=log,
    )

    # 4-6. build context, run the engine, write the report
    ctx = HuntContext(
        base_url=base_url, scope_hosts=scope,
        account_a=account_a, account_b=account_b,
        endpoints=endpoints, allow_write=allow_write, fetch=fetch,
    )
    try:
        from tools.hunter.kb import KnowledgeBase
        ctx.kb = KnowledgeBase()
    except Exception:
        pass

    log("hunt: running the full engine (all applicable depth kits)...")
    report = engine.run_hunt(ctx)

    out = out_dir or os.path.join("findings", _safe_name(host))
    _write_report(out, report, log)

    summary = report.get("ledger_summary") or {}
    log(f"done: {len(report.get('findings') or [])} finding(s), "
        f"{len(report.get('chains') or [])} chain(s), ledger complete={summary.get('complete')}")
    return report


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(
        prog="autohunt.py",
        description="Autonomous full-power hunt (opens a browser only to log in).",
    )
    ap.add_argument("target", nargs="?", help="target host or URL, e.g. https://api.target.com")
    ap.add_argument("--scope", default="", help="comma-separated in-scope hosts (default: the target host)")
    ap.add_argument("--swagger", help="OpenAPI/Swagger spec: a local file or a URL")
    ap.add_argument("--recon-dir", help="existing recon output directory to ingest")
    ap.add_argument("--surface-graph", help="path to a surface_graph.json")
    ap.add_argument("--safe", action="store_true", help="read-only hunt (disable all write probes)")
    ap.add_argument("--no-auth", action="store_true", help="do not attempt login / never open a browser")
    ap.add_argument("--one-account", action="store_true", help="capture only account A (skip the second login)")
    ap.add_argument("--env", default=".env", help="path to the .env credential file")
    ap.add_argument("--out", help="output directory for the report")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON at the end")
    args = ap.parse_args(argv)
    if not args.target:
        ap.error("target is required, e.g. https://api.target.com")

    scope = tuple(h.strip() for h in args.scope.split(",") if h.strip())
    report = run(
        args.target, scope_hosts=scope, swagger=args.swagger,
        recon_dir=args.recon_dir, surface_graph=args.surface_graph,
        allow_write=not args.safe, auth=not args.no_auth,
        two_accounts=not args.one_account, env=args.env, out_dir=args.out,
    )
    if args.json:
        print(json.dumps(engine._to_jsonable(report), indent=2))
    else:
        engine._print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
