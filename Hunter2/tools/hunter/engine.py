#!/usr/bin/env python3
"""Hunter Engine — the driver that runs the expert loop over the depth kits.

Responsibilities (kept deliberately small; the kits do the deep work):

  * ``discover_kits()``  — scan ``tools/hunter/kits/*.py``, import each by file
    path (every kit self-registers), and return the shared registry. A kit that
    fails to import is logged and skipped, never fatal.
  * ``build_context(...)`` — assemble a :class:`HuntContext`: credentials for
    accounts A/B (optional), scope, and an injected SSRF-safe ``fetch``.
  * ``run_hunt(ctx)`` — model the target, run every applicable kit, drive the
    coverage ledger, then (if present) chain and gate the findings. Returns a
    report dict.
  * ``main()`` — a small CLI.

Everything degrades gracefully: the sibling harness modules (``net.py``,
``chain.py``, ``validate_gate.py``) and the kit files are built in parallel, so
they are all imported defensively. The engine and its tests pass standalone.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools.hunter import contract, target_model  # noqa: E402
from tools.hunter.contract import Account, HuntContext, Resp  # noqa: E402
from tools.hunter.ledger import CoverageLedger  # noqa: E402

log = logging.getLogger("hunter.engine")

_USER_AGENT = "hunter-engine/1.0"
_DEFAULT_TIMEOUT = 15


# --------------------------------------------------------------------------- #
# Kit discovery                                                               #
# --------------------------------------------------------------------------- #
def discover_kits(kits_dir: "str | Path | None" = None) -> dict:
    """Import every kit module under ``kits_dir`` and return the registry.

    Kits self-register at import time (``contract.register(...)``), so importing
    the file is all it takes. Import failures are logged and skipped so one
    broken kit cannot sink the whole run.
    """
    directory = Path(kits_dir) if kits_dir is not None else Path(__file__).parent / "kits"
    if directory.is_dir():
        for pyfile in sorted(directory.glob("*.py")):
            if pyfile.name.startswith("_"):
                continue
            modname = f"tools.hunter.kits.{pyfile.stem}"
            try:
                spec = importlib.util.spec_from_file_location(modname, str(pyfile))
                if spec is None or spec.loader is None:
                    log.warning("skipping kit %s: no import spec", pyfile.name)
                    continue
                module = importlib.util.module_from_spec(spec)
                sys.modules[modname] = module
                spec.loader.exec_module(module)
            except Exception as exc:  # noqa: BLE001 - one bad kit must not abort
                sys.modules.pop(modname, None)
                log.warning("skipping kit %s (failed to import): %s", pyfile.name, exc)
    else:
        log.warning("kits directory not found: %s", directory)
    return contract.registry()


# --------------------------------------------------------------------------- #
# Fetch resolution                                                            #
# --------------------------------------------------------------------------- #
def _scope_check_factory(scope_hosts: tuple):
    def _check(host: str) -> bool:
        if not scope_hosts:
            return True
        host = (host or "").lower().rstrip(".")
        return any(
            host == h or host.endswith("." + h)
            for h in (s.lower().lstrip("*.") for s in scope_hosts)
        )

    return _check


def _make_safe_fetch(scope_hosts: tuple, timeout: int):
    """A minimal SSRF-safe ``fetch`` built on ``tools/safe_http.safe_urlopen``.

    Used as the fallback until the harness's ``tools/hunter/net.py`` lands. The
    SSRF guard (private/loopback/metadata block) is always on; redirects are
    additionally held to program scope when ``scope_hosts`` is set.
    """
    import time
    import urllib.error
    import urllib.request

    from tools.safe_http import safe_urlopen

    scope_check = _scope_check_factory(tuple(scope_hosts or ()))

    def fetch(method, url, headers=None, body=None):
        method = (method or "GET").upper()
        hdrs = {"User-Agent": _USER_AGENT}
        if headers:
            hdrs.update(headers)
        data = None
        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode("utf-8")
                hdrs.setdefault("Content-Type", "application/json")
            elif isinstance(body, str):
                data = body.encode("utf-8")
            elif isinstance(body, bytes):
                data = body
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        t0 = time.perf_counter()
        try:
            resp = safe_urlopen(req, timeout=timeout, scope_check=scope_check)
            raw = resp.read(2_000_000)  # cap the fallback read so a huge body can't exhaust memory
            elapsed = (time.perf_counter() - t0) * 1000.0
            rbody = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
            status = getattr(resp, "status", None) or getattr(resp, "code", 0) or 0
            rheaders = {k: v for k, v in (getattr(resp, "headers", None) or {}).items()}
            return Resp(status=int(status), body=rbody, headers=rheaders, elapsed_ms=elapsed)
        except urllib.error.HTTPError as exc:
            elapsed = (time.perf_counter() - t0) * 1000.0
            try:
                rbody = exc.read().decode("utf-8", "replace")
            except Exception:
                rbody = ""
            rheaders = {k: v for k, v in (getattr(exc, "headers", None) or {}).items()}
            return Resp(status=int(getattr(exc, "code", 0) or 0), body=rbody, headers=rheaders, elapsed_ms=elapsed)
        except Exception:
            # Network/DNS/SSRF-guard failure: a dead or disallowed host must
            # never abort a run (contract: return None).
            return None

    return fetch


def _resolve_fetch(scope_hosts: tuple, timeout: int):
    """Prefer the harness fetch from ``net.py``; fall back to the safe fetch.

    ``net.default_fetch`` may be a ready ``Fetch`` or a factory that takes
    configuration and returns one; both shapes are handled, and anything else
    falls back to the local safe fetch.
    """
    try:
        from tools.hunter import net as _net  # built in parallel; optional
    except Exception:
        _net = None

    if _net is not None:
        factory = getattr(_net, "default_fetch", None)
        if callable(factory):
            for kwargs in (
                {"scope_hosts": scope_hosts, "timeout": timeout},
                {"scope_hosts": scope_hosts},
                {"timeout": timeout},
                {},
            ):
                try:
                    candidate = factory(**kwargs)
                except TypeError:
                    continue
                except Exception as exc:  # noqa: BLE001
                    log.warning("net.default_fetch factory failed: %s", exc)
                    break
                if callable(candidate):
                    return candidate
            # Could not build via a factory signature: use it directly as Fetch.
            return factory

    return _make_safe_fetch(scope_hosts, timeout)


# --------------------------------------------------------------------------- #
# Context                                                                     #
# --------------------------------------------------------------------------- #
def _account_headers(store, prefix: str) -> dict:
    """Auth headers for one account: prefer a bearer TOKEN, else a COOKIE."""
    if store.has(prefix + "_TOKEN"):
        return store.as_headers(prefix + "_TOKEN", header_type="bearer")
    if store.has(prefix + "_COOKIE"):
        return store.as_headers(prefix + "_COOKIE", header_type="cookie")
    return {}


def build_context(base_url: str, allow_write: bool = False,
                  scope_hosts: tuple = (), env: str = ".env") -> HuntContext:
    """Assemble a :class:`HuntContext` ready to hand to :func:`run_hunt`."""
    from tools.credential_store import CredentialStore

    store = CredentialStore(env)
    account_a = Account("A", _account_headers(store, "ACCOUNT_A"), store.get("ACCOUNT_A_ID", "") or "")
    account_b = Account("B", _account_headers(store, "ACCOUNT_B"), store.get("ACCOUNT_B_ID", "") or "")

    scope = tuple(scope_hosts or ())
    fetch = _resolve_fetch(scope, _DEFAULT_TIMEOUT)

    ctx = HuntContext(
        base_url=base_url,
        scope_hosts=scope,
        account_a=account_a,
        account_b=account_b,
        allow_write=bool(allow_write),
        timeout=_DEFAULT_TIMEOUT,
        fetch=fetch,
    )

    # Attach the knowledge base (deep per-class checklists) so kits and the
    # report can follow an expert methodology. Optional: absence is non-fatal.
    try:
        from tools.hunter.kb import KnowledgeBase
        ctx.kb = KnowledgeBase()
    except Exception:
        pass

    return ctx


# --------------------------------------------------------------------------- #
# The hunt                                                                    #
# --------------------------------------------------------------------------- #
def _run_optional(modname: str, func: str, findings: list, ctx):
    """Import ``tools.hunter.<modname>`` defensively and call ``func``.

    Tries a couple of plausible signatures ``(findings, ctx)`` then
    ``(findings,)``. Returns whatever the callable returned, or None if the
    module/function is absent or raised.
    """
    try:
        module = __import__(f"tools.hunter.{modname}", fromlist=[func])
    except Exception:
        return None
    fn = getattr(module, func, None)
    if not callable(fn):
        return None
    for args in ((findings, ctx), (findings,)):
        try:
            return fn(*args)
        except TypeError:
            continue
        except Exception as exc:  # noqa: BLE001
            log.warning("tools.hunter.%s.%s failed: %s", modname, func, exc)
            return None
    return None


def run_hunt(ctx, kits: "dict | None" = None) -> dict:
    """Run the full loop against ``ctx`` and return a report dict.

    Report shape: ``{target, tech, findings, chains, ledger_summary}``.
    """
    # 1. Understand the target.
    target_model.build(ctx)

    # 2. Coverage ledger.
    ledger = CoverageLedger()

    # 3. Select + go deep.
    if kits is None:
        kits = discover_kits()

    findings: list = []
    all_declared: set = set()
    applied_classes: set = set()   # classes of kits that were applicable and ran

    for name, kit in kits.items():
        classes = tuple(getattr(kit, "classes", ()) or ())
        all_declared.update(classes)

        try:
            applicable = bool(kit.applicable(ctx))
        except Exception as exc:  # noqa: BLE001
            log.warning("kit %s applicable() raised: %s", name, exc)
            continue
        if not applicable:
            continue

        for cls in classes:
            ledger.start(cls)

        try:
            kit_findings = list(kit.run(ctx) or [])
        except Exception as exc:  # noqa: BLE001
            log.warning("kit %s run() raised: %s", name, exc)
            for cls in classes:
                ledger.blocked(cls, f"kit {name} raised during run: {exc}")
            continue

        findings.extend(kit_findings)
        applied_classes.update(classes)

    # 4. Validate FIRST, then mark the ledger from the SURVIVORS. Marking before
    #    the 7-question gate would let a class read FOUND on the strength of a
    #    finding the gate later killed as a false positive; this keeps the
    #    coverage ledger honest.
    gated = _run_optional("validate_gate", "apply", findings, ctx)
    if isinstance(gated, tuple) and gated and isinstance(gated[0], list):
        findings = gated[0]
    elif isinstance(gated, list):
        findings = gated

    surviving_classes = {getattr(f, "cls", None) for f in findings}
    surviving_classes.discard(None)
    for cls in surviving_classes:            # a surviving finding => FOUND
        ledger.start(cls)
        ledger.found(cls)
    for cls in applied_classes:              # ran, nothing survived => TESTED_DEEP
        if cls not in surviving_classes:
            ledger.tested(cls)

    # 5. Resolve everything still untouched, with an honest reason (no silent
    #    skips). A class a kit declared but was not applicable reads differently
    #    from one no kit covers at all.
    for cls in list(ledger.pending()):
        if cls in all_declared:
            ledger.na(cls, "a kit declares this class but was not applicable to this surface")
        else:
            ledger.na(cls, "no registered kit covers this class yet")

    # 6. Chain over the SURVIVING findings only (killed false positives excluded).
    chains = _run_optional("chain", "build_chains", findings, ctx) or []

    return {
        "target": ctx.base_url,
        "tech": ctx.tech,
        "findings": findings,
        "chains": chains,
        "ledger_summary": ledger.summary(),
    }


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #
def _force_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _to_jsonable(obj):
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _print_report(report: dict) -> None:
    tech = report.get("tech") or {}
    findings = report.get("findings") or []
    chains = report.get("chains") or []
    summary = report.get("ledger_summary") or {}

    print(f"Target : {report.get('target', '')}")
    print(
        "Tech   : "
        f"spa={tech.get('is_spa')} json_api={tech.get('json_api')} "
        f"server={tech.get('server') or '-'} powered_by={tech.get('powered_by') or '-'}"
    )
    detected = tech.get("detected") or []
    if detected:
        print("Stack  : " + ", ".join(detected))

    print(f"\nFindings ({len(findings)}):")
    if not findings:
        print("  (none)")
    for f in findings:
        sev = getattr(f, "severity", "info")
        conf = getattr(f, "confidence", "tentative")
        cls = getattr(f, "cls", "?")
        title = getattr(f, "title", "")
        method = getattr(f, "method", "GET")
        url = getattr(f, "url", "")
        print(f"  [{sev}/{conf}] {cls}: {title} ({method} {url})".rstrip())

    print(f"\nChains : {len(chains)}")

    print("\nCoverage ledger:")
    print(summary.get("table", ""))
    print(f"\nComplete: {summary.get('complete')}")


def main(argv: "list | None" = None) -> int:
    _force_utf8()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    ap = argparse.ArgumentParser(
        prog="engine.py",
        description="Hunter Engine — drive the depth kits against a target.",
    )
    ap.add_argument("base_url", nargs="?", help="target base URL, e.g. https://api.target.com/")
    ap.add_argument("--allow-write", action="store_true",
                    help="permit state-changing probes (kits capture+revert); off by default")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON output")
    ap.add_argument("--scope", default="", help="comma-separated in-scope hosts (safety gate)")
    ap.add_argument("--env", default=".env", help="path to the .env credential file (default: .env)")
    args = ap.parse_args(argv)

    if not args.base_url:
        ap.error("base_url is required (e.g. https://api.target.com/)")

    scope = tuple(h.strip() for h in args.scope.split(",") if h.strip())
    ctx = build_context(args.base_url, allow_write=args.allow_write, scope_hosts=scope, env=args.env)
    report = run_hunt(ctx)

    if args.json:
        print(json.dumps(_to_jsonable(report), indent=2))
    else:
        _print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
