#!/usr/bin/env python3
"""
spa_baseline.py - detect the "catch-all" response of an SPA / edge host.

Why this exists
---------------
On a single-page-app host (Vercel/Netlify/Next.js and friends) almost every
path - including random non-existent ones, ``/.git/HEAD``, ``/.env`` and
``/swagger.json`` - returns the SAME 200 HTML shell. Status-code and
reflection based scanners read that as "endpoint is live / file exists" and
either false-positive or give up. This module fingerprints the shell once, so
every scanner can ask "is this response just the catch-all?" and skip it.

How
---
``probe(fetch)`` requests a couple of deliberately non-existent paths and
records (status, body). A later response is the catch-all when, for one of the
samples, the status matches, the body length is within tolerance, and a
dynamic-token-stripped similarity ratio clears a threshold. Stripping digits
and long hex/uuid runs first means per-request nonces/CSRF tokens in the shell
don't defeat the match.

Use as a library::

    from spa_baseline import probe
    baseline = probe(lambda path: (r.status_code, r.text))   # your fetcher
    if baseline.is_catchall(resp.status_code, resp.text):
        continue  # not a real endpoint - skip

Or standalone::

    python tools/spa_baseline.py https://web.target.com/
"""
from __future__ import annotations

import argparse
import hashlib
import random
import re
import string
import sys
from difflib import SequenceMatcher

# Strip values that legitimately differ between two requests for the same
# shell: digit runs, long hex / uuid tokens (nonces, build ids, csrf tokens).
_DYNAMIC = re.compile(r"[0-9a-fA-F]{8,}|\d+")

# Only the first/last slice of a body is compared, so a huge JS bundle served
# as the shell can't blow up SequenceMatcher.
_CAP = 6000


def _normalise(body: str) -> str:
    if not body:
        return ""
    head = body[:_CAP]
    tail = body[-_CAP:] if len(body) > _CAP else ""
    return _DYNAMIC.sub("", head + tail)


def _rand_path() -> str:
    seg = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
    leaf = "".join(random.choices(string.ascii_lowercase, k=10))
    return f"/{seg}/does-not-exist-{leaf}"


class Baseline:
    """A fingerprint of a host's catch-all response(s)."""

    def __init__(self, samples: list[tuple[int, str]]):
        # samples: list of (status_code, body)
        self.samples = samples
        self._norm = [
            (status, _normalise(body), len(body or ""),
             hashlib.sha1(_normalise(body).encode("utf-8", "replace")).hexdigest())
            for status, body in samples
        ]
        self.active = len(samples) > 0

    def is_catchall(self, status: int, body: str | None,
                    ratio: float = 0.95, len_tol: float = 0.15) -> bool:
        """True when (status, body) looks like the recorded catch-all shell."""
        if not self.active or body is None:
            return False
        nb = _normalise(body)
        lb = len(body)
        nb_hash = hashlib.sha1(nb.encode("utf-8", "replace")).hexdigest()
        for s_status, s_norm, s_len, s_hash in self._norm:
            if status != s_status:
                continue
            if nb_hash == s_hash:           # identical shell, fast path
                return True
            if s_len and abs(lb - s_len) / max(s_len, 1) > len_tol:
                continue
            if SequenceMatcher(None, s_norm, nb).ratio() >= ratio:
                return True
        return False

    def summary(self) -> str:
        if not self.active:
            return "no baseline (host did not answer the probe)"
        parts = [f"status={s} bytes={ln}" for s, _, ln, _ in self._norm]
        return "catch-all shell: " + "; ".join(parts)


def probe(fetch, samples: int = 2) -> Baseline:
    """Build a Baseline by fetching ``samples`` random non-existent paths.

    ``fetch`` is a callable ``path -> (status:int, body:str) | None``. Returning
    None (network error) for a sample just drops it. Two differing random paths
    that both come back 200-with-the-same-body is the signature of a catch-all.
    """
    collected: list[tuple[int, str]] = []
    for _ in range(max(1, samples)):
        try:
            res = fetch(_rand_path())
        except Exception:
            res = None
        if res is not None:
            status, body = res
            collected.append((int(status), body or ""))
    return Baseline(collected)


def _cli_fetch(base: str):
    """Standalone fetcher using the SSRF-safe urllib wrapper when present."""
    import urllib.request
    from urllib.parse import urljoin
    try:
        from safe_http import safe_urlopen  # type: ignore
    except ImportError:
        safe_urlopen = None

    def fetch(path):
        url = urljoin(base, path.lstrip("/"))
        req = urllib.request.Request(url, headers={"User-Agent": "spa-baseline/1.0"})
        try:
            if safe_urlopen is not None:
                resp = safe_urlopen(req, timeout=10)
            else:  # pragma: no cover - safe_http ships alongside this file
                resp = urllib.request.urlopen(req, timeout=10)
            body = resp.read(200_000).decode("utf-8", "replace")
            return (getattr(resp, "status", 0) or getattr(resp, "code", 0), body)
        except Exception as exc:  # noqa: BLE001 - probe is best-effort
            code = getattr(exc, "code", None)
            if code is not None:
                try:
                    body = exc.read(200_000).decode("utf-8", "replace")  # type: ignore[attr-defined]
                except Exception:
                    body = ""
                return (code, body)
            return None

    return fetch


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="Fingerprint a host's SPA catch-all response")
    ap.add_argument("base", help="base URL, e.g. https://web.target.com/")
    ap.add_argument("--samples", type=int, default=2, help="random probe paths (default 2)")
    args = ap.parse_args(argv)

    base = args.base if args.base.endswith("/") else args.base + "/"
    baseline = probe(_cli_fetch(base), samples=args.samples)
    print(f"[spa-baseline] {args.base}")
    print(f"  {baseline.summary()}")
    if baseline.active:
        # Re-probe one more random path and show the verdict as a sanity check.
        extra = _cli_fetch(base)(_rand_path())
        if extra is not None:
            verdict = baseline.is_catchall(extra[0], extra[1])
            print(f"  fresh random path -> is_catchall={verdict} "
                  f"(status={extra[0]}, bytes={len(extra[1])})")
        print("  => scanners should treat matching responses as noise, not findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
