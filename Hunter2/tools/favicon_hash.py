#!/usr/bin/env python3
"""
Favicon-hash recon pivot.

Computes the Shodan-style favicon hash (MurmurHash3 x86_32 over the base64 of the
favicon bytes) so you can pivot from one known asset to every other host on the
internet that serves the same favicon — a fast way to find shadow infra, staging
copies, and origin servers hiding behind a CDN.

MurmurHash3 is implemented in pure Python (no mmh3 dependency); the hash function
is pure and unit-tested. Only `fetch_favicon()` touches the network.

Outputs ready-to-run Shodan and Censys queries.

Usage:
  tools/favicon_hash.py https://target.com
  tools/favicon_hash.py https://target.com/favicon.ico --json
  tools/favicon_hash.py --file downloaded.ico
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from tools.safe_http import safe_urlopen
except Exception:  # pragma: no cover - safe_http always present in repo
    safe_urlopen = None


def _rotl32(x: int, r: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure MurmurHash3 x86_32. Returns the SIGNED 32-bit int Shodan uses."""
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1, c2 = 0xCC9E2D51, 0x1B873593

    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = _rotl32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = _rotl32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convert to signed 32-bit (Shodan reports the signed value).
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def shodan_favicon_hash(raw: bytes) -> int:
    """Shodan's exact recipe: mmh3 over the base64 (with 76-col newlines) of the bytes."""
    b64 = base64.encodebytes(raw)  # inserts a newline every 76 chars + trailing \n
    return murmur3_x86_32(b64)


def fetch_favicon(url: str, timeout: int = 15) -> bytes:
    if not url.endswith((".ico", ".png")) and "favicon" not in url:
        url = urljoin(url if url.endswith("/") else url + "/", "favicon.ico")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (BugHunter favicon)"})
    opener = safe_urlopen if safe_urlopen else urllib.request.urlopen
    resp = opener(req, timeout=timeout)
    return resp.read(2_000_000)


def queries(h: int) -> dict[str, str]:
    return {
        "shodan": f'http.favicon.hash:{h}',
        "shodan_cli": f'shodan search http.favicon.hash:{h}',
        "censys": f'services.http.response.favicons.md5_hash:  (use FavFreak/Shodan hash {h})',
        "fofa": f'icon_hash="{h}"',
        "zoomeye": f'iconhash:"{h}"',
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Favicon-hash recon pivot (Shodan/Censys/FOFA)")
    ap.add_argument("url", nargs="?", help="site or favicon URL")
    ap.add_argument("--file", help="hash a local favicon file instead of fetching")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.file:
        with open(args.file, "rb") as fh:
            raw = fh.read()
    elif args.url:
        try:
            raw = fetch_favicon(args.url, args.timeout)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError, ValueError) as e:
            print(f"[favicon] fetch failed: {e}", file=sys.stderr)
            return 1
    else:
        ap.error("provide a URL or --file")

    h = shodan_favicon_hash(raw)
    q = queries(h)
    if args.json:
        print(json.dumps({"hash": h, "queries": q}, indent=2))
    else:
        print(f"favicon hash (Shodan mmh3): {h}")
        for k, v in q.items():
            print(f"  {k:10s}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
