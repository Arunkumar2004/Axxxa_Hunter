#!/usr/bin/env python3
"""
JavaScript source-map extractor.

Production JS bundles are minified, but if a `.map` is shipped (very common on
misconfigured deploys) it contains the ORIGINAL source — often with comments,
internal endpoints, feature flags, and hardcoded secrets the minified bundle
hides. This tool finds the map, downloads it, reconstructs the original file
tree, and greps the recovered source for endpoints and secrets.

The map parsing / secret scan is pure and unit-tested; only fetching is networked.

Usage:
  tools/sourcemap_extract.py https://target.com/static/app.min.js
  tools/sourcemap_extract.py https://target.com/static/app.min.js.map -o out/
  tools/sourcemap_extract.py --file app.js.map -o out/
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from tools.safe_http import safe_urlopen
except Exception:  # pragma: no cover
    safe_urlopen = None

_SECRET = re.compile(
    r"(?i)(api[_-]?key|secret|token|passwd|password|aws_access_key_id|"
    r"bearer\s+[a-z0-9._-]{10,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|"
    r"AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{10,}|ghp_[0-9A-Za-z]{36})")
_ENDPOINT = re.compile(r"""["'`](/(?:api|v[0-9]|graphql|internal|admin|rest)[A-Za-z0-9/_\-.{}$:]*)["'`]""")
_URL = re.compile(r"https?://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9/_\-.?=&%]*)?")


def parse_sourcemap(text: str) -> dict:
    """Pure: return {path: content} from a source map JSON string."""
    data = json.loads(text)
    sources = data.get("sources", []) or []
    contents = data.get("sourcesContent", []) or []
    out: dict[str, str] = {}
    for i, src in enumerate(sources):
        content = contents[i] if i < len(contents) and contents[i] is not None else ""
        # Normalise the webpack-style path into a safe relative path.
        clean = re.sub(r"^(webpack://|\.{1,2}/|/)+", "", src).replace("\\", "/")
        clean = re.sub(r"[?#].*$", "", clean) or f"source_{i}.js"
        clean = "/".join(p for p in clean.split("/") if p not in ("", "..", "."))
        out[clean or f"source_{i}.js"] = content
    return out


def scan_sources(files: dict[str, str]) -> dict[str, list[str]]:
    """Pure: grep recovered sources for secrets, endpoints, and URLs."""
    secrets, endpoints, urls = set(), set(), set()
    for content in files.values():
        for m in _SECRET.finditer(content):
            secrets.add(m.group(0)[:120])
        for m in _ENDPOINT.finditer(content):
            endpoints.add(m.group(1))
        for m in _URL.finditer(content):
            urls.add(m.group(0)[:200])
    return {"secrets": sorted(secrets), "endpoints": sorted(endpoints), "urls": sorted(urls)}


def _fetch(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (BugHunter sourcemap)"})
    opener = safe_urlopen if safe_urlopen else urllib.request.urlopen
    return opener(req, timeout=timeout).read(20_000_000).decode("utf-8", "replace")


def find_map_url(js_url: str, js_body: str) -> str | None:
    m = re.search(r"//[#@]\s*sourceMappingURL=(\S+)", js_body)
    if m:
        return urljoin(js_url, m.group(1).strip())
    return None


def extract(url: str, out_dir: str | None, timeout: int = 15) -> dict:
    if url.endswith(".map"):
        map_text = _fetch(url, timeout)
    else:
        js = _fetch(url, timeout)
        map_url = find_map_url(url, js) or (url + ".map")
        map_text = _fetch(map_url, timeout)
    files = parse_sourcemap(map_text)
    written = 0
    if out_dir:
        for path, content in files.items():
            dest = os.path.normpath(os.path.join(out_dir, path))
            if not dest.startswith(os.path.normpath(out_dir)):  # path-traversal guard
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(content)
            written += 1
    return {"files": len(files), "written": written, **scan_sources(files)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="JS source-map extractor")
    ap.add_argument("url", nargs="?", help="URL to a .js or .js.map")
    ap.add_argument("--file", help="parse a local .map file instead")
    ap.add_argument("-o", "--out", help="directory to reconstruct original sources into")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.file:
        files = parse_sourcemap(open(args.file, encoding="utf-8").read())
        if args.out:
            for path, content in files.items():
                dest = os.path.normpath(os.path.join(args.out, path))
                if not dest.startswith(os.path.normpath(args.out)):
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                open(dest, "w", encoding="utf-8").write(content)
        result = {"files": len(files), "written": len(files) if args.out else 0, **scan_sources(files)}
    elif args.url:
        try:
            result = extract(args.url, args.out, args.timeout)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError, ValueError, json.JSONDecodeError) as e:
            print(f"[sourcemap] failed: {e}", file=sys.stderr)
            return 1
    else:
        ap.error("provide a URL or --file")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"recovered {result['files']} source files"
              + (f" -> {args.out} ({result['written']} written)" if args.out else ""))
        for k in ("secrets", "endpoints", "urls"):
            if result[k]:
                print(f"\n[{k}] ({len(result[k])})")
                for v in result[k][:40]:
                    print(f"  {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
