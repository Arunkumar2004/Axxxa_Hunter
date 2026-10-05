#!/usr/bin/env python3
"""
cloud_bucket_enum.py - Public cloud bucket enumeration (S3/GCS/Azure).

Zero credentials. Generates bucket-name candidates from a domain (and any
extra --names), checks DNS resolution and anonymous HTTP listing, and flags:
  PUBLIC-READ   (200 with object listing)
  PUBLIC-WRITE  (PUT accepted - only reports, never leaves data)
  TAKEOVER      (dangling DNS name, provider says NoSuchBucket/NotFound)

Usage:
  python tools/cloud_bucket_enum.py example.com
  python tools/cloud_bucket_enum.py example.com --names media,static,assets
  python tools/cloud_bucket_enum.py example.com --all

Cross-platform: requests + socket. Read-only by default (PUT only with --test-write).
"""

import argparse
import json
import re
import socket
import sys
import urllib.parse

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    sys.exit(1)

TIMEOUT = 8
UA = "cloud-bucket-enum/1.0"

# getaddrinfo() ignores per-call timeouts; bound every DNS/socket op globally.
socket.setdefaulttimeout(5)

PROVIDERS = [
    {"name": "s3", "host": "{b}.s3.amazonaws.com", "list_url": "https://{b}.s3.amazonaws.com/?list-type=2",
     "notfound": ["nosuchbucket", "nosuchkey", "accessdenied but bucket does not exist"],
     "takeover_sig": ["nosuchbucket"]},
    {"name": "s3-ws", "host": "{b}.s3-website-{r}.amazonaws.com", "list_url": None,
     "notfound": ["nosuchbucket"], "takeover_sig": ["nosuchbucket"]},
    {"name": "gcs", "host": "storage.googleapis.com", "list_url": "https://storage.googleapis.com/{b}/?prefix=",
     "notfound": ["no such object", "not found"], "takeover_sig": ["no such object"]},
    {"name": "azure", "host": "{b}.blob.core.windows.net", "list_url": "https://{b}.blob.core.windows.net/?restype=container&comp=list",
     "notfound": ["resourcenotfound", "container not found", "cannot find", "not found"],
     "takeover_sig": ["resourcenotfound", "containernotfound"]},
    {"name": "digitalocean", "host": "{b}.{r}.digitaloceanspaces.com", "list_url": "https://{b}.{r}.digitaloceanspaces.com/?list-type=2",
     "notfound": ["nosuchbucket"], "takeover_sig": ["nosuchbucket"]},
]

REGIONS = ["us-east-1", "eu-west-1", "ap-southeast-1"]


def candidates_for_domain(domain):
    name = domain.split(".")[0]
    clean = re.sub(r"[^a-z0-9-]", "", name.lower())
    base = clean or name
    perms = []
    for sep in ["", "-", "."]:
        for tail in ["", "-dev", "-prod", "-assets", "-media", "-backup", "-static",
                     "-staging", "-test", "-uploads", "-files", "-data", "-cdn",
                     "-production", "-store", "-img", "-downloads", "-public"]:
            perms.append(f"{base}{sep}{tail}".strip(".-"))
    # also full domain forms
    perms += [domain.replace(".", "-"), domain]
    return sorted(set(p for p in perms if p))


def resolve(host):
    # socket.getaddrinfo() takes no timeout kwarg (passing one raised TypeError,
    # which the broad except swallowed so every lookup silently "failed"). Bound
    # the lookup with a module-level default socket timeout instead.
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False


def check_provider(sc, bucket, prov):
    out = {"bucket": bucket, "provider": prov["name"], "dns": False, "list": None,
           "status": "not-found"}
    # Both host and list_url may contain a {r} region placeholder (s3-website,
    # digitalocean). Formatting list_url with b= only raised KeyError: 'r'.
    region = REGIONS[0]
    host = prov["host"].format(b=bucket, r=region)
    out["dns"] = resolve(host)
    if not prov.get("list_url"):
        return out
    url = prov["list_url"].format(b=bucket, r=region)
    try:
        r = sc.get(url, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return out
    out["status_code"] = r.status_code
    low = r.text[:400].lower()
    if r.status_code == 200:
        keys = len(re.findall(r"<Key>", r.text)) or (1 if "<Contents>" in r.text else 0)
        out["status"] = "PUBLIC-READ"
        out["objects_visible"] = keys
    elif r.status_code in (403, 401):
        if any(s in low for s in prov.get("takeover_sig", [])):
            out["status"] = "TAKEOVER-CANDIDATE"
        else:
            out["status"] = "exists-private"
    elif r.status_code == 404:
        out["status"] = "TAKEOVER-CANDIDATE" if any(s in low for s in prov.get("takeover_sig", [])) else "not-found"
    return out


def main():
    ap = argparse.ArgumentParser(description="Public bucket enumeration")
    ap.add_argument("target", help="domain or company name")
    ap.add_argument("--names", help="comma-separated extra bucket names")
    ap.add_argument("--all", action="store_true", help="test all permutations (slower)")
    ap.add_argument("--test-write", action="store_true",
                    help="PUT a canary object to confirm public write (removes it after)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    sc = requests.Session()
    sc.headers["User-Agent"] = UA

    names = set(candidates_for_domain(args.target))
    if args.names:
        for n in args.names.split(","):
            names.add(n.strip().lower())
    if not args.all:
        # keep the high-probability subset for speed
        names = set(list(names)[:60])

    results = []
    for b in sorted(names):
        for prov in PROVIDERS:
            res = check_provider(sc, b, prov)
            if res["status"] in ("PUBLIC-READ", "TAKEOVER-CANDIDATE", "exists-private"):
                results.append(res)
                if res["status"] == "PUBLIC-READ" and args.test_write:
                    canary = f"bbhunt-canary-{int(__import__('time').time())}.txt"
                    base_url = prov["list_url"].format(b=b, r=REGIONS[0]).split("?")[0]
                    try:
                        put = sc.put(base_url + f"/{canary}",
                                     data="probe", timeout=TIMEOUT)
                        if put.status_code in (200, 204):
                            res["status"] = "PUBLIC-WRITE"
                            sc.delete(base_url + f"/{canary}")
                    except requests.RequestException:
                        pass

    if args.json:
        print(json.dumps(results, indent=2))
        return

    print(f"\n[+] Bucket enumeration: {args.target}")
    if not results:
        print("    No public/exposed buckets found.")
    for r in results:
        print(f"  [!] {r['status']:<18} {r['bucket']} ({r['provider']}) dns={r['dns']} "
              f"objects={r.get('objects_visible', '-')}")
    print("\n[!] PUBLIC-READ/TAKEOVER need manual verification (see cloud-security skill).")


if __name__ == "__main__":
    main()
