---
description: Static-first mobile app scan for APK/IPA in bug bounty scope. Wires apkleaks (secrets + hidden API endpoints), MobSF/mobsfscan (static SAST), and objection (SSL-pinning bypass for runtime proxying). Use when program scope includes a mobile app or web recon dries up and you need fresh attack surface. Usage: /mobile-scan <app.apk> [--patch]
---

# /mobile-scan

Automated static sweep + pinning-bypass prep for a mobile app. Complements the
runtime-first `mobile-pentest` skill: this is the fast, no-device step that
extracts hidden endpoints and gets pinned traffic flowing.

## Usage

```bash
./tools/mobile_scan.sh <app.apk>                       # apkleaks + mobsfscan
./tools/mobile_scan.sh <app.apk> --patch               # + objection SSL-pin bypass
./tools/mobile_scan.sh <app.apk> --output-dir ./findings/target/mobile
```

## What it does

1. **apkleaks** — hardcoded secrets + hidden API endpoints / base URLs. The
   recovered `endpoints.txt` is fresh attack surface — feed it straight to `/hunt`.
2. **mobsfscan** (or MobSF server) — static SAST: insecure storage, weak crypto,
   exported activities, WebView bridges.
3. **objection patchapk** (`--patch`) — bypasses SSL pinning so you can proxy the
   app through Burp/mitmproxy and test its API like a web target.

Missing tools are skipped with an install hint, never a hard failure.
Install: `python tools/arsenal.py install --profile mobile --yes`
(or `pipx install apkleaks mobsf mobsfscan objection`).

## Scope

Only run against apps whose parent program is confirmed in-scope by the
`scope-checker`. Decompiling and traffic-proxying a third-party app is not
authorized by the web program's scope alone.

## Next steps

After extracting endpoints, run `/hunt` against them and follow the
`mobile-pentest` skill for runtime IDOR / auth-bypass / business-logic testing.
