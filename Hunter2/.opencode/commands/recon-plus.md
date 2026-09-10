---
description: Recon power tools - favicon-hash pivot (Shodan/Censys/FOFA), JS source-map extraction (recover original source + secrets + endpoints), and OpenAPI/Swagger -> auto IDOR/BOLA test generation. Usage: /recon-plus favicon <url> | /recon-plus sourcemap <js-url> -o out/ | /recon-plus idor <spec>
---

# /recon-plus

Three high-yield recon pivots that turn one known asset into new attack surface.

## favicon-hash pivot
```bash
tools/favicon_hash.py https://target.com
```
Computes the Shodan mmh3 favicon hash and prints Shodan/Censys/FOFA/ZoomEye
queries. Find shadow infra, staging clones, and CDN-hidden origin servers that
serve the same favicon.

## JS source-map extraction
```bash
tools/sourcemap_extract.py https://target.com/static/app.min.js -o out/
```
If a `.map` ships (common misconfig), recovers the ORIGINAL source tree and greps
it for hardcoded secrets, internal endpoints, and full URLs the minified bundle hid.

## API-spec -> IDOR/BOLA tests
```bash
tools/apispec_idor.py https://target.com/swagger.json --sh --token-a "$A" --token-b "$B" > idor.sh
```
Parses OpenAPI/Swagger, finds every endpoint carrying an object id
(`/users/{id}`, `?account_id=`), and emits an account-A-vs-account-B test plan —
diff the responses for missing object-level authorization.

## Chain
favicon pivot -> new hosts -> recon -> hunt. Source-map secrets -> direct auth /
API access. Spec IDOR plan -> feed confirmed hits to `business-logic-hunter`.
