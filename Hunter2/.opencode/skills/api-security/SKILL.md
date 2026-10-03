---
name: api-security
description: Use when testing any API - REST, GraphQL, gRPC, mobile backends, SPA API layers, or when the user says "api", "endpoint", "BOLA", "IDOR", "mass assignment", "BFLA". Full OWASP API Security Top 10 2023 methodology with per-category test checklists, payloads, tool routing, and confirmation rules.
---

# API Security (OWASP API Top 10 2023)

APIs are the #1 source of reportable bugs. Authorization bugs are invisible to scanners — you hunt them manually.

## Phase 0: Map the API (10 min)

1. **Specs**: `GET /swagger.json`, `/swagger-ui`, `/api-docs`, `/openapi.json`, `/v3/api-docs`, `/redoc`, `/graphql` (introspection), Postman collections in JS bundles (`linkfinder`/`gau`).
2. **Discover endpoints**: JS bundle grep for `/api/`, `fetch(`, `axios.`, `$.ajax`; `gau`/`katana` crawl; `param_discovery.sh` (Arjun/x8).
3. **Infer REST patterns**: `/users/{id}`, `/orders/{id}`, `/v1/...` vs `/v2/...`, admin endpoints, internal services (`/internal`, `/admin`, `/debug`).
4. **Fingerprint auth**: bearer, cookie, API key header, basic, mutual TLS, OAuth2.

## API1 BOLA / IDOR (highest value)

- Every ID param: swap for another user's ID. Numeric: ±1. GUID: use leaked GUIDs (from emails/receipts/public pages). Encoded: base64/hex/GUID-no-dashes variants.
- **Two-identity test is gold**: account A owns resource, account B requests it. B gets A's data → CONFIRMED.
- GraphQL: `user(id: 12){...}` → `user(id: 13)`; alias batching.
- Filter bypass: `?user_id=me` → `?user_id=admin`, path `/api/users/me` → `/api/users/1`.
- Only valid if response contains the **foreign object data**.

## API2 Broken Authentication

- JWT: `alg:none`, RS256→HS256, weak secret crack (`jwt_scanner.py`), `kid` path traversal, missing `exp`, no `aud` check, token in URL.
- OAuth: state CSRF, redirect_uri open redirect, scope escalation, token leakage via referrer.
- Password reset: token predictability (incrementing, timestamp, short), token reuse, no invalidation.
- 2FA: bypass on API endpoints (mobile app skips OTP), response manipulation (change `"2fa":true` → `false`), rate limit on OTP (brute-force 4-6 digits), OTP reuse across sessions.
- Rate limit / lockout: username enumeration via different error messages/timing.

## API3 BOPLA / Mass Assignment

- Response oversharing: look for extra fields (`email`, `ssn`, `internal_id`, `role`, `credit_card`).
- Mass assignment: POST/PUT/PATCH with extra keys: `{"role":"admin"}`, `{"is_admin":true}`, `{"balance":1000000}`, `{"verified":true}`, `{"price":0.01}`, `{"status":"approved"}`.
- Content-type tricks: send as `application/x-www-form-urlencoded` when API expects JSON (framework binding mismatch), `__proto__`/`constructor` keys, array injection `"roles":["admin"]`.

## API4 Unrestricted Resource Consumption

- No rate limit: brute-forceable OTP/login, enumeration.
- Large payloads: JSON depth, XML billion laughs, regex bombs, pagination abuse (`?page=1&size=1000000`).
- GraphQL: batching 1000s of aliases → DoS; field duplication.
- Report only if no compensating limits.

## API5 BFLA

- Method escalation: `GET /users` → `PUT /users`, `POST /users/delete`, `DELETE` on read-only endpoint.
- Path swap: `/user/me` → `/user/admin`, `/v1/user` → `/v2/user`.
- Header/method override: `X-HTTP-Method-Override: DELETE`, `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`.
- Role param: `"role":"admin"` in request, `?as_user=admin`.

## API6 Unrestricted Access to Sensitive Business Flows

- Automated abuse: free trial reset (`/cancel` then new trial), unlimited invites, coupon code reuse (also race), OTP SMS bombing, wallet top-up exploit.
- Check for: CAPTCHA absence, per-user quotas, server-side validation of business rules.

## API7 SSRF

- Any URL param: `url=`, `image_url=`, `callback=`, `webhook=`, `redirect=`, `proxy=`, `feed=`, `import=`.
- Targets: `http://169.254.169.254/` (AWS/GCP/Azure metadata), `http://localhost:6379` (Redis), `http://127.0.0.1:8080`, internal DNS names, `file://`, `gopher://`.
- See `ssrf` skill for full bypass methodology.

## API8 Security Misconfiguration

- Debug endpoints, stack traces, verbose errors, CORS misconfig, HSTS missing, insecure TLS, default credentials, directory listing, admin consoles (`/actuator`, `/console`, `/phpmyadmin`).
- HTTP methods exposed: `OPTIONS` → `Allow: PUT, DELETE`.

## API9 Improper Inventory Management

- Old versions: `/v1` still live after `/v2` — often unpatched, no auth changes.
- Debug/staging subdomains: `staging.`, `dev.`, `api-dev.` running old API.
- Deprecated endpoints still functional with weaker auth.

## API10 Unsafe Consumption of APIs

- Third-party services trusted too much: webhooks (no signature check), OAuth IdP (token validation flaws), payment callbacks (verify amount/status), cloud presigned URLs (no expiry), partner APIs.
- Test: tamper webhook payload, replay webhook, use stale presigned URL, change amount in callback.

## Tools

```
python tools/api_security_scanner.py <base-url>       # spec discovery + core probes
python tools/h1_idor_scanner.py <request>             # IDOR scan
python tools/h1_mutation_idor.py                      # write-path IDOR
python tools/jwt_scanner.py <token>                   # JWT attacks
bash   tools/graphql_audit.sh <url>                   # GraphQL audit
python tools/param_discovery.sh (bash)                # hidden params
python tools/validate.py "<finding>"                  # 7-Question Gate
```

## Confirmation Rules (before reporting)

1. BOLA: foreign object data returned → CONFIRMED.
2. BFLA: elevated action executed (state change) → CONFIRMED.
3. Mass assignment: persisted change + impact → CONFIRMED.
4. Anything else = POSSIBLE, needs a second test.

## References

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP API Security Testing Framework: https://owasp.org/www-project-api-security-testing-framework
- crAPI practice target: https://github.com/OWASP/crAPI
- JSON Web Token Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
