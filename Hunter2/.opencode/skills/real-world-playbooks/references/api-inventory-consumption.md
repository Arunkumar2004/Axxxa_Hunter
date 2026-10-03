# Real-World Playbook - API Inventory and Unsafe Consumption

**Class:** `api-inventory-consumption` · **Coverage-matrix tier:** 2 · **Hunter2:** `/recon-plus` · `/param-discover` · `api_security_scanner.py` · `api-security` review (API10 = guided-manual) · **Skill:** api-security

**Route:** `api-security` -> `api-hunter` -> `/api-audit`, `/recon-plus`,
`api_security_scanner.py` -> version/third-party trust evidence -> validator/report-writer.

## Conditions

- REST, GraphQL, gRPC, mobile, SPA, deprecated, staging, or third-party API surfaces exist.

## Safe method

- Compare documented and observed versions, auth requirements, schemas, and roles.
- Check webhook signature, redirect, URL-fetch, serialization, and third-party response
  trust boundaries with controlled endpoints.
- Test old versions only within scope and rate limits.

## Proof and rejection

- Confirm an inventory flaw only when an old/undocumented surface grants unauthorized
  access or a third-party trust boundary changes security state.
- Reject documentation exposure or version banners without reachable impact.

## Test flow / checklist — do these in order
*(public methodology — OWASP API Security Top 10 / WSTG / HowToHunt; run each, mark result in the coverage matrix)*

[ ] Enumerate every API surface and host — REST/GraphQL/gRPC/SOAP, plus `api.`, `api-v1.`, `staging.`, `dev.`, `sandbox.`, `internal.`
[ ] Diff documented endpoints (Swagger/OpenAPI/GraphQL introspection) against observed traffic; flag undocumented/shadow endpoints
[ ] Enumerate API versions (`/v1/`, `/v2/`, `/beta/`, `/internal/`) and retest known bugs against older/deprecated versions
[ ] Check whether old/beta/staging versions enforce the same authN, authZ, rate limits, and input validation as production
[ ] Hunt for exposed API docs, Swagger UI, `/openapi.json`, `.well-known`, and Postman collections that leak hidden routes
[ ] Map every place the app *consumes* a third-party API (webhooks, OAuth, URL-fetch, importers, payment/notification callbacks)
[ ] Test whether third-party responses are trusted without validation (redirects followed, SSRF via fetch, deserialization of external data)
[ ] Verify webhook/callback signature validation and TLS verification on outbound third-party calls
[ ] Check data flowing from a third party into a sink (HTML/SQL/template/file path) for injection via the trusted channel
[ ] Confirm reachable impact: unauthorized access via an old/shadow surface, or a trust-boundary change from consuming external data

## What gets this rejected (kill before you write)
*(from `skills/triage-validation/SKILL.md` — one wrong answer = kill it and move on)*

- Version banner or documented API-version disclosure with no unauthorized access.
- Swagger/OpenAPI/GraphQL introspection exposed alone (no auth bypass or IDOR demonstrated).
- "Deprecated endpoint exists" without proving it grants access production denies.
- "The API returns more fields than necessary" without proven sensitivity/PII.
- Issues rooted in a third-party service the company merely uses (out of scope), not the target's own asset.
- Staging/dev host findings when those hosts are not explicitly in scope.
- **Conditionally valid (only WITH a chain):** shadow/old version → IDOR/BOLA or auth bypass on live data; unsafe consumption of an external API → SSRF/injection/deserialization landing in a real sink.
