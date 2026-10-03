# Phase 1 Priority Research Ledger

This ledger is the compact Phase 1 evidence set. It uses public report links already
curated in the playbooks, so raw report archives are not stored in the repository.

The per-reference extraction records are in `PHASE1_EXTRACTIONS.md`.

## Standard Extraction Contract

Every reference is reduced to:

```text
condition -> method -> Hunter2 route -> safe proof -> impact -> report evidence
```

Do not mark a result `CONFIRMED` from a title, scanner hit, or response difference
alone. Require a reproducible request, response, demonstrated impact, and a safe
authorized validation path.

## IDOR / BOLA / BFLA

**Route:** `idor-bola` / `api-security` -> `api-hunter` -> `api_security_scanner.py`,
`h1_idor_scanner.py`, `h1_mutation_idor.py`, `apispec_idor.py` -> two-account or
minimum-safe ownership proof -> `validate.py` -> report-writer.

1. https://hackerone.com/reports/415081 - PayPal secondary-user mutation
2. https://hackerone.com/reports/2207248 - Shopify GraphQL billing objects
3. https://hackerone.com/reports/1658418 - Reddit moderator logs
4. https://hackerone.com/reports/1966006 - Unikrn user enumeration
5. https://hackerone.com/reports/2122671 - HackerOne GraphQL certification deletion
6. https://hackerone.com/reports/1392630 - TikTok support tickets
7. https://hackerone.com/reports/1969141 - HackerOne campaign deletion
8. https://hackerone.com/reports/2487889 - HackerOne private report disclosure
9. https://hackerone.com/reports/876300 - Starbucks cross-site account takeover
10. https://hackerone.com/reports/1527906 - TikTok Ads object mutation

**Extracted method themes:** cross-account read/write/delete, GraphQL object access,
method and path variants, encoded identifiers, and proof of ownership boundary failure.

## Authentication / Account Takeover

**Route:** `auth-session`, `account-takeover`, `oauth`, `jwt`, `mfa-2fa` -> `api-hunter`
or auth specialist -> `h1_oauth_tester.py`, `jwt_scanner.py`, `h1_idor_scanner.py`,
browser/proxy session -> safe account-impact proof -> validation -> report-writer.

1. https://hackerone.com/reports/2293343 - GitLab password-reset takeover
2. https://hackerone.com/reports/745324 - Leaked session cookie
3. https://hackerone.com/reports/2443228 - TikTok recovery bypass
4. https://hackerone.com/reports/976603 - SSO availability and takeover chain
5. https://hackerone.com/reports/173551 - Uber reset-token leak
6. https://hackerone.com/reports/136885 - Uber complete takeover
7. https://hackerone.com/reports/394329 - Chaturbate billing takeover
8. https://hackerone.com/reports/862589 - Public Actuator and takeover
9. https://hackerone.com/reports/1923672 - GitLab RelayState OAuth takeover chain
10. https://hackerone.com/reports/397497 - OAuth redirect XSS to takeover

**Extracted method themes:** reset-token handling, session leakage, OAuth redirect and
state validation, JWT verification, MFA workflow, and safe two-account takeover proof.

## SSRF

**Route:** `ssrf` / `cloud-security` -> `cloud-hunter` or primary `hunter` ->
`ssrf-chain`, `oob_listener.py`, `cloud_recon.sh` -> controlled OOB or safe
internal-response proof
-> redacted evidence -> report-writer.

1. https://hackerone.com/reports/2262382 - Analytics report SSRF
2. https://hackerone.com/reports/398799 - GitLab OAuth Jira blind SSRF
3. https://hackerone.com/reports/826361 - GitLab project import SSRF
4. https://hackerone.com/reports/1960765 - Reddit blind SSRF
5. https://hackerone.com/reports/1409727 - Lark document import SSRF
6. https://hackerone.com/reports/1547877 - SSRF to internal Jolokia/RCE chain
7. https://hackerone.com/reports/776017 - Kubernetes half-blind SSRF
8. https://hackerone.com/reports/374737 - HackerOne Sentry blind SSRF
9. https://hackerone.com/reports/2429894 - Libuv domain lookup SSRF
10. https://hackerone.com/reports/746024 - LY XML endpoint SSRF

**Extracted method themes:** URL-fetch sinks, blind versus full-response proof, redirect
and parser differentials, OOB correlation, and safe cloud-metadata chain analysis.

## Command Injection / RCE

**Route:** `command-injection` / `rce` -> `novel-vuln-reasoner` or primary `hunter`
-> `vuln_scanner.sh`, `oob_listener.py`, source/SAST review -> controlled OOB or
non-destructive proof -> validation -> report-writer.

1. https://hackerone.com/reports/1609965 - GitLab archive processing RCE
2. https://hackerone.com/reports/925585 - PayPal dependency confusion RCE
3. https://hackerone.com/reports/591295 - Twitter VPN pre-auth RCE
4. https://hackerone.com/reports/1154542 - GitLab ExifTool RCE
5. https://hackerone.com/reports/1125425 - GitLab Kramdown RCE
6. https://hackerone.com/reports/181879 - Shopify script type-confusion RCE
7. https://hackerone.com/reports/658013 - GitLab flag injection chain
8. https://hackerone.com/reports/3782701 - Mozilla GraphQL filter RCE
9. https://hackerone.com/reports/733072 - GitLab traversal to RCE
10. https://hackerone.com/reports/125980 - Uber Jinja2 template RCE

**Extracted method themes:** reachable command sinks, file/parser processing, template
and expression injection, dependency/build paths, OOB confirmation, and no-destructive
proof. Never claim RCE from a banner, error, or unverified delay.

## Business Logic / Race Conditions

**Route:** `business-logic` / `race-condition` -> `business-logic-hunter` and
`race-hunter` -> Caido/Burp replay, `h1_race.py`, auth sessions, and IDOR tools ->
controlled state or monetary proof -> validation -> report-writer.

1. https://hackerone.com/reports/689314 - GitLab private project copying
2. https://hackerone.com/reports/1478633 - Cloudflare transform-rule logic
3. https://hackerone.com/reports/1628209 - Administrative PDF workflow SSRF
4. https://hackerone.com/reports/1520931 - Rust time-of-check/time-of-use
5. https://hackerone.com/reports/1330529 - OTP/listing workflow abuse
6. https://hackerone.com/reports/484745 - Valve state/parser RCE chain
7. https://hackerone.com/reports/2301565 - Webhook workflow SSRF
8. https://hackerone.com/reports/364843 - Upserve negative-quantity price manipulation
9. https://hackerone.com/reports/3255473 - Hover OTP signup bypass
10. https://hackerone.com/reports/429026 - Duplicate payment race

**Extracted method themes:** state-machine skipping and reordering, replay, price and
quantity ownership, coupon/refund races, cross-account workflow access, and measurable
impact using only controlled test accounts and minimal safe actions.

## Phase 1 Completion Criteria

- 50 public references are indexed above.
- The five playbooks have an explicit route to an agent, tool, validator, and report.
- Every result is classified `CONFIRMED`, `POSSIBLE`, `REJECTED`, or `BLOCKED`.
- Evidence includes endpoint, request, response, reproduction, and impact.
- Secrets, credentials, raw sessions, and target data are never committed.
