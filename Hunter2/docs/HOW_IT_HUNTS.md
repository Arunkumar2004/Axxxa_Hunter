# Hunter2 — How It Hunts (Full Capability Reference)

A plain-English map of **what the tool does, every vulnerability class it tests, how it
tests each one, how it behaves like a real human hacker, and the agents + tools that do
the work.** Everything here uses the *existing* setup — no new dependencies.

- Full upgrade plan + progress: [`TO_EXTREME.md`](TO_EXTREME.md)
- Project readme: [`README.md`](README.md)
- Playbooks (per-class methodology): `Hunter2/skills/real-world-playbooks/references/`

> **Authorized testing only.** A deterministic scope checker gates every request.
> Destructive HTTP methods and report submission require the operator's approval.

---

## 1. What the tool does — the end-to-end hunt

When you run `hunt <target>`, the tool executes a full professional workflow, identically
in **Claude Code** and **OpenCode** (they share the same `tools/` engine):

```
scope → recon → freshness diff → playbook context → automated scanners →
playbook-guided manual testing → two-account access-control → auto-chain →
validate (rejection gate + 7-question) → report → learn
```

| Phase | What happens | Key tool(s) |
|---|---|---|
| **Scope** | Confirm the asset is in-scope; every request is gated | `scope_checker.py`, `/scope` |
| **Recon** | Subdomain enum, live hosts, URL crawl, tech fingerprint, JS extraction | `recon_engine.sh`, subfinder/dnsx/katana/gau/nuclei |
| **Freshness** | Diff vs last recon → new assets = hunt first (Rule 12) | `recon_diff.py` |
| **Playbook context** | Auto-index the right playbook per class → `findings/<t>/PLAYBOOKS.md` | `playbook_router.py` |
| **Scanners** | Fire real payloads across the ~15 automatable classes | the `*_scanner.py` set + `vuln_scanner.sh` |
| **Playbook testing** | Agent tests the ~40 knowledge classes by the disclosed-report checklist | `real-world-playbooks` skill |
| **Two-account** | Cross-tenant IDOR/BOLA/payment/privesc with your two accounts | `two_account_idor.py` |
| **Auto-chain** | Each confirmed hit → sibling + A→B next-tests | `chain_engine.py` |
| **Validate** | Auto-kill invalid findings, then the 7-question gate | `rejection_gate.py`, `validate.py` |
| **Report** | Impact-first H1/Bugcrowd/Intigriti/Immunefi report | `report-writer` agent, `/report` |
| **Learn** | Record worked/rejected/dead-ends → next hunt is smarter | `hunt_memory.py` |

---

## 2. How it tests like a real human (the doctrine)

Scanners find duplicates; humans find the money bugs. The tool encodes real-hunter
discipline (`rules/hunting.md`, `rules/lead-commander.md`):

- **Two-account testing** — the #1 move: log in as A and B, replay A's requests with B's
  auth to prove cross-tenant access. Scanners cannot do this.
- **The Sibling Rule** — for every working endpoint, test its siblings
  (`/export`,`/delete`,`/share`,`/v1/`…). Explains ~30% of paid IDOR.
- **A→B signal method** — one confirmed bug means the dev made a *class* of mistake; look
  for the same flaw nearby before writing the report.
- **Follow the money** — billing/credits/refunds/wallet/checkout get the most dev
  shortcuts → highest ROI.
- **Impact-first** — "what's the worst thing if auth broke here?" Skip low-value surface.
- **Hunt fresh/new** — features < 30 days old have the weakest security (freshness diff).
- **Kill weak findings fast** — the rejection gate + 7-question gate stop invalid reports
  before they cost you validity ratio.
- **Depth over breadth** — one target understood deeply beats ten scanned shallowly.
- **Learn across hunts** — remembers what worked and what got rejected, so it compounds.

---

## 3. Every vulnerability class — and how each is tested

Two tiers: **[SCANNER]** = automated payload firing; **[PLAYBOOK]** = agent tests by hand
following the real disclosed-report checklist. Both draw on the same 54 leveled playbooks
(each has: test-flow checklist + real payloads + rejection rules + tool mapping).

### Access control & authorization (the money classes)
- **IDOR / BOLA** `[SCANNER + TWO-ACCOUNT]` — ID swap, mutation IDOR, API-spec-driven, and
  cross-account replay (A's request with B's token). Sibling rule on every hit.
  `h1_idor_scanner.py`, `h1_mutation_idor.py`, `apispec_idor.py`, `two_account_idor.py`
- **BFLA (function-level auth)** `[PLAYBOOK]` — low-priv user hitting admin/privileged
  endpoints; every sibling in the same controller. `api_security_scanner.py`
- **Mass assignment / BOPLA** `[PLAYBOOK]` — inject extra JSON fields (`role`,`is_admin`).
- **Privilege escalation** `[PLAYBOOK + TWO-ACCOUNT]` — role transitions, horizontal +
  vertical, hidden admin routes.

### Authentication
- **Auth / session** `[PLAYBOOK]` — logout invalidation, fixation, token entropy,
  concurrent sessions, cookie flags on sensitive cookies. `auth-session` playbook.
- **OAuth / OIDC** `[SCANNER]` — redirect_uri manipulation, state reuse/CSRF, PKCE, code
  reuse, token leak. `h1_oauth_tester.py`
- **SAML / SSO** `[PLAYBOOK]` — XML signature wrapping (XSW), comment injection in NameID,
  signature stripping. `/auth-hunt`
- **JWT** `[SCANNER]` — alg:none forgery, RS256→HS256 confusion, weak-secret crack, kid
  injection. `jwt_scanner.py`
- **MFA / 2FA** `[PLAYBOOK]` — OTP brute (with lockout check), backup-code abuse, flow
  bypass. **reset-password / registration** `[PLAYBOOK]` — token poisoning, host-header.
- **Account takeover** `[PLAYBOOK + CHAIN]` — the ATO taxonomy (9 paths), assembled from
  chained primitives.

### Injection
- **SQLi** `[SCANNER]` — error/boolean/time-based (nuclei/ghauri/sqlmap via `vuln_scanner.sh`).
- **NoSQLi** `[SCANNER]` — `$ne`/`$gt`/`$regex` operator auth-bypass, `$where` blind. `nosqli_scanner.py`
- **Command injection / RCE** `[PLAYBOOK + OOB]` — OOB callback confirm (never destructive).
- **SSTI** `[SCANNER]` — `{{7*7}}`/`${7*7}` math canaries per engine (Jinja/Twig/FreeMarker/ERB).
- **XXE** `[SCANNER + OOB]` — file-read + OOB blind exfil. `xxe_scanner.py` + `oob_listener.py`
- **LFI / path traversal → RCE** `[PLAYBOOK]` — php://filter, log/session poisoning, wrappers.
- **Deserialization** `[PLAYBOOK + OOB]` — Java/PHP/Python/.NET gadgets, OOB confirm.

### Client-side & web
- **XSS (reflected/stored/DOM)** `[SCANNER + BROWSER]` — dalfox + a real headless Chromium
  harness that only reports `[CONFIRMED]` when the browser executes the payload.
  `dom_xss_harness.py` (Playwright)
- **CSRF** `[SCANNER]` — SameSite + token-entropy + validation check. `csrf_scanner.py`
- **CORS** `[SCANNER]` — origin reflection, null origin, suffix/prefix bypass, credentialed
  read. `cors_scanner.py`
- **Prototype pollution** `[SCANNER + BROWSER]` — server `__proto__` probes + client gadget.
  `prototype_pollution_scanner.py`
- **HPP / postMessage / clickjacking / open-redirect** `[SCANNER/PLAYBOOK]` —
  `hpp_postmessage_scanner.py` + playbooks.
- **WebSocket (CSWSH)** `[SCANNER]` — cross-site hijack, origin + message-auth. `websocket_scanner.py`
- **CRLF / host-header injection** `[SCANNER]` — encoded CRLF, Set-Cookie canary. `crlf_scanner.py`

### Server-side & infra
- **SSRF** `[SCANNER + OOB]` — sink discovery (webhook/import/preview), filter bypass, cloud
  metadata (169.254.169.254), blind OOB confirm. `/ssrf-chain`, `oob_listener.py`
- **Request smuggling** `[PLAYBOOK]` — CL.TE / TE.CL / H2.CL desync probes.
- **Web cache poisoning** `[PLAYBOOK]` — unkeyed headers reflected into cached responses.
- **Subdomain takeover** `[SCANNER]` — dangling CNAME + claimable-service check + PoC page.
  `takeover_scanner.sh`
- **Secrets / CI-CD** `[SCANNER + PLAYBOOK]` — JS/source secret grep, `pull_request_target`
  + expression-injection in workflows. `secrets_hunter.sh`, `sast_scan.py`, `cicd_scanner.sh`
- **Cloud storage** `[SCANNER]` — S3/GCS/Azure bucket enum + takeover. `cloud_bucket_enum.py`
- **Kubernetes** `[PLAYBOOK]` — unauth API server, kubelet, anonymous RBAC, exposed dashboard. `/k8s-audit`
- **Port / service scan** `[SCANNER]` — naabu for non-web services (Redis, Docker API, DBs). `port_scanner.py`
- **CVE sweep** `[SCANNER]` — nuclei templates. `cve_scan.sh` / `/scan-cves`

### Business logic & timing
- **Business logic** `[PLAYBOOK + REASONING]` — negative quantity, price tampering, coupon
  stacking, step-skipping, quota bypass. `business-logic-hunter` agent (scanners can't find these).
- **Race conditions** `[SCANNER]` — parallel/pipelined fire on redeem/refund/transfer/vote.
  `h1_race.py`, `/race`.

### AI / LLM
- **LLM / agentic** `[SCANNER]` — prompt injection, jailbreak, system-prompt leak, data
  exfil, indirect injection, RAG/MCP poisoning, ASI01–ASI10. `llm_redteam.py`, `/llm-redteam`.

### Web3 (if in scope)
- **Smart contracts** `[PLAYBOOK]` — 10 EVM classes (reentrancy, oracle, access control,
  accounting desync…) + Solana SPL + meme-coin rug checks. `web3-auditor`, `token_scanner.py`.

---

## 4. The agents (who does the work)

The primary `hunter` orchestrates; 14 specialists handle their domains:

| Agent | Role |
|---|---|
| `recon-agent` | Subdomain enum + live-host discovery (Chaos/subfinder/dnsx/httpx) |
| `recon-ranker` | Ranks attack surface + hunt memory into a prioritized plan |
| `api-hunter` | REST/GraphQL/gRPC vs OWASP API Top 10 2023 + two-account IDOR |
| `business-logic-hunter` | The reasoning bugs scanners can't find — logic/abuse-of-function |
| `race-hunter` | TOCTOU / race conditions (coupons, wallet, limits) |
| `cloud-hunter` | AWS/GCP/Azure exposed assets, buckets, metadata SSRF |
| `llm-hunter` | Chatbots/copilots/RAG/agents — prompt injection + ASI framework |
| `credential-hunter` | Password-spray pipeline (wordlist-gen + breach-check + osint) |
| `novel-vuln-reasoner` | Unknown/novel classes with no signature — deep code/behavior review |
| `chain-builder` | Given bug A, finds B and C to chain for higher severity/payout |
| `token-auditor` | Meme-coin / token security (mint, honeypot, fee manipulation) |
| `web3-auditor` | Smart-contract audit — 10 classes by frequency |
| `validator` | 7-Question Gate + 4-gate checklist — kills weak findings |
| `report-writer` | Impact-first H1/Bugcrowd/Intigriti/Immunefi reports |
| `autopilot` | Autonomous full loop (scope→recon→rank→hunt→validate→report) with safety rails |

---

## 5. The Phase-1/2 engine (what makes it "active", not just knowledgeable)

These were built in the EXTREME upgrade and make the tool *act* on its knowledge:

| Tool | What it does |
|---|---|
| `playbook_router.py` | Resolves any class/alias → the right playbook; auto-writes `PLAYBOOKS.md` per hunt |
| `two_account_idor.py` | Cross-tenant replay (A's request, B's auth); safe methods by default; never logs tokens |
| `rejection_gate.py` | Auto-kills always-rejected findings (public keys, self-XSS, theoretical, out-of-scope) |
| `chain_engine.py` | Sibling rule + A→B table → ranked next-tests after each confirmed hit |
| `hunt_memory.py` | Records worked/rejected/dead-ends → next hunt loads them (compounds) |
| `recon_diff.py` | Flags new assets since last recon → hunt fresh first |

Safety infra always on: `scope_checker.py` (deterministic scope gate), `AutopilotGuard`
(circuit breaker + rate limiter + `SafeMethodPolicy`), `credential_store.py` (`.env`,
masked, never in transcripts), audit log + pattern DB with 10 MB rotation.

---

## 6. What it will NOT do (honest limits)

- It does **not** auto-find bugs with zero human input — it finds + guides; you confirm.
- The ~40 playbook classes have **no dedicated auto-scanner** — the agent tests them by
  hand with expert guidance (this finds the high-value bugs anyway).
- It won't test out-of-scope assets, DoS, social-engineer, exfiltrate real user data, or
  enter your credentials / solve CAPTCHAs — it stops and asks.
- High-value access-control bugs need **your two own test accounts** in `.env`.

---

## 7. One-line summary

Point it at an authorized target and it runs the full hunt — recon, the right playbook per
lead, real scanners for the automatable classes, expert manual methodology for the rest,
two-account testing for the money bugs, auto-chaining, hard validation, a clean report —
and it gets smarter every hunt. Same behavior in Claude Code and OpenCode.
