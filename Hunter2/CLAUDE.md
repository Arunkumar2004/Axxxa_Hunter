# Claude Bug Bounty — Plugin Guide

This repo is a Claude Code plugin for professional bug bounty hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi.

## Operating Contract (READ FIRST — this is the default, no need to restate it)

When the operator says anything like **"hunt", "start hunt", "use this tool", "use Hunter2", "go", "full send"** on a target, treat it as standing authorization for the **FULL-POWER flow**. Do **not** ask "should I use all the tools / agents / MCPs?" — the answer is always **yes**. Specifically:

1. **PREFLIGHT FIRST, ALWAYS.** Begin every hunt by running `python tools/start.py <target>` — the **AXXX HUNTER start dashboard** (banner + connection board; wraps `preflight.py`) — and reporting the readout — what tools, MCPs, proxies (Caido/Burp), agents, and skills are actually armed. **Never assume a tool/MCP is live just because it's shipped.** State clearly what is connected vs. what needs setup (and that MCP servers only load after a Claude Code **restart** + approval).
2. **USE EVERYTHING APPLICABLE.** All installed tools (curl/python fallback when a native binary is AV-blocked), all relevant **agents in parallel** (api-hunter, business-logic-hunter, llm-hunter, cloud-hunter, race-hunter, novel-vuln-reasoner, etc.), all **skills**, and any connected **MCP** (Caido for authenticated replay, HackerOne for program data).
   - **RUN THE SHIPPED TOOLS — do NOT hand-roll replacements.** Drive `tools/hunt.py` (the master orchestrator) and the shipped `*_scanner.py` / `*.sh` for each class. Writing your own one-off scripts to replace a shipped scanner is a **failure mode**: it bypasses the coverage matrix, chaining, and validation, and leaves most of the toolkit unused. Only write custom code to (a) confirm/triage a finding a shipped tool surfaced, or (b) cover a gap **no** shipped tool addresses — and say which. If a shipped tool is broken, report the bug; don't silently route around the whole framework.
3. **HUNT EVERY BUG CLASS — not a subset.** The 26 web2 classes **plus**: RCE, SQLi, SSTI, XXE, insecure deserialization, HTTP request smuggling, cache poisoning/deception, SSRF, LFI/file-inclusion, file upload, IDOR/BOLA/BFLA, business logic, race conditions, GraphQL, auth/session/JWT/SAML/OAuth/OIDC/MFA, ATO chains, subdomain takeover, cloud/CI-CD/k8s misconfig, prototype pollution, CORS/CRLF/host-header, dependency confusion/supply chain, mobile, web3, and LLM/agentic (OWASP LLM Top 10 / ASI01-10). **Match the class to the reachable surface** — fire a class only where a real sink/feature exists (don't spray RCE payloads at a static login). Say why a class is N/A rather than silently skipping it.
4. **NEVER LOSE A LEAD.** After recon, run `lead_board.py ingest` + `show`, route each finding to its `hunt-*` skill, and `touch` status as you go (see Critical Rule 6). Surface stale high-priority leads unprompted.
5. **ALWAYS TRY TO CHAIN.** Before finalizing, run the chaining pass (`chain-builder` agent / `/chain`): combine every finding — including low/medium/info ones — into higher-severity **A->B->C chains**. Standard patterns: IDOR->ATO, SSRF->cloud-metadata->creds, open-redirect->OAuth-token-theft, XSS->session/ATO, subdomain-takeover->OAuth-redirect, source-leak->secret->API, prompt-injection->tool-abuse->IDOR. A lone "info" finding (e.g. an auth-gate quirk) often becomes Critical once chained — never report findings in isolation without asking "what does this unlock?"
6. **FINISH WITH A CONSOLIDATED REPORT.** Full flow (all steps, in order): **scope -> preflight -> recon -> lead board -> rank -> hunt (all classes) -> chain -> validate (7-Question Gate) -> report.** Deliver a single merged findings report at the end.

**Environment truths (this box):** ProjectDiscovery binaries (httpx/nuclei) are **Defender-quarantined** — use curl/Python equivalents, don't fight AV. MCPs live in `.mcp.json` and need a **restart** to activate. **Caido** (`127.0.0.1:8080`) is the authenticated-hunting proxy: proxy the browser -> operator logs in -> replay their authed requests to hunt IDOR/BOLA/business-logic on protected APIs.

**Safety rails always hold (full power != reckless):** read full scope first; in-scope assets only; no DoS/load testing; subdomain-takeover is **detect-and-report only** (never claim a resource); minimal redacted PoCs (no bulk PII scraping); never create accounts or enter the operator's credentials — the operator logs in themselves via the browser.

## Leader Doctrine (the Lead Commander) — READ THESE TWO FILES

The primary agent runs the hunt like an experienced human attacker, not a scanner that
drifts. On **every** hunt it follows:

- **`rules/lead-commander.md`** — the **Startup Ritual** (show a Connection Board of
  tools/MCPs/proxies/agents/skills/scope *before* hunting), the full loop, **Depth
  Discipline** (test every reachable class to real depth; park-and-return, never abandon;
  show your work continuously), the **Interaction Protocol** (on any OTP/MFA/password/
  captcha/login wall → **STOP and ASK the operator**, never skip the page, never enter
  creds), and parallel specialist orchestration.
- **`rules/coverage-matrix.md`** — the canonical **A→Z class list** (OWASP Web Top 10 +
  API Top 10 + LLM Top 10 + PortSwigger full topic list). Every class gets a status
  (`FOUND / TESTED / N/A-with-reason / PENDING`); a hunt is **not done** while any
  reachable class is `PENDING`. End every hunt with the matrix readout.
- **`skills/real-world-playbooks/`** — real disclosed-report tradecraft + chaining recipes
  distilled from HackerOne/writeups, applied per class.

## What's Here

### Skills (27 domains — load with `/bug-bounty`, `/web2-recon`, `/token-scan`, etc.)

> Full set lives in `skills/` (27 dirs) and is auto-available; the table below highlights the core ones. **New: `real-world-playbooks`** — real disclosed-HackerOne-report tradecraft + per-class chaining (see `rules/coverage-matrix.md` for the A→Z class list).

| Skill | Domain |
|---|---|
| `skills/bug-bounty/` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `skills/bb-methodology/` | **Hunting mindset + 5-phase non-linear workflow + tool routing + session discipline** |
| `skills/web2-recon/` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `skills/web2-vuln-classes/` | 21 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `skills/security-arsenal/` | Payloads, bypass tables, gf patterns, always-rejected list |
| `skills/web3-audit/` | 10 smart contract bug classes, Foundry PoC template, pre-dive kill signals |
| `skills/meme-coin-audit/` | Meme coin rug pull detection, token authority checks, bonding curve exploits, LP attacks |
| `skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
| `skills/triage-validation/` | 7-Question Gate, 4 gates, never-submit list, conditionally valid table |
| `skills/credential-attack/` | Password spray methodology — when/why, 4-stage pipeline, mode selection, lockout tactics, legal guardrails, pitfalls learned from live tests |
| `skills/client-reverse/` | Client-side request-signing / anti-bot token reversal — packet-first replay, sign-input isolation, fetch/XHR hooking, deobfuscation, reach protected APIs |
| `skills/mobile-pentest/` | Android/iOS app pentest — runtime-first proxy workflow, APK/IPA decompile for hidden endpoints + secrets, deeplink/exported-activity injection, WebView bridge, SSL pinning bypass |
| `skills/cicd-security/` | CI/CD pipeline hunting — GitHub Actions injection, secret exfil, self-hosted runner poisoning, OIDC abuse, supply chain attacks |
| `skills/graphql-audit/` | GraphQL hunting — introspection, field suggestions (clairvoyance), batching DoS, IDOR via aliasing, injection, auth bypass, depth bombs |
| `skills/argus/` | **Argus** (all-seeing scanner suite) — CORS, CRLF/host-header, NoSQL injection, JWT (alg:none/confusion/crack), OOB blind-bug confirmation (interactsh), LLM red-team corpus |

### Commands (57 slash commands)

> Full list in `commands/` (57 files) — see README.md §5. The table below is a subset; **all 57** are available.

> **Note:** All commands are prefixed to avoid conflicts with Claude Code's built-in commands.
> `/resume` is a reserved Claude Code command — use `/pickup` to continue a previous hunt.

| Command | Usage |
|---|---|
| `/recon` | `/recon target.com` — full recon pipeline |
| `/hunt` | `/hunt target.com` — start hunting |
| `/validate` | `/validate` — run 7-Question Gate on current finding |
| `/report` | `/report` — write submission-ready report |
| `/chain` | `/chain` — build A→B→C exploit chain |
| `/scope` | `/scope <asset>` — verify asset is in scope |
| `/scope-aggregate` | `/scope-aggregate <program>` — pull every in-scope asset across H1/Bugcrowd/Intigriti/YWH/Immunefi |
| `/triage` | `/triage` — quick 7-Question Gate |
| `/web3-audit` | `/web3-audit <contract.sol>` — smart contract audit |
| `/autopilot` | `/autopilot target.com --normal` — autonomous hunt loop |
| `/surface` | `/surface target.com` — ranked attack surface |
| `/pickup` | `/pickup target.com` — pick up previous hunt (was `/resume`) |
| `/remember` | `/remember` — log finding to hunt memory |
| `/intel` | `/intel target.com` — fetch CVE + disclosure intel |
| `/token-scan` | `/token-scan <contract>` — meme coin/token rug pull scanner |
| `/memory-gc` | `/memory-gc [--rotate|--purge-backups]` — inspect/rotate hunt-memory JSONL files (10MB cap, 3 backups) |
| `/secrets-hunt` | `/secrets-hunt --js-bundle <recon-dir>` — leaked-credential scan (trufflehog/noseyparker/gitleaks) |
| `/takeover` | `/takeover --recon <recon-dir>` — subdomain takeover candidates (dnsReaper/subjack) |
| `/cloud-recon` | `/cloud-recon --keyword <name>` — public S3/Azure/GCP + CloudFlare-bypass origin IPs |
| `/param-discover` | `/param-discover <url>` — find hidden HTTP parameters (Arjun/x8) |
| `/bypass-403` | `/bypass-403 <url>` — try header/method/encoding tricks against a 403/401 |
| `/arsenal` | `/arsenal [tool]` — list installed external tools or get an install hint |
| `/scan-cves` | `/scan-cves <host>` — focused nuclei CVE sweep (high/critical) + optional log4j-scan |
| `/wordlist-gen` | `/wordlist-gen <target>` — company-specific password wordlist (cewler + hashcat); requires `--with-credential-attack` |
| `/osint-employees` | `/osint-employees <target>` — employee names + emails (theHarvester + username-anarchy, opt-in LinkedIn); requires `--with-credential-attack` |
| `/breach-check` | `/breach-check <wordlist>` — HIBP k-anonymity rank wordlist by real-world breach count |
| `/spray` | `/spray <url> --mode http-form\|oauth\|o365\|okta --users <f> --passes <f>` — password spray with hard guards (typed-host confirm, lockout warn, audit log) |
| `/graphql-audit` | `/graphql-audit <url>` — full GraphQL audit: introspection, batching DoS, IDOR, injection, alias bomb, graphw00f fingerprint |
| `/cors` | `/cors <url>` — CORS misconfig scanner (arbitrary-origin reflection, null-origin, credential exposure, suffix/prefix regex bypass) |
| `/crlf` | `/crlf <url> [--host-header]` — CRLF / response-splitting + host-header injection (Set-Cookie injection, reset poisoning) |
| `/nosqli` | `/nosqli --login <url> --user-field <f> --pass-field <f>` — NoSQL injection (operator auth-bypass, $where time-based blind) |
| `/jwt-scan` | `/jwt-scan <token> [--analyze\|--alg-none\|--confuse\|--crack]` — JWT alg:none, RS256→HS256 confusion, weak-secret crack (offline) |
| `/oob` | `/oob --payloads <oob-domain>` — out-of-band orchestrator: confirm blind SSRF/XXE/SQLi/RCE/Log4Shell via interactsh correlation |
| `/llm-redteam` | `/llm-redteam --url <chat-endpoint>` — LLM red-team corpus: prompt-injection, jailbreak, system-prompt leak, exfil, indirect injection |

### Agents (16 — 1 primary `hunter` + 15 specialists)

> Full set in `agents/` (15 specialists) + the primary hunter. The list below is a subset; delegate any of them in parallel via the Task/task tool.

- `recon-agent` — subdomain enum + live host discovery
- `report-writer` — generates H1/Bugcrowd/Immunefi reports
- `validator` — 4-gate checklist on a finding
- `web3-auditor` — smart contract bug class analysis
- `chain-builder` — builds A→B→C exploit chains
- `autopilot` — autonomous hunt loop (scope→recon→rank→hunt→validate→report)
- `recon-ranker` — attack surface ranking from recon output + memory
- `token-auditor` — fast meme coin/token rug pull and security analysis
- `credential-hunter` — orchestrates wordlist-gen + osint-employees + breach-check; HARD STOPS at spray for human go/no-go

### Rules (always active)

- `rules/hunting.md` — 17 critical hunting rules
- `rules/reporting.md` — report quality rules

### Tools (Python/shell — in `tools/`)

- `tools/preflight.py` — **run first**: reports what's actually armed (tools on PATH + AV-blocked bins, MCP servers from `.mcp.json` + backend reachability, Caido/Burp proxy ports, agent/skill counts, readiness verdict). `--json` for machine-readable. Enforces the Operating Contract's "never assume a tool is connected" rule.
- `tools/hunt.py` — master orchestrator
- `tools/recon_engine.sh` — subdomain + URL discovery (now with optional `nuclei` phase)
- `tools/vuln_scanner.sh` — XSS/SQLi/SSTI/MFA/SAML probe pipeline
- `tools/validate.py` — 4-gate finding validator
- `tools/learn.py` — CVE + disclosure intel
- `tools/intel_engine.py` — on-demand intel with memory context
- `tools/scope_checker.py` — deterministic scope safety checker
- `tools/scope_aggregator.sh` — multi-platform scope pull (bbscope + bounty-targets-data)
- `tools/secrets_hunter.sh` — trufflehog/noseyparker/gitleaks wrapper for FS/git/JS/GH-org
- `tools/takeover_scanner.sh` — dnsReaper/subjack subdomain-takeover scanner
- `tools/cloud_recon.sh` — S3Scanner + cloud_enum + CloudFail wrapper
- `tools/param_discovery.sh` — Arjun/x8 hidden-parameter discovery
- `tools/bypass_403.sh` — byp4xx + built-in 403/401 bypass matrix
- `tools/cve_scan.sh` — focused nuclei CVE-tag sweep + optional log4j-scan
- `tools/external_arsenal.sh` — installed-tool registry (~50 tools); other scripts source this for `_have <tool>`
- `tools/cicd_scanner.sh` — GitHub Actions workflow scanner (sisakulint wrapper, remote scan)
- `tools/token_scanner.py` — automated token red flag scanner (EVM + Solana)
- `tools/wordlist_engine.sh` — company-specific password wordlist generator (cewler + hashcat rules); requires `--with-credential-attack`
- `tools/osint_employees.sh` — employee names + email patterns for spray prep (theHarvester + username-anarchy, opt-in CrossLinked); requires `--with-credential-attack`
- `tools/breach_checker.py` — HIBP k-anonymity wordlist enrichment; ranks passwords by breach count (no API key, free)
- `tools/spray_orchestrator.sh` — password spray with typed-hostname guard + lockout warning + audit log; modes: http-form / oauth / o365 / okta (TREVOR); requires `--with-credential-attack` for TREVOR modes
- `tools/graphql_audit.sh` — 7-phase GraphQL audit: introspection + schema dump, graphw00f fingerprint, clairvoyance field discovery, batching DoS, alias bomb, gqlmap injection, graphql-cop checklist
- `tools/lead_board.py` — persistent per-target lead ledger that routes every recon observation to the right `hunt-*` skill and tracks its status so no lead is forgotten (`memory/leads/<target>.jsonl`). `ingest` parses recon output and routes 30+ signal types (IDOR/SSRF/GraphQL/OAuth/SAML/LLM/source-leak/tech-stack/nuclei) to skills; `show` lists untouched-first and flags stale high-priority leads; `next` returns the single top lead; `touch` marks a lead investigating/killed/reported (re-ingest preserves status). See **Critical Rule 6**.
- `tools/eol_check.py` — EOL / lifecycle intel from endoflife.date (auto-run by `hunt.py` after recon)
- `tools/waf_encoder.py` · `waf_response_analyzer.py` · `multipart_mutator.py` — WAF bypass + soft-block scoring + upload mutation
- `tools/cors_scanner.py` — CORS misconfig scanner (origin-reflection / null / credentialed / suffix-prefix regex / scheme-downgrade); pure classifier, no deps
- `tools/crlf_scanner.py` — CRLF / response-splitting + host-header injection with Set-Cookie canary detection (encoded + UTF-8 bypass variants)
- `tools/nosqli_scanner.py` — NoSQL injection (operator auth-bypass, bracket-syntax, $where time-based blind) with differential + timing classifier
- `tools/csrf_scanner.py` — CSRF scanner (form parser + anti-CSRF token / SameSite classifier; HIGH when state-changing form has neither)
- `tools/xxe_scanner.py` — XXE scanner (safe internal-entity expansion -> error-based file disclosure -> blind OOB via interactsh)
- `tools/prototype_pollution_scanner.py` — prototype pollution (static JS source+sink gadgets; --active server-side __proto__ reflection/500 probing)
- `tools/websocket_scanner.py` — Cross-Site WebSocket Hijacking (raw handshake with forged vs same Origin, authenticated-socket aware)
- `tools/hpp_postmessage_scanner.py` — HTTP param pollution (positional first/last differential) + postMessage listeners missing origin checks
- `tools/favicon_hash.py` — Shodan-style mmh3 favicon hash (pure MurmurHash3) -> Shodan/Censys/FOFA pivot queries for shadow infra + origin discovery
- `tools/sourcemap_extract.py` — recover original source from shipped .js.map, grep for secrets/endpoints/URLs (path-traversal-guarded)
- `tools/apispec_idor.py` — OpenAPI/Swagger -> auto IDOR/BOLA test plan (id-bearing endpoints, account-A-vs-B curl pairs)
- `tools/login_capture.py` — interactive login-wall capture: real browser, human logs in, auto-captures cookie/JWT -> .private/<target>.json (AuthSession)
- `tools/finding_replay.py` — replay a saved finding to re-verify (VULNERABLE/FIXED/CHANGED); regression-check a whole findings folder
- `tools/parallel_hunt.sh` — scope-gated parallel multi-host hunt (bounded job pool, per-host output dirs)
- `tools/web3_audit.sh` — automated smart-contract analyzers (slither/aderyn/mythril/echidna/medusa/halmos) -> findings/web3/<name>/summary.md; wired into /web3-audit
- `tools/llm_redteam.py` — LLM red-team; Hunter 2 adds output->sink (LLM02), multi-turn crescendo, and multimodal (image) injection
- `tools/jwt_scanner.py` — offline JWT toolkit: alg:none forgery, RS256→HS256 confusion, HS256 secret crack, static claim analysis (pure stdlib)
- `tools/oob_listener.py` — out-of-band orchestrator wrapping interactsh-client; payloads + correlation for blind SSRF/XXE/SQLi/RCE/Log4Shell
- `tools/llm_redteam.py` — LLM red-team corpus runner (prompt-injection/jailbreak/system-prompt-leak/exfil/indirect/guardrail-bypass) with canary detection
- Full catalogue: **`tools/README.md`** (~50 tools). `hunt.py` auto-ingests leads after recon (`--graphql` / `--cve-hunt` / `--skip-leads` flags).

### External tool references

- `wordlists/REFERENCES.md` — pointers to SecLists / OneListForAll / fuzz4bounty / PayloadsAllTheThings
- `skills/security-arsenal/REFERENCES.md` — methodology, writeup archives, dorks, key-verification, AI-security skill repos
- `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` — per-vuln quick-check tables distilled from HowToHunt + HolyTips + AllAboutBugBounty + KingOfBugBountyTips

### MCP Integrations (in `mcp/`)

- `mcp/burp-mcp-client/` — Burp Suite proxy integration
- `mcp/hackerone-mcp/` — HackerOne public API (Hacktivity, program stats, policy)

### Hunt Memory (in `memory/`)

- `memory/pattern_db.py` — cross-target pattern learning
- `memory/audit_log.py` — request audit log, rate limiter, circuit breaker
- `memory/rotation.py` — size-based JSONL rotation (10MB cap, keep 3 backups), auto-fired on append
- `memory/schemas.py` — schema validation for all data

## Start Here

```bash
claude
# python tools/preflight.py   # FIRST — what's armed? (tools/MCPs/Caido/agents)
# /recon target.com
# /hunt target.com
# /validate   (after finding something)
# /report     (after validation passes)
```

## Install Skills

```bash
chmod +x install.sh && ./install.sh
```

## Critical Rules (Always Active)

0. **PREFLIGHT + FULL POWER** — run `python tools/preflight.py` first and report what's armed; then run the full flow with all applicable tools/agents/skills/MCPs and hunt every bug class (see **Operating Contract** above). Never assume a tool/MCP is connected just because it's shipped.
1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. Park-and-return — a stalled lead gets parked (note why) and returned to before closing; never abandon it silently
6. **LEAD BOARD — never lose a lead.** After recon, run `lead_board.py ingest <target>` + `show`, and route each finding to its `hunt-*` skill in plain language ("GraphQL endpoint → hunt-graphql"). When starting/killing/reporting a lead, `touch` its status. The hunter focuses on one lead at a time; the board remembers the rest so none is forgotten. Surface stale high-priority leads unprompted.
