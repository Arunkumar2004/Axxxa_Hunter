# Bug Bounty Agent Toolkit — Plugin Guide

This repo is an agent-portable bug bounty plugin for professional hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi. It supports Claude Code, OpenCode, Pi Agent, Codex-style Agent Skills, and shared `.agents/skills` harnesses.

## Operating Contract (READ FIRST — this is the default, no need to restate it)

When the operator says anything like **"hunt", "start hunt", "use this tool", "use Hunter2", "go", "full send"** on a target, treat it as standing authorization for the **FULL-POWER flow**. Do **not** ask "should I use all the tools / agents / MCPs?" — the answer is always **yes**. Specifically:

1. **PREFLIGHT FIRST, ALWAYS.** Begin every hunt by running `python tools/start.py <target>` — the **AXXX HUNTER start dashboard** (banner + connection board; wraps `preflight.py`) — and reporting the readout — what tools, MCPs, proxies (Caido/Burp), agents, and skills are actually armed. **Never assume a tool/MCP is live just because it's shipped.** State clearly what is connected vs. what needs setup.
2. **USE EVERYTHING APPLICABLE.** All installed tools (curl/python fallback when a native binary is AV-blocked), all relevant **agents/subagents in parallel**, all **skills**, and any connected **MCP** (Caido for authenticated replay, HackerOne for program data).
   - **RUN THE SHIPPED TOOLS — do NOT hand-roll replacements.** Drive `tools/hunt.py` (the master orchestrator) and the shipped `*_scanner.py` / `*.sh` for each class. Writing your own one-off scripts to replace a shipped scanner is a **failure mode**: it bypasses the coverage matrix, chaining, and validation, and leaves most of the toolkit unused. Only write custom code to (a) confirm/triage a finding a shipped tool surfaced, or (b) cover a gap **no** shipped tool addresses — and say which. If a shipped tool is broken, report the bug; don't silently route around the whole framework.
3. **HUNT EVERY BUG CLASS — not a subset.** The 26 web2 classes **plus** RCE, SQLi, SSTI, XXE, insecure deserialization, HTTP request smuggling, cache poisoning/deception, SSRF, LFI, file upload, IDOR/BOLA/BFLA, business logic, race conditions, GraphQL, auth/session/JWT/SAML/OAuth/OIDC/MFA, ATO chains, subdomain takeover, cloud/CI-CD/k8s misconfig, prototype pollution, CORS/CRLF/host-header, dependency confusion/supply chain, mobile, web3, and LLM/agentic. **Match the class to the reachable surface**; say why a class is N/A rather than silently skipping it.
4. **NEVER LOSE A LEAD.** After recon, run `python tools/lead_board.py ingest <target>` + `show`, route each finding to its `hunt-*` skill, and `touch` status as you go. Surface stale high-priority leads unprompted.
5. **ALWAYS TRY TO CHAIN.** Before finalizing, run the chaining pass (`chain-builder` / `/chain`): combine every finding — including low/medium/info — into higher-severity **A->B->C chains** (IDOR->ATO, SSRF->metadata->creds, open-redirect->OAuth-token-theft, XSS->ATO, source-leak->secret->API, prompt-injection->tool-abuse->IDOR). Never report findings in isolation without asking "what does this unlock?"
6. **FINISH WITH A CONSOLIDATED REPORT.** Full flow (in order): **scope -> preflight -> recon -> lead board -> rank -> hunt (all classes) -> chain -> validate (7-Question Gate) -> report.** Deliver a single merged findings report at the end.

**Safety rails always hold (full power != reckless):** read full scope first; in-scope assets only; no DoS/load testing; subdomain-takeover is **detect-and-report only**; minimal redacted PoCs (no bulk PII scraping); never create accounts or enter the operator's credentials — the operator logs in themselves via the browser.

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

> Full set lives in `skills/` (27 dirs), auto-registered via `opencode.json`. **New: `real-world-playbooks`** — real disclosed-HackerOne-report tradecraft + per-class chaining.

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
| `skills/credential-attack/` | Password spray methodology — when/why, 4-stage pipeline, mode selection, lockout tactics, legal guardrails |
| `skills/mobile-pentest/` | Android/iOS app pentest — runtime-first proxy workflow, APK/IPA decompile, deeplink injection, WebView bridge |
| `skills/cicd-security/` | CI/CD pipeline hunting — GitHub Actions injection, secret exfil, self-hosted runner poisoning |
| `skills/graphql-audit/` | GraphQL hunting — introspection, field suggestions, batching DoS, IDOR via aliasing, injection |
| `skills/api-security/` | **OWASP API Top 10 2023** — BOLA/IDOR, BFLA, mass assignment, broken auth, resource consumption, improper inventory, SSRF, unsafe consumption |
| `skills/cloud-security/` | Cloud (AWS/GCP/Azure) — bucket enum + takeover, metadata SSRF chains, exposed services, cloud subdomain takeover |
| `skills/kubernetes-security/` | K8s — unauth API server, anonymous RBAC, kubelet, dashboard skip-login, ingress, secrets in JS |
| `skills/active-directory/` | **Authorized internal only** — AS-REP/Kerberoast, relay checks, BloodHound DA paths, spray coordination |
| `skills/llm-security/` | **OWASP LLM Top 10 2025** — prompt injection (direct/indirect/multimodal), system-prompt leak, excessive agency, improper output handling, RAG/vector, DoW |
| `skills/race-conditions/` | TOCTOU — coupon/wallet/OTP/quantity races, pipelining/parallel/GraphQL-alias vectors, persistence confirmation |
| `skills/deserialization/` | Java/PHP/.NET/Python/Node — blob format detection, reflection probes, OOB DNS callbacks, safe exploitation rules |
| `skills/auth-attacks/` | Reset flows, OAuth/OIDC/SAML, MFA bypass, sessions, JWT, ATO chains |
| `skills/ssrf/` | SSRF sinks, filter bypass ladder, cloud metadata, blind/OOB confirmation |
| `skills/client-side-security/` | DOM XSS, prototype pollution, postMessage, CORS, CSRF, clickjacking, WS hijack |
| `skills/hunt-orchestrator/` | **OpenCode glue** — maps "hunt <target>" to exact toolkit commands + skill routes + Windows syntax |

### Commands (slash commands)

> **Note:** All commands are prefixed to avoid conflicts with Codex's built-in commands.
> `/resume` is a reserved Codex command — use `/pickup` to continue a previous hunt.

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
| `/wordlist-gen` | `/wordlist-gen <target>` — company-specific password wordlist; requires `--with-credential-attack` |
| `/osint-employees` | `/osint-employees <target>` — employee names + emails; requires `--with-credential-attack` |
| `/breach-check` | `/breach-check <wordlist>` — HIBP k-anonymity rank wordlist by breach count |
| `/spray` | `/spray <url> --mode http-form\|oauth\|o365\|okta --users <f> --passes <f>` — password spray with hard guards |
| `/graphql-audit` | `/graphql-audit <url>` — full GraphQL audit |

### Agents (16 — 1 primary `hunter` + 15 specialists)

- `recon-agent` — subdomain enum + live host discovery
- `report-writer` — generates H1/Bugcrowd/Immunefi reports
- `validator` — 4-gate checklist on a finding
- `web3-auditor` — smart contract bug class analysis
- `chain-builder` — builds A→B→C exploit chains
- `autopilot` — autonomous hunt loop (scope→recon→rank→hunt→validate→report)
- `recon-ranker` — attack surface ranking from recon output + memory
- `token-auditor` — fast meme coin/token rug pull and security analysis
- `credential-hunter` — orchestrates wordlist-gen + osint-employees + breach-check; HARD STOPS at spray for human go/no-go
- `api-hunter` — OWASP API Top 10 hunting (BOLA/BFLA/mass-assignment)
- `cloud-hunter` — bucket/takeover/metadata/exposed-service hunting
- `llm-hunter` — prompt injection, agentic AI, RAG hunting
- `race-hunter` — TOCTOU race condition hunting
- `business-logic-hunter` — workflow/state-machine, price/coupon/wallet-tampering, quota-abuse reasoning (bugs scanners can't fuzz)
- `novel-vuln-reasoner` — first-principles review for unknown bug classes (parser differentials, smuggling, deser, cache poisoning, chained lows)

OpenCode-specific copies (with `mode: subagent` frontmatter) live in
`.opencode/agents/`; the primary `hunter` agent is `.opencode/agent/hunter.md`.
The `agents/` folder is the single harness-neutral **source of truth** for every subagent; run `python scripts/convert_opencode.py` to regenerate `.opencode/agents/` + `.opencode/commands/` (it also prunes stale generated files). Never edit `.opencode/agents/` or `.opencode/commands/` by hand.

### Rules (always active)

- `rules/hunting.md` — 17 critical hunting rules
- `rules/reporting.md` — report quality rules

### Tools (Python/shell — in `tools/`)

See **`tools/README.md`** for the full ~50-tool catalogue. Highlights:

- `tools/hunt.py` — master orchestrator (auto lead-board ingest + EOL after recon; `--graphql` / `--cve-hunt` / `--zero-day`)
- `tools/lead_board.py` — persistent recon→skill lead ledger (`ingest` / `show` / `next` / `touch`)
- `tools/recon_engine.sh` · `vuln_scanner.sh` · `validate.py` · `scope_checker.py`
- `tools/graphql_audit.sh` · `cicd_scanner.sh` · `cve_scan.sh` · `eol_check.py`
- `tools/waf_encoder.py` · `waf_response_analyzer.py` · `multipart_mutator.py` · `bypass_403.sh`
- `tools/external_arsenal.sh` — installed-tool registry (~50 tools); `_have <tool>` gate
- `tools/secrets_hunter.sh` · `takeover_scanner.sh` · `cloud_recon.sh` · `param_discovery.sh`
- Credential attack (opt-in): `wordlist_engine.sh` · `osint_employees.sh` · `breach_checker.py` · `spray_orchestrator.sh`
- Web3: `token_scanner.py`

### External tool references

- `wordlists/REFERENCES.md` — pointers to SecLists / OneListForAll / fuzz4bounty / PayloadsAllTheThings
- `skills/security-arsenal/REFERENCES.md` — methodology, writeup archives, dorks, key-verification
- `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` — per-vuln quick-check tables

### MCP Integrations (in `mcp/`)

- `mcp/burp-mcp-client/` — Burp Suite proxy integration
- `mcp/hackerone-mcp/` — HackerOne public API (Hacktivity, program stats, policy)

### Hunt Memory (in `memory/`)

- `memory/pattern_db.py` — cross-target pattern learning
- `memory/audit_log.py` — request audit log, rate limiter, circuit breaker
- `memory/rotation.py` — size-based JSONL rotation (10MB cap, keep 3 backups), auto-fired on append
- `memory/schemas.py` — schema validation for all data
- `memory/leads/<target>.jsonl` — lead board ledger (via `lead_board.py`)

## Start Here

**OpenCode (primary harness):** `cd` to the repo root and run `opencode`.
Everything is pre-wired: 26 skills, 47 commands, 13 agents, 6 MCP servers
(Caido, Burp, HackerOne, Playwright, Nuclei, Shodan) in `opencode.json`.
Say `hunt target.com` to run the full agentic loop — see `skills/hunt-orchestrator/`
for the exact command mapping and `OPENCODE.md` for the guide.

**Windows note:** use `python` (not `python3`); run `.sh` tools via
`.\tools\run.ps1 <tool.sh> <args>` or `bash tools/<tool>.sh`.

```bash
Codex
# /recon target.com
# /hunt target.com
# /validate   (after finding something)
# /report     (after validation passes)
```

## Install Skills

```bash
chmod +x install.sh && ./install.sh
```

Install for another harness:

```bash
./install.sh --agent opencode          # ~/.config/opencode/skills + commands + agents
./install.sh --agent pi                # ~/.pi/agent/skills + prompt templates
./install.sh --agent codex             # ~/.codex/skills + commands
./install.sh --agent agents            # ~/.agents/skills shared by OpenCode/Pi
./install.sh --agent all               # every supported global target
./install.sh --agent opencode --project # local .opencode/ install
./install.sh --agent pi --project       # local .pi/ install
```

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. Park-and-return — a stalled lead gets parked (note why) and returned to before closing; never abandon it silently
6. **LEAD BOARD — never lose a lead.** After recon, run `lead_board.py ingest <target>` + `show`, and route each finding to its `hunt-*` skill in plain language ("GraphQL endpoint → hunt-graphql"). When starting/killing/reporting a lead, `touch` its status. The hunter focuses on one lead at a time; the board remembers the rest so none is forgotten. Surface stale high-priority leads unprompted.
