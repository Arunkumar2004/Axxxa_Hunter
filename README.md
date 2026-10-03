<p align="center">
  <img src="assets/banner.png" alt="Hunter 2 - AI-powered agentic bug bounty framework" width="100%"/>
</p>

# Hunter 2 — Agentic Bug Bounty Framework

**One folder. Full agentic bug bounty hunting, driven in plain English.**
Point it at a target, say **`hunt target.com`**, and it runs the entire
professional workflow — **scope → recon → lead ranking → vulnerability testing →
validation → report** — from either **OpenCode** or **Claude Code**.

- **57 commands** — one word per task (`hunt`, `recon`, `csrf`, `web3-audit`, …)
- **16 agents** — 1 primary `hunter` + 15 specialists (recon, API, cloud, LLM, race, business-logic, novel-vuln, validator, report-writer…)
- **27 skills** — professional methodology (OWASP API Top 10, LLM Top 10 2025, Web2 vuln classes, Web3…)
- **~80 tools** — real scanners & scripts (recon engine, IDOR/JWT/CORS/XXE/CSRF scanners, LLM red-team, OOB listener…)
- **6 MCP integrations** — Caido, Burp, HackerOne, Playwright browser, Nuclei, Shodan
- **Hunt memory** — findings/targets/leads persist across sessions

> ⚠️ **For authorized bug bounty testing only** — HackerOne / Bugcrowd / Intigriti /
> Immunefi engagements, CTFs, and your own targets. A deterministic scope checker
> gates every request; destructive HTTP methods and report submission require your approval.

---

## Table of Contents
1. [What's New in Hunter 2](#whats-new-in-hunter-2)
2. [Prerequisites](#1-prerequisites)
3. [Setup](#2-setup)
4. [How to Run](#3-how-to-run)
5. [MCP Setup (Caido, Burp, HackerOne, Nuclei, Shodan, Browser)](#4-mcp-setup)
6. [Full Command Reference](#5-full-command-reference-57)
7. [Agents](#6-agents-16)
8. [Skills](#7-skills-26)
9. [Key Tools](#8-key-tools)
10. [What It Finds](#9-what-it-finds)
11. [Installing External Tools (Arsenal)](#10-installing-external-tools-arsenal)
12. [Safety](#11-safety-always-on)
13. [Standalone Mode (no subscription)](#12-standalone-mode-no-subscription)
14. [Project Layout](#13-project-layout)
15. [Windows Notes & Troubleshooting](#14-windows-notes--troubleshooting)
16. [Development](#15-development)

---

## What's New in Hunter 2

### 🔥 EXTREME Upgrade — the active-hunter engine (Level 1 complete)

Hunter 2 now doesn't just *hold* knowledge — it **acts on it automatically**, identically in
Claude Code and OpenCode. Full plan + progress: [`TO_EXTREME.md`](TO_EXTREME.md).

- **Auto-playbook per lead** — every `hunt` writes `findings/<target>/PLAYBOOKS.md` and the
  agent opens the matching real-world playbook (checklist + rejection rules) before testing.
  (`tools/playbook_router.py`)
- **Two-account IDOR/BOLA harness** — `hunt <target> --two-account` replays account A's
  requests with account B's auth to find cross-tenant reads (the #1 money-bug move). Reads
  your own `ACCOUNT_A_*`/`ACCOUNT_B_*` from `.env`; safe methods by default; never logs
  tokens. (`tools/two_account_idor.py`)
- **Auto-chain after a hit** — each confirmed access-control hit auto-generates sibling
  (`/export`,`/delete`,`/v1/`…) + A→B next-tests → `findings/<target>/chains.json`.
  (`tools/chain_engine.py`)
- **Rejection gate in `/validate`** — auto-kills always-rejected findings (public keys like
  `rzp_live_*`, self-XSS, missing headers, theoretical, out-of-scope) before you waste a
  report. (`tools/rejection_gate.py`)
- **Learning memory** — every hunt records what worked / got rejected / dead-ended
  (`memory/hunt_outcomes.jsonl`); the next hunt loads it so the tool compounds.
  (`tools/hunt_memory.py`)
- **All 54 playbooks leveled** — every class now has tool mapping + test-flow checklist +
  rejection rules (54/54 on all three). Windows portability fixed (recon no longer skips).

#### Level 2 — the "thinks like a hunter" layer (2 of 3 built)
- **Attack-surface graph** — connects the flat URL list into a map
  (host → family → endpoint → param), flags IDOR/action candidates, sibling clusters, and
  version anomalies. `--probe` adds LIVE auth-probing (anon/A/B) → real missing-auth +
  cross-account leads + role reachability. (`tools/surface_graph.py` → `SURFACE_GRAPH.md`)
- **Feedback loop** — records real submission outcomes (PAID/REJECTED/DUPLICATE/
  INFORMATIVE); next hunt boosts paid techniques and avoids rejected ones.
  (`tools/feedback_loop.py`)
- *Not yet built:* hypothesis engine (the deep novel-reasoning piece — the remaining tier).

- **Verified:** full test suite **867 passed, 10 skipped**. Connection board
  (`py tools/start.py <target>`) shows what's armed before every hunt. See the one-page
  [`HUNT_RUNBOOK.md`](HUNT_RUNBOOK.md) and [`HOW_IT_HUNTS.md`](HOW_IT_HUNTS.md).

### 🧠 Real-Hunter Upgrade (Lead Commander + real-world knowledge)

The biggest change: Hunter 2 now runs like a **disciplined human attacker**, identically in
**Claude Code and OpenCode**, driven from a single crystal-clear starting point.

- **Start dashboard:** on `hunt <target>` the leader first runs `python tools/start.py
  <target>` — a big **AXXX HUNTER** banner + the live **Connection Board** (which tools,
  MCPs, proxies Caido/Burp, agents (16), skills (27), scope, and the Chromium login-window
  are actually armed) — **then** hunts. No silent starts, no assuming a tool is live.
- **Lead Commander doctrine** ([`rules/lead-commander.md`](Hunter2/rules/lead-commander.md)):
  full-power loop, **high→low priority**, **park-and-return** (no drift, no lead left behind),
  **always chain**, and a **consolidated report** proving nothing was missed.
- **Coverage Matrix** ([`rules/coverage-matrix.md`](Hunter2/rules/coverage-matrix.md)): the
  canonical **A→Z class list** (OWASP Web + API + LLM Top 10 + PortSwigger full topic list).
  Every class is tracked `FOUND / TESTED / N/A-with-reason / PENDING`; a hunt isn't "done"
  while any reachable class is `PENDING`.
- **`real-world-playbooks` skill:** **54 per-class playbooks** distilled from real
  disclosed **HackerOne reports** (`reddelexc/hackerone-reports` — technique + bounty + link)
  and hands-on **test-flow checklists** (`Az0x7/vulnerability-Checklist`), plus chaining
  recipes and Hunter2 tool wiring. Refresh anytime: `python scripts/gen_real_world_playbooks.py`.
- **Authenticated hunting, first-class:** the leader brings up **Caido/Burp**, has *you* log
  in (via `/login-capture` — creds never touch chat), then replays your authenticated
  requests to hunt IDOR/BOLA/BFLA/business-logic on protected APIs (two-account testing).
- **Interaction protocol:** at any **OTP / MFA / password / captcha / login** wall the agent
  **stops and asks you** — never skips the page, never enters your credentials, never solves a
  CAPTCHA. The **browser MCP** (`@playwright/mcp` via Node/npx — no Python playwright needed)
  opens a real Chromium window; you log in there (OTP/MFA) and the hunt resumes authenticated.
  (`/login-capture`, which also saves the session to `.private/`, is an optional
  Python-playwright alternative.)
- **Lightweight learning loop:** reads prior per-target memory (`lead_board.py`,
  `memory/leads/<target>.notes.md`) at start and writes back what worked/what was N/A at the
  end — each hunt makes the next one smarter.
- **Dual-CLI parity fixes:** the full-power Operating Contract now lives in **both**
  `CLAUDE.md` and `AGENTS.md`/`hunter.md`; `.mcp.json` corrected (all 6 MCPs, relative paths,
  fixed the broken Caido path + missing `--mcp` on HackerOne) so Claude Code and OpenCode
  behave the same.

- **5 new web scanners:** `/csrf`, `/xxe`, `/proto-pollution`, `/websocket` (CSWSH), `/hpp` (HTTP param pollution + `postMessage`). Each has a pure, unit-tested classifier and takes `--json`, `--cookie`, `-l list`.
- **2 reasoning agents:** `business-logic-hunter` (workflow/price/coupon/wallet abuse) and `novel-vuln-reasoner` (unknown bug classes + chaining low findings into criticals).
- **Recon power** (`/recon-plus`): favicon-hash pivot (Shodan/Censys/FOFA), JS source-map extraction (recover source + secrets), OpenAPI/Swagger → auto IDOR/BOLA test plan.
- **`/login-capture`:** open a real browser, log in manually (credentials go into the site, never chat), session auto-captured to `.private/<target>.json`; the hunt pauses on login walls and resumes authenticated.
- **`/parallel-hunt`** (scope-gated multi-host), **`/replay`** (re-verify findings: VULNERABLE/FIXED/CHANGED), and browser-in-loop for SPA targets.
- **Upgraded `/web3-audit`:** automated analyzers — slither + aderyn (static), mythril + halmos (symbolic), echidna + medusa (fuzzing).
- **Upgraded `/llm-redteam`:** output→dangerous-sink (LLM02), multi-turn crescendo jailbreaks, multimodal (image) injection.
- **Newly wired tools:** dalfox + **xsstrike** (XSS), **whatwaf** (WAF fingerprint), **fuxploider** (upload bypass).
- **Single source of truth:** edit `agents/` + `commands/`; `scripts/convert_opencode.py` regenerates `.opencode/` and prunes stale files. Test suite: **768 passing**.

See [CHANGELOG.md](CHANGELOG.md) for the full history.

---

## 1. Prerequisites

- **Python 3.10+** — <https://www.python.org/downloads/>
- **An agent CLI**, either:
  - **[OpenCode](https://opencode.ai)** — recommended, fully agentic (default agent `hunter`)
  - **[Claude Code](https://claude.com/claude-code)**
- **Git** (for cloning + a few git-based tools)
- **(Optional) external security tools** — installed on demand; anything missing is skipped, never fatal.

---

## 2. Setup

```bash
# 1. Get the code
git clone <your-hunter2-repo> && cd Hunter2

# 2. Python deps
pip install -r requirements.txt

# 3. Install the hunting toolchain by profile (start with core)
python tools/arsenal.py install --profile core --yes
#    profiles: core | recon | web | api | cloud | secrets | mobile | web3 | all
#    Windows: .\install_tools.ps1 -Profile core

# 4. (optional) check what's installed
python tools/arsenal.py status
```

Nothing else to configure to start — skills, commands, agents, and MCP config all
load from this folder.

### OpenCode
```bash
opencode          # run inside the Hunter2 folder — the "hunter" agent loads automatically
```

### Claude Code
```bash
claude            # run inside the folder; commands live in commands/, settings in .claude/settings.json
```

Both CLIs share the same commands, agents, and skills.

---

## 3. How to Run

You can drive Hunter 2 two ways — **plain English** or **slash commands**. Both work in either CLI.

### Plain English (talk to the `hunter` agent)
```
hunt example.com
hunt example.com for IDOR, CORS, and business-logic bugs
recon example.com
login-capture https://example.com/login      # then: hunt authenticated
validate        # run the finding-quality gate on your latest finding
report          # draft a submission-ready report
```

### Slash commands
```
/hunt example.com
/csrf https://example.com/account --cookie "session=..."
/recon-plus favicon https://example.com
/web3-audit ./contracts-repo
/parallel-hunt hosts.txt --jobs 8 --scope scope.txt
```

### What `hunt target.com` actually does
```
1. SCOPE      scope_checker.py confirms authorized; policy fetched via HackerOne MCP
2. RECON      subfinder / httpx / katana / nuclei  ->  recon/<target>/
3. LEAD BOARD every attack surface becomes a lead ("GraphQL endpoint -> graphql-audit")
4. RANK       picks the highest-impact lead (auth / IDOR / SSRF / business-logic first)
5. HUNT       the matching skill + tools attack that lead (through Caido/Burp proxy)
6. VALIDATE   finding-quality gate; weak findings are killed
7. REPORT     drafts a submission-quality report  (never submitted without your approval)
8. REMEMBER   memory + lead board updated for the next session
```

---

## 4. MCP Setup

MCP servers give the agent extra powers (proxy, program scope, real browser, CVE
templates, internet intel). They're **declared in `opencode.json`** — provide the
env var / prerequisite and the server auto-starts. Check status with
`opencode mcp list` (or `Ctrl+O` → MCP in the TUI).

| Server | What it gives you | Setup |
|--------|-------------------|-------|
| **HackerOne** | Program scope, policy, disclosed reports → automatic scope safety | ✅ zero setup (Python server in `mcp/`) |
| **Nuclei** | 10,000+ CVE / misconfig template scans | ✅ zero setup (Python server in `mcp/`); needs the `nuclei` binary |
| **Browser (Playwright)** | Real browser — clicks logins, proves DOM XSS | ✅ zero setup (`npx @playwright/mcp`, auto-downloads Chromium) |
| **Caido** | Intercept/replay traffic; IDOR/auth hunting | Set `CAIDO_URL` (e.g. `http://127.0.0.1:8080`); `tools/bin/caido-mcp-server.exe` present. On Windows run `tools/bin/caido-mcp-server.exe login` once, then restart. |
| **Burp** | Same as Caido, via Burp Suite | Optional. Set `BURP_MCP_JAR` to the Burp MCP jar; run Burp's MCP extension on `:9876`. |
| **Shodan** | Exposed ports/services/CVEs, real IPs behind CDNs | Optional. Set your Shodan API key env var. |

Set env vars in your shell before launching, e.g.:
```bash
export CAIDO_URL="http://127.0.0.1:8080"
export BURP_MCP_JAR="/path/to/burp-mcp.jar"
export SHODAN_API_KEY="..."          # your key
opencode
```
Each user logs into Caido/Burp locally with their own credentials.

---

## 5. Full Command Reference (57)

Run `/<name>` in either CLI, or the underlying `tools/*` directly.

### Core loop
| Command | Purpose |
|---------|---------|
| `/hunt <target>` | Full agentic loop (scope → recon → rank → hunt → validate → report) |
| `/autopilot <target> [--paranoid\|--normal\|--yolo]` | Autonomous hunt with configurable checkpoints |
| `/recon <target>` | Recon only (subdomains, live hosts, URLs, attack surface) |
| `/validate` | Finding-quality gate — kills weak findings |
| `/report` | Draft a submission-ready report |
| `/triage` | Triage / prioritize current findings |
| `/chain` | Build A→B→C exploit chains |
| `/pickup <target>` | Resume a previous hunt |
| `/remember` | Log a finding/lead to hunt memory |

### Scope & intelligence
| Command | Purpose |
|---------|---------|
| `/scope <target>` | Verify an asset is in-scope/authorized |
| `/scope-aggregate` | Aggregate scope across programs |
| `/intel <target>` | OSINT / target intelligence |
| `/surface` | Attack-surface overview |

### Recon & discovery
| Command | Purpose |
|---------|---------|
| `/recon-plus favicon\|sourcemap\|idor <arg>` | Favicon-hash pivot · JS source-map extraction · OpenAPI→IDOR plan |
| `/param-discover <url>` | Hidden parameter discovery |
| `/portscan <target>` | Port/service scan (non-web services) |
| `/scan-cves <target>` | CVE template sweep |
| `/screenshot <targets>` | Visual triage gallery (PoC evidence) |
| `/arsenal [tool]` | External tool inventory / install hints |

### Web scanners
| Command | Purpose |
|---------|---------|
| `/csrf <url>` | CSRF (anti-CSRF token + SameSite) |
| `/xxe <url> [--oob URL]` | XML external entities (internal → error-based → blind OOB) |
| `/proto-pollution <url> [--active]` | Prototype pollution (client gadgets + server `__proto__`) |
| `/websocket <ws-url>` | Cross-Site WebSocket Hijacking (CSWSH) |
| `/hpp <url?param=x>` | HTTP parameter pollution + `postMessage` origin checks |
| `/cors <url>` | CORS misconfiguration |
| `/crlf <url>` | CRLF / response splitting / host-header injection |
| `/nosqli <url>` | NoSQL injection |
| `/jwt-scan <token>` | JWT forgery / alg confusion / secret crack |
| `/domxss <url>` | DOM XSS confirmation (headless browser) |
| `/bypass-403 <url>` | 403/401 access-control bypass |
| `/client-side <url>` | Client-side security sweep |
| `/ssrf-chain <url>` | SSRF → cloud-metadata chains |
| `/deser-hunt <url>` | Deserialization probing |
| `/sast <path\|url>` | Static analysis (Semgrep) over fetched source |

### API, auth & sessions
| Command | Purpose |
|---------|---------|
| `/api-audit <url>` | OWASP API Top 10 (BOLA/BFLA/mass-assignment…) |
| `/login-capture <login-url>` | Real-browser manual login → capture session to `.private/` |
| `/auth-hunt <target>` | Authentication attack surface |
| `/spray` | Password spraying (HARD-STOPS for human go/no-go) |
| `/wordlist-gen` | Target-specific wordlist generation |
| `/osint-employees` | Employee OSINT (for auth testing) |
| `/breach-check` | Breach-data checks |

### LLM / AI
| Command | Purpose |
|---------|---------|
| `/llm-hunt <target>` | LLM/AI feature hunting (OWASP LLM Top 10) |
| `/llm-redteam --url … [--crescendo\|--multimodal FIELD\|--category output-sink]` | Prompt injection, jailbreak, output→sink, crescendo, multimodal |

### Cloud & infra
| Command | Purpose |
|---------|---------|
| `/cloud-hunt <target>` | Cloud misconfig / exposed services |
| `/cloud-recon <target>` | Cloud asset recon |
| `/k8s-audit <target>` | Kubernetes audit |
| `/takeover <target>` | Subdomain takeover |
| `/secrets-hunt <target>` | Secret/credential leaks |

### Web3
| Command | Purpose |
|---------|---------|
| `/web3-audit <contract\|repo>` | Smart-contract audit + automated analyzers (slither/aderyn/mythril/echidna/medusa/halmos) |
| `/token-scan <token>` | Meme-coin / token rug-pull analysis |

### Loop utilities
| Command | Purpose |
|---------|---------|
| `/parallel-hunt hosts.txt [--jobs N] [--scope f]` | Scope-gated concurrent multi-host hunting |
| `/replay finding.json [--dir]` | Re-verify findings (VULNERABLE/FIXED/CHANGED) |
| `/oob` | OOB/interactsh listener for blind bug confirmation |
| `/memory-gc` | Rotate/prune hunt memory |

### Internal (authorized engagements only)
| Command | Purpose |
|---------|---------|
| `/ad-hunt` | Active Directory hunting (authorized internal only) |
| `/mobile-scan <app.apk>` | Mobile app static scan (apkleaks/mobsf/objection) |

---

## 6. Agents (16)

The primary **`hunter`** agent orchestrates the rest automatically; you can also invoke any subagent directly.

`recon-agent` · `recon-ranker` · `autopilot` · `validator` · `report-writer` ·
`chain-builder` · `api-hunter` · `cloud-hunter` · `llm-hunter` · `race-hunter` ·
`business-logic-hunter` · `novel-vuln-reasoner` · `credential-hunter` ·
`web3-auditor` · `token-auditor`

Agents live in `agents/` (**single source of truth**); run
`python scripts/convert_opencode.py` after editing to regenerate the OpenCode copies.

---

## 7. Skills (27)

Methodology playbooks the agents apply automatically.

- **Core:** `bug-bounty` (master) · `bb-methodology` · `hunt-orchestrator` · `real-world-playbooks` (real HackerOne-report tradecraft + per-class chaining, 44 classes) · `triage-validation` · `report-writing`
- **Web:** `web2-recon` · `web2-vuln-classes` · `security-arsenal` · `client-side-security` · `ssrf` · `api-security` · `auth-attacks` · `race-conditions` · `deserialization` · `graphql-audit` · `argus`
- **AI / CI:** `llm-security` · `cicd-security` · `client-reverse`
- **Web3:** `web3-audit` · `meme-coin-audit`
- **Mobile:** `mobile-pentest`
- **Cloud / Infra:** `cloud-security` · `kubernetes-security` · `credential-attack` · `active-directory` (authorized internal only)

### Real-World Knowledge (5 sources + payload corpus)

The `real-world-playbooks` skill is the agent's real-hacker knowledge base — **44 per-class
files** in `skills/real-world-playbooks/references/<class>.md`, each carrying the full
attacker flow for that bug: real reports → checklist → real payloads → real methodology →
chaining. It is distilled live over HTTPS from **five public sources**:

| Source | What it contributes |
|--------|---------------------|
| [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) | top **disclosed HackerOne reports** per class (technique + bounty + link) |
| [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) | ordered **test-flow checklist** per class |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | **real payloads + filter bypasses** per class |
| [OWASP WSTG](https://github.com/OWASP/wstg) | authoritative **testing methodology** per class |
| [KathanP19/HowToHunt](https://github.com/KathanP19/HowToHunt) | step-by-step **hunting methodology** per class |
| [daffainfo/AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) | concise **real technique notes** per class |
| [HackTricks](https://github.com/HackTricks-wiki/hacktricks) | short **methodology excerpt + link** per class (non-commercial: excerpt only) |

Coverage after this pass: **methodology on 42/44 classes, real payloads on 28/44** (a class with no match simply omits that section).

Refresh any time new reports land (self-contained, mirrors for both CLIs):

```bash
python scripts/gen_real_world_playbooks.py
cp -r skills/real-world-playbooks .claude/skills/real-world-playbooks   # Claude Code parity
```

**Scanner payload corpus:** the active scanners also fire real payloads from
`tools/payloads/*.txt` via `tools/payload_loader.py` (currently `nosqli`, `crlf`, `xxe`),
keeping their built-ins as a fallback so detection never regresses. Add a `<class>.txt`
there to extend a scanner's payloads without touching code.

---

## 8. Key Tools

`tools/` holds ~80 scanners and scripts. Highlights:

| Tool | What it does |
|------|--------------|
| `hunt.py` | Master orchestrator (recon + scan + leads + report) |
| `recon_engine.sh` | Subdomains, live hosts, URLs, nuclei sweep |
| `vuln_scanner.sh` | XSS (dalfox+xsstrike) · SQLi · SSTI · SSRF · WAF (whatwaf) · upload (fuxploider) pipeline |
| `csrf_scanner.py` · `xxe_scanner.py` · `prototype_pollution_scanner.py` · `websocket_scanner.py` · `hpp_postmessage_scanner.py` | The new web scanners |
| `cors_scanner.py` · `crlf_scanner.py` · `nosqli_scanner.py` · `jwt_scanner.py` | Core web-class scanners |
| `favicon_hash.py` · `sourcemap_extract.py` · `apispec_idor.py` | Recon-plus tools |
| `login_capture.py` · `finding_replay.py` · `parallel_hunt.sh` | Session capture · finding re-verify · multi-host |
| `h1_idor_scanner.py` · `h1_mutation_idor.py` · `h1_race.py` · `h1_oauth_tester.py` | IDOR / race / OAuth |
| `api_security_scanner.py` | API Top 10 audit |
| `web3_audit.sh` | Automated smart-contract analyzers |
| `llm_redteam.py` | LLM red-team (injection/jailbreak/output-sink/crescendo/multimodal) |
| `deser_probe.py` · `oob_listener.py` · `dom_xss_harness.py` | Deser · blind-OOB · DOM-XSS confirmation |
| `scope_checker.py` · `lead_board.py` | Deterministic scope safety · persistent lead ledger |

---

## 9. What It Finds

Every vulnerability class Hunter 2 hunts, and the command/tool that finds each.

### Access control
| Vulnerability | Find it with |
|---|---|
| IDOR / BOLA (object-level auth) | `/api-audit`, `tools/h1_idor_scanner.py`, `/recon-plus idor` |
| Write-path / mutation IDOR | `tools/h1_mutation_idor.py` |
| BFLA (broken function-level auth) | `/api-audit` |
| Mass assignment / BOPLA | `/api-audit` |
| Privilege escalation | `/auth-hunt`, `business-logic-hunter` |
| 403 / 401 access-control bypass | `/bypass-403` |

### Authentication & account takeover
| Vulnerability | Find it with |
|---|---|
| JWT forgery / alg confusion / weak secret | `/jwt-scan` |
| OAuth flaws (state CSRF, redirect_uri, PKCE, code leak) | `/auth-hunt`, `tools/h1_oauth_tester.py` |
| SAML / SSO (signature wrapping, XSW) | `/auth-hunt`, `vuln_scanner.sh` |
| Password-reset flaws | `/auth-hunt` |
| MFA / 2FA bypass | `/auth-hunt`, `vuln_scanner.sh` |
| Session fixation / weak session mgmt | `/auth-hunt` |
| Password spraying (authorized) | `/spray` |

### Injection
| Vulnerability | Find it with |
|---|---|
| SQL injection | `vuln_scanner.sh` (nuclei/ghauri/sqlmap) |
| NoSQL injection | `/nosqli` |
| XSS — reflected | `/hunt`, `vuln_scanner.sh` (dalfox + xsstrike) |
| XSS — DOM | `/domxss` (headless-browser confirmation) |
| XSS — stored / via LLM output | `vuln_scanner.sh`, `/llm-redteam` |
| SSTI (template injection) | `vuln_scanner.sh` |
| Command injection | `/hunt`, `oob_listener.py` (blind) |
| CRLF / HTTP response splitting / host-header injection | `/crlf` |
| XXE (XML external entities) | `/xxe` |
| LDAP / header / log injection | `/hunt`, skills |

### Client-side
| Vulnerability | Find it with |
|---|---|
| CSRF | `/csrf` |
| Prototype pollution (client + server) | `/proto-pollution` |
| Cross-Site WebSocket Hijacking (CSWSH) | `/websocket` |
| postMessage listeners missing origin check | `/hpp` |
| HTTP Parameter Pollution (HPP) | `/hpp` |
| CORS misconfiguration | `/cors` |
| Open redirect | `/hunt`, `/client-side` |
| Clickjacking / client-side misconfig | `/client-side` |

### SSRF, cloud & infrastructure
| Vulnerability | Find it with |
|---|---|
| SSRF (→ cloud metadata → creds) | `/ssrf-chain` |
| Public S3 / GCS / Azure buckets | `/cloud-hunt`, `cloud_bucket_enum.py` |
| Bucket / subdomain takeover | `/takeover` |
| Exposed services (Redis, Docker, k8s, DBs, RDP, SMB) | `/portscan`, `/cloud-hunt` |
| Kubernetes misconfig | `/k8s-audit` |
| Cloud metadata / IMDS chains | `/ssrf-chain`, `/cloud-recon` |
| Known CVEs / template hits | `/scan-cves` (nuclei) |

### Business logic
| Vulnerability | Find it with |
|---|---|
| Race conditions (coupon/OTP/wallet double-spend) | `/race`, `business-logic-hunter` |
| Price / quantity / currency tampering | `business-logic-hunter` |
| Coupon / referral / cashback abuse | `business-logic-hunter` |
| Workflow / state-machine bypass | `business-logic-hunter` |
| Quota / rate-limit evasion | `business-logic-hunter` |

### Novel & chained (reasoning)
| Vulnerability | Find it with |
|---|---|
| HTTP request smuggling (CL.TE / TE.CL) | `novel-vuln-reasoner`, `vuln_scanner.sh` |
| Parser differentials | `novel-vuln-reasoner` |
| Deserialization RCE (Java/PHP/.NET/Python) | `/deser-hunt`, `deser_probe.py` |
| Web cache poisoning / deception | `novel-vuln-reasoner` |
| Type / logic confusion | `novel-vuln-reasoner` |
| Low → critical exploit chains | `chain-builder`, `novel-vuln-reasoner` |

### AI / LLM
| Vulnerability | Find it with |
|---|---|
| Prompt injection (direct + indirect) | `/llm-redteam`, `/llm-hunt` |
| Jailbreak / guardrail bypass | `/llm-redteam` |
| Multi-turn crescendo jailbreak | `/llm-redteam --crescendo` |
| Multimodal (image) injection | `/llm-redteam --multimodal` |
| System-prompt leak | `/llm-redteam` |
| Output → dangerous sink (LLM02) | `/llm-redteam --category output-sink` |
| RAG poisoning / excessive agency | `/llm-hunt` |

### Web3 / smart contracts
| Vulnerability | Find it with |
|---|---|
| Reentrancy, access control, integer bugs | `/web3-audit` (slither/aderyn/mythril) |
| Invariant / property violations | `/web3-audit` (echidna/medusa/halmos) |
| Accounting desync, oracle, flash-loan, signature replay, proxy/upgrade | `/web3-audit` (10-class checklist) |
| Meme-coin rug pull / token authority | `/token-scan` |

### Recon-surfaced exposures
| Vulnerability | Find it with |
|---|---|
| Secret / API-key leaks | `/secrets-hunt` |
| JS source-map source & secret disclosure | `/recon-plus sourcemap` |
| Hidden endpoints / API surface | `/recon-plus`, `/param-discover` |
| GraphQL introspection / batching / alias-IDOR | `/hunt` + `graphql-audit` skill |
| CI/CD pipeline injection | `sast_scan.py`, `cicd-security` skill |
| Mobile app secrets / endpoints (APK) | `/mobile-scan` |

---

## 10. Installing External Tools (Arsenal)

### Do I need to install everything? — No.

Two separate things:

- **Hunter itself** (57 commands, 16 agents, 27 skills, ~80 `tools/` scripts) — **already included, ~15 MB, no install.** It just needs Python. The pure-Python scanners (CSRF, XXE, CORS, JWT, prototype-pollution, WebSocket, HPP, recon-plus…) and the AI reasoning work with **zero external tools**.
- **External tools** (nuclei, ffuf, xsstrike, Chromium, slither…) — **optional add-ons**, installed system-wide (not into the Hunter folder), only the ones you want. Anything missing is **skipped with a hint**, never a crash.

### Disk footprint — pick your level

| Level | Install | Size |
|-------|---------|------|
| **Start (pure-Python + AI)** | nothing (Python only) | **~15 MB** |
| **Full WEB hunting** (recommended) | `--profile core` + `--profile web` | **~1 GB** |
| **+ browser bugs** (DOM XSS, login-capture) | + Playwright Chromium | +~0.5–1 GB |
| **Absolute everything** | `--profile all` + SecLists | ~4–5 GB |

> The big 3–4 GB extras — **mobile** (mobsf/jadx), **web3** (slither/echidna/…),
> **SecLists** wordlists, and **Chromium** — are only needed if you actually use
> those features. Web-only hunters skip them.

### Recommended lean web setup (~1 GB)

```bash
python tools/arsenal.py install --profile core --yes   # recon + scan (28 tools)
python tools/arsenal.py install --profile web  --yes   # web-vuln kit (12 tools: xsstrike, whatwaf, dalfox, ffuf, nuclei…)
# Windows: .\install_tools.ps1 -Profile core   then   -Profile web
```

**`core`** (28) = subdomain/DNS recon (subfinder, amass, dnsx…), live-host probing
(httpx, naabu…), URL crawling (katana, gau, waybackurls…), fuzzing (ffuf,
feroxbuster, gobuster), and CVE scanning (nuclei).
**`web`** (12) = XSS (dalfox, xsstrike), param discovery (arjun, x8), WAF
fingerprint/bypass (whatwaf, byp4xx, unwaf), JS analysis (linkfinder).

### Other profiles (install only if you need them)

```bash
python tools/arsenal.py status                        # what's installed vs missing
python tools/arsenal.py install --profile api    --yes   # API/GraphQL/JWT
python tools/arsenal.py install --profile cloud  --yes   # bucket/takeover/scout
python tools/arsenal.py install --profile secrets --yes  # trufflehog, gitleaks…
python tools/arsenal.py install --profile web3   --yes   # slither, aderyn, mythril, echidna, medusa, halmos
python tools/arsenal.py install --profile all    --yes   # everything (excludes credential-attack)
```

Because external tools install **system-wide** (Go bin, pipx venvs, tool caches),
the Hunter folder you share with someone stays a **~15 MB zip** — they install only
the profiles they want.

---

## 11. Safety (always on)

1. **Scope check on every request** (`scope_checker.py`) — out-of-scope = blocked + logged.
2. **No report submitted** without explicit human approval (all modes, including `--yolo`).
3. **Safe HTTP methods** auto-only; PUT/DELETE/PATCH need approval.
4. **Credentials** stay in the browser / `.private/` (gitignored, chmod 600 on POSIX) — never in chat or transcripts.
5. **Circuit breaker + rate limits** back off on WAF / rate-limit / error storms.
6. **Audit log** of every request in `hunt-memory/audit.jsonl` (auth values never logged).
7. **Password spraying + AD hunting** hard-stop for a human go/no-go.

---

## 12. Standalone Mode (no subscription)

Hunter 2 also runs **without an agent-CLI subscription** using the bundled
`engine.py` / `brain.py` with free or local AI providers:

```bash
python engine.py            # or:  ./bughunter setup   (configure a provider)
```
Supported providers include **Ollama** (fully offline), **Groq** (free cloud),
**OpenRouter**, and **OrcaRouter**. See [FAQ.md](FAQ.md) for provider setup and
auto-detection details.

---

## 13. Project Layout

```
agents/        16 subagent definitions      (SINGLE SOURCE OF TRUTH)
commands/      57 slash commands
skills/        27 methodology skills
tools/         ~80 scanners / recon / session / utility tools
mcp/           HackerOne + Nuclei MCP servers
.opencode/     OpenCode copies              (GENERATED — do not edit by hand)
.claude/       Claude Code settings
scripts/       convert_opencode.py          (regenerate + prune .opencode/)
tests/         pytest suite                 (768 passing)
docs/          TUTORIAL, capability gaps, advanced techniques, TODOs
engine.py      standalone runner (free/local AI providers)
opencode.json  OpenCode + MCP configuration
```

---

## 14. Windows Notes & Troubleshooting

- Use **`python`** (not `python3`).
- Run shell tools via Git Bash wrapper: `.\tools\run.ps1 recon_engine.sh target.com`
- Quick helpers: `.\hunt.ps1 target.com` · `.\bughunter.ps1 recon target.com`
- Install tools: `.\install_tools.ps1 -Profile core`

| Problem | Fix |
|---------|-----|
| Skills/commands not showing | Restart the CLI **inside** this folder |
| Caido not connecting | Start Caido → `tools/bin/caido-mcp-server.exe login` → restart |
| MCP not working | `opencode mcp list` → check env vars → restart |
| `python3` not found (Windows) | Use `python` |
| `.sh` won't run (Windows) | `.\tools\run.ps1 tool.sh args` (Git Bash auto) |
| A scanner "skips" a tool | Install it: `python tools/arsenal.py install --profile <p> --yes` |

---

## 15. Development

```bash
python -m pytest -q                    # run the suite (768 tests)
python scripts/convert_opencode.py     # after editing agents/ or commands/ (regenerates + prunes .opencode/)
```

House rule: every new scanner ships a **pure, unit-tested classifier** plus a
networked `scan()` and a `--json` / `--cookie` / `-l list` CLI. Copy any
`tools/*_scanner.py` and its `tests/test_*` as the template.

---

*Use responsibly and only against targets you are authorized to test.*
