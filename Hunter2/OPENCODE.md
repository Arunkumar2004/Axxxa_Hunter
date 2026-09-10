# Bug Bounty Hunter — OpenCode (Full Agentic)

This repo is a **complete OpenCode setup** for professional bug bounty hunting
(HackerOne, Bugcrowd, Intigriti, Immunefi, Web3). Everything is wired in the
repo — no extra install steps besides OpenCode itself.

## Quick Start

```bash
cd Agentic-Bug-Hunter
opencode
```

OpenCode auto-loads (from the repo root):
- **Skills** (26) — from `./skills` (registered via `skills.paths` in `opencode.json`)
- **Commands** (47) — from `.opencode/commands/`
- **Agents** (13) — `.opencode/agent/hunter.md` (primary) + `.opencode/agents/*.md` (subagents)
- **MCP servers** (6) — `opencode.json` → `mcp`
- **Instructions** — `AGENTS.md` at repo root

Then just say:

| You say | What happens |
|---|---|
| `hunt target.com` | Full agentic loop: scope → recon → lead board → rank → hunt → validate → report (human approves submit) |
| `recon target.com` | Recon pipeline via `hunt.py` |
| `validate <finding>` | 7-Question Gate via `validate.py` |
| `report` | Draft report via `report-writing` skill |
| `chain` | A→B→C exploit chain builder |
| `api-audit <url>` | OWASP API Top 10 audit (`api_security_scanner.py`) |
| `llm-hunt <url>` | Prompt injection / jailbreak / leak red-team |
| `cloud-hunt <domain>` | Buckets, metadata SSRF, exposed services, takeover |
| `k8s-audit <host>` | Unauth kube API / kubelet / dashboard |
| `race <url>` | Concurrent TOCTOU racing |
| `deser-hunt <url>` | Insecure deserialization probes |
| `ssrf-chain <url> --param url` | SSRF + bypass ladder + OOB confirm |
| `auth-hunt <url>` | Reset / OAuth / MFA / JWT / ATO chains |
| `client-side <url>` | DOM XSS / proto pollution / postMessage / CORS |
| `ad-hunt <domain> <dc>` | Authorized AD engagement only |
| `autopilot <target>` | Full autonomous loop (delegates to autopilot agent) |

Commands are prompt templates — the agent executes the toolkit directly
(`python tools/*.py`, `bash tools/*.sh`), it does **not** re-implement the
methodology.

## MCP Servers (pre-wired in `opencode.json`)

| Server | Package | Needs |
|---|---|---|
| `caido` | bundled `tools/bin/caido-mcp-server.exe serve` | Caido running; each user logs in once |
| `burp` | `java -jar <jar> --sse-url http://127.0.0.1:9876` | `BURP_MCP_JAR` env var (absolute path to `mcp-proxy-all.jar`) |
| `hackerone` | `python mcp/hackerone-mcp/server.py --mcp` | nothing (public API) |
| `browser` | `npx @playwright/mcp` | nothing |
| `nuclei` | `python mcp/nuclei-mcp/server.py` | `nuclei` binary on PATH |
| `shodan` | `npx @burtthecoder/mcp-shodan` | `SHODAN_API_KEY` env var |

For Caido on Windows, start Caido and run this once from the project folder:

```powershell
 $env:CAIDO_URL = "http://127.0.0.1:8080"
 .\tools\bin\caido-mcp-server.exe login
```

The login is stored locally for that user. Do not share Caido tokens or login data.

Optional integrations use these environment variables:

```powershell
$env:BURP_MCP_JAR  = "C:\tools\mcp-proxy-all.jar"
$env:SHODAN_API_KEY = "..."
```

Check status: `opencode mcp list`. Missing env vars make only that server fail
— the rest keep working. Disable any server by setting `"enabled": false` in
`opencode.json`.

## Windows (PowerShell) notes

- Use `python` (not `python3`) — `python3` may not exist on Windows.
- `.sh` tools run via Git Bash/WSL: `bash tools/recon_engine.sh target.com`
- Or use the wrapper: `.\tools\run.ps1 recon_engine.sh target.com`
- Quick CLI: `.\hunt.ps1 target.com`, `.\bughunter.ps1 recon target.com`
- PowerShell `-LiteralPath` doesn't expand wildcards — use `-Path` with globs.

## Agents

- **`hunter`** (primary, default) — full agentic orchestrator; loads skills per
  phase, routes to subagents, enforces scope/validate/report gates.
- Subagents: `recon-agent`, `recon-ranker`, `validator`, `report-writer`,
  `chain-builder`, `autopilot`, `web3-auditor`, `token-auditor`,
  `credential-hunter`, `api-hunter`, `cloud-hunter`, `llm-hunter`, `race-hunter`.

All subagents run `mode: subagent`; they're invoked via the `task` tool.
Files in `.opencode/agents/` use OpenCode frontmatter
(`description`/`mode`); the shared `agents/` folder keeps the harness-neutral
versions used by other agents (Claude/Codex/etc.).

## Skills (26)

`bb-methodology`, `bug-bounty`, `web2-recon`, `web2-vuln-classes`,
`security-arsenal`, `triage-validation`, `report-writing`, `web3-audit`,
`meme-coin-audit`, `graphql-audit`, `mobile-pentest`, `cicd-security`,
`credential-attack`, `client-reverse`, `argus`,
**+ new ultra skills**: `api-security`, `cloud-security`, `kubernetes-security`,
`active-directory`, `llm-security`, `race-conditions`, `deserialization`,
`auth-attacks`, `ssrf`, `client-side-security`, `hunt-orchestrator`.

`hunt-orchestrator` is the glue skill — it maps a natural-language request to
the exact toolkit commands and skill routes. Load it first in every session.

## Memory & Lead Board

- `python tools/lead_board.py ingest <target>` → `show` → never lose a lead.
- `python tools/lead_board.py touch <lead> <status>` — update lead status.
- Hunt memory JSONL auto-rotates at 10MB; manual: `python -m tools.memory_gc --rotate`.

## Rules (always active)

1. READ FULL SCOPE FIRST — only test what the program allows
2. ONLY REAL BUGS — "Can an attacker do this RIGHT NOW?" if no, stop
3. KILL WEAK FINDINGS FAST — 30-second check saves hours
4. NEVER GO OUT OF SCOPE
5. 5-MINUTE RULE — no progress? move to the next lead
6. VALIDATE BEFORE REPORT — `validate.py` 7-Question Gate
7. IMPACT FIRST

## Troubleshooting

- **Skills not loading**: check `opencode.json` `skills.paths` → `./skills`;
  restart opencode.
- **Commands not showing**: confirm files in `.opencode/commands/*.md`;
  restart opencode.
- **MCP not connecting**: `opencode mcp list`; verify env vars; restart.
- **Config error on start**: run with
  `$env:OPENCODE_DISABLE_PROJECT_CONFIG=1; opencode`, fix the file, restart.
- After editing `opencode.json` / agents / skills → **quit and restart opencode**
  (config is loaded once at startup).

---

**Built by bug hunters, for bug hunters.** For authorized security testing only.
Test only within an approved bug bounty program scope.
