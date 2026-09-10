---
name: hunt-orchestrator
description: Use when the user says "hunt", "autopilot", "start hunting", "full scan", or when starting any bug bounty session in OpenCode. The OpenCode agentic orchestrator: maps a natural-language hunt request to the exact toolkit commands (scope → recon → lead board → rank → hunt → validate → report), with skill routing, Windows/PowerShell command syntax, and the safety gates. Load FIRST in every OpenCode hunting session.
---

# Hunt Orchestrator (OpenCode)

This skill is the glue between you (the user) and the Agentic-Bug-Hunter toolkit. It tells the agent exactly what to run for each request.

## How to run a hunt (say: "hunt target.com")

The agent executes, in order, WITHOUT asking per step (only at report submission):

1. **Scope check** (always first):
   ```
   python tools/scope_checker.py <target>
   ```
   If out of scope → STOP, tell the user.

2. **Recon** (if `recon/<target>/` doesn't exist):
   ```
   python tools/hunt.py --target <target>          # full: recon then scan
   python tools/hunt.py --target <target> --quick  # faster
   ```
   If recon exists: `python tools/hunt.py --target <target> --scan-only`

3. **Lead board** (never lose a lead):
   ```
   python tools/lead_board.py ingest <target>
   python tools/lead_board.py show
   ```
   Route each lead to its skill: "GraphQL endpoint → graphql-audit", "API at /v1 → api-security", "AI chatbot → llm-security", "S3 link → cloud-security", "coupon flow → race-conditions", "login flow → auth-attacks", "URL fetcher → ssrf", "serialized cookie → deserialization", "DOM-heavy → client-side-security".

4. **Rank & hunt** the top lead:
   - `bash tools/vuln_scanner.sh recon/<target>/` — general sweep
   - `python tools/api_security_scanner.py <base>` — API
   - `python tools/h1_idor_scanner.py`, `h1_race.py`, `h1_oauth_tester.py`, `jwt_scanner.py`, `llm_redteam.py`, `cloud_bucket_enum.py`, `dom_xss_harness.py`, `deser_probe.py`
   - `python tools/oob_listener.py` for blind bugs
   - MCP: `caido`/`burp` for proxy, `browser` for Playwright, `nuclei` MCP `nuclei_scan`, `shodan` for exposure intel

5. **Validate** every candidate:
   ```
   python tools/validate.py "<finding description>"
   ```
   Only PASS → continue. Kill weak findings (7-Question Gate).

6. **Report** (draft only, human approves before submit):
   ```
   commands/report.md + skills/report-writing
   ```

7. **Remember**: `python tools/lead_board.py touch <lead> done`, `commands/remember.md`.

## Command syntax (Windows PowerShell / Linux)

| Task | Command |
|---|---|
| Recon | `python tools/hunt.py --target target.com` |
| Scan only | `python tools/hunt.py --target target.com --scan-only` |
| Validate | `python tools/validate.py "..."` |
| Lead board | `python tools/lead_board.py show` |
| Shell tool | `bash tools/recon_engine.sh target.com` (Git Bash/WSL) |
| PowerShell wrapper | `.\tools\run.ps1 recon_engine.sh target.com` |

**Windows note:** use `python` (not `python3`). `.sh` tools run via `bash` (Git Bash installed) or `.\tools\run.ps1 <script> <args>`.

## Safety gates (never skip)

1. Scope check before every outbound request (`scope_checker.py`).
2. No report submission without human approval.
3. No destructive action (DELETE/PUT/DROP/rm) without human approval.
4. No credential dumping in output — hash secrets.
5. No testing outside program scope, no DoS.
6. Log via audit (`memory/audit_log.py`).

## Special modes

- **"autopilot target.com --normal"** → delegate to `autopilot` subagent (full loop with checkpoints).
- **"validate this finding"** → `python tools/validate.py "<finding>"`.
- **"write report"** → `report-writing` skill; draft in `findings/<target>/`.
- **"pickup target.com"** → resume from `recon/<target>/` + lead board.

## Skill routing table

| You see | Skill |
|---|---|
| API endpoints / mobile backend | `api-security` |
| AI chatbot / copilot / agent | `llm-security` |
| Cloud / S3 / storage | `cloud-security` |
| k8s / container | `kubernetes-security` |
| Coupons / wallet / OTP / limits | `race-conditions` |
| Login / reset / OAuth / MFA / JWT | `auth-attacks` |
| URL fetcher / webhook / preview | `ssrf` |
| Serialized blob / Java/PHP/Python app | `deserialization` |
| DOM / postMessage / CORS / CSRF | `client-side-security` |
| GraphQL | `graphql-audit` |
| Smart contracts | `web3-audit` / `meme-coin-audit` |
| Android/iOS app | `mobile-pentest` |
| CI/CD pipeline | `cicd-security` |
| Password spray | `credential-attack` |
| Internal engagement | `active-directory` |
| General web | `web2-vuln-classes` / `security-arsenal` |
