# Real-World Playbook — SSRF (Server-Side Request Forgery)

**Class:** `ssrf` · **Coverage-matrix tier:** 0 · **Hunter2:** /ssrf-chain · tools/oob_listener.py · **Skill:** ssrf
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed SSRF reports peak at **$25,000**. Rewarded across: Aiven Ltd, Dropbox, EXNESS, GitLab, HackerOne, Internet Bug Bounty, Kubernetes, LY Corporation.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Server Side Request Forgery (SSRF) via Analytics Reports** — HackerOne, $25,000 · 521👍 · [2262382](https://hackerone.com/reports/2262382)
- **Full Response SSRF via Google Drive** — Dropbox, $17,576 · 302👍 · [1406938](https://hackerone.com/reports/1406938)
- **SSRF on project import via the remote_attachment_url on a Note** — GitLab, $10,000 · 358👍 · [826361](https://hackerone.com/reports/826361)
- **Blind SSRF to internal services in matrix preview_link API** — Reddit, $6,000 · 341👍 · [1960765](https://hackerone.com/reports/1960765)
- **Full read SSRF via Lark Docs `import as docs` feature** — Lark Technologies, $5,000 · 124👍 · [1409727](https://hackerone.com/reports/1409727)
- **[Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia** — Aiven Ltd, $5,000 · 56👍 · [1547877](https://hackerone.com/reports/1547877)
- **Half-Blind SSRF found in kube/cloud-controller-manager can be upgraded to complete SSRF (fully crafted HTTP requests) in vendor managed k8s service.** — Kubernetes, $5,000 · 21👍 · [776017](https://hackerone.com/reports/776017)
- **important: Apache HTTP Server on WIndows UNC SSRF (CVE-2024-38472)** — Internet Bug Bounty, $4,920 · 45👍 · [2585385](https://hackerone.com/reports/2585385)
- **Server Side Request Forgery (SSRF) at app.hellosign.com leads to AWS private keys disclosure** — Dropbox, $4,913 · 360👍 · [923132](https://hackerone.com/reports/923132)
- **Libuv: Improper Domain Lookup that potentially leads to SSRF attacks** — Internet Bug Bounty, $4,860 · 74👍 · [2429894](https://hackerone.com/reports/2429894)
- **SSRF on music.line.me through getXML.php** — LY Corporation, $4,500 · 134👍 · [746024](https://hackerone.com/reports/746024)
- **important: Apache HTTP Server: SSRF with mod_rewrite in server/vhost context on Windows (CVE-2024-40898)** — Internet Bug Bounty, $4,263 · 19👍 · [2612028](https://hackerone.com/reports/2612028)
- **Unauthenticated blind SSRF in OAuth Jira authorization controller** — GitLab, $4,000 · 237👍 · [398799](https://hackerone.com/reports/398799)
- **SSRF via Office file thumbnails** — Slack, $4,000 · 107👍 · [671935](https://hackerone.com/reports/671935)
- **SSRF in Functional Administrative Support Tool pdf generator (████) [HtUS]** — U.S. Dept Of Defense, $4,000 · 46👍 · [1628209](https://hackerone.com/reports/1628209)
- **Blind SSRF on errors.hackerone.net due to Sentry misconfiguration** — HackerOne, $3,500 · 142👍 · [374737](https://hackerone.com/reports/374737)
- **SSRF in graphQL query (pwapi.ex2b.com)** — EXNESS, $3,000 · 259👍 · [1864188](https://hackerone.com/reports/1864188)
- **Stored XSS & SSRF in Lark Docs** — Lark Technologies, $3,000 · 178👍 · [892049](https://hackerone.com/reports/892049)

## Chaining — always ask "what does this unlock?"
- SSRF → cloud metadata (169.254.169.254 / metadata.google) → **IAM creds** → infra takeover
- SSRF → internal admin panels / unauthenticated internal APIs
- Blind SSRF → confirm via OOB (interactsh); then escalate to gopher/redis/file schemes
- SSRF via URL param, webhook, PDF/image/importer, XXE, or SVG

## Hunter2 wiring
- **Run:** `/ssrf-chain · tools/oob_listener.py`
- **Skill:** `ssrf`
- **Coverage-matrix tier:** 0 (Tier 0 = test first)
