---
name: real-world-playbooks
description: Use during ANY hunt when testing a vulnerability class or looking for exploit chains. The agent's real-world knowledge base — per-class playbooks distilled from real disclosed HackerOne reports (reddelexc/hackerone-reports, with bounty signal + technique + report links), hands-on test-flow checklists (Az0x7/vulnerability-Checklist), real payloads + filter bypasses (PayloadsAllTheThings), and real attacker methodology (HowToHunt + AllAboutBugBounty). For each lead, open references/<class>.md to test it the way real hackers did and to chain it. Load whenever hunting IDOR/BOLA, SSRF, XSS, auth/ATO, business logic, API, JWT/OAuth, SQLi/SSTI/RCE, XXE, file upload, race conditions, GraphQL, request smuggling, cache poisoning, and more.
---

# Real-World Playbooks — hunt like the reports that got paid

This skill turns Hunter 2 from a scanner into an **experienced hunter**. Every playbook is
built from real public sources:

- **[reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports)** — the
  top **disclosed HackerOne reports** per class. Each report's *title is the actual
  technique*, with its bounty and a link to the full PoC. This teaches *what really works
  and pays*.
- **[Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist)** —
  ordered, hands-on **test-flow checklists** per vuln. This teaches *exactly what to try,
  where, and in what order*.
- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** — the
  **real payloads + filter bypasses** per class (the "Real payloads" section). These are the
  actual attack strings to fire once a sink is reachable.
- **[OWASP WSTG](https://github.com/OWASP/wstg)** — the authoritative **testing methodology**
  per class from the OWASP Web Security Testing Guide.
- **[HowToHunt](https://github.com/KathanP19/HowToHunt)** + **[AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty)** —
  the **real attacker flow / methodology** per class: how a hunter reasons through it step by step.
- **[HackTricks](https://github.com/HackTricks-wiki/hacktricks)** — a **short excerpt + link** of
  its deep per-topic methodology (non-commercial license, so excerpt only — open the link for full).

> The active scanners also fire real payloads from `tools/payloads/*.txt` via
> `tools/payload_loader.py` (nosqli/crlf/xxe today), keeping their built-ins as fallback.
> Refresh everything with `python scripts/gen_real_world_playbooks.py` then
> `cp -r skills/real-world-playbooks .claude/skills/real-world-playbooks` (Claude Code parity).

## How to use it (every lead, every class)

1. **Pick the class** from the lead board / coverage matrix.
2. **Open `references/<class>.md`.** Read:
   - **"How real hackers found it"** — scan the top report titles; they are technique
     recipes. Open a report link when a title matches your target's surface.
   - **"Test flow / checklist"** — run each step **in order** on the reachable surface.
     Don't stop at step 1; a real hunter works the whole list.
   - **"Chaining"** — after any finding, apply these to escalate (info→IDOR→ATO, etc.).
3. **Record the result** in the coverage matrix (`FOUND / TESTED / N/A-reason`). A class is
   only `TESTED` when you actually worked its checklist, not glanced at it.
4. **Always chain** — never close a finding without asking "what does this unlock?" and
   trying the recipes in the playbook + `rules/coverage-matrix.md`.

This is depth discipline in practice: the playbook is why the agent tests thoroughly
instead of drifting.

## Playbook index (44 classes)

**Tier 0 — always test first**
`idor-bola` · `account-takeover` · `ssrf` · `xss` · `business-logic` · `auth-session` · `api-auth`

**Tier 1 — test on every reachable surface**
`jwt` · `oauth` · `openid` · `mfa-2fa` · `reset-password` · `csrf` · `cors` · `sqli` ·
`nosqli` · `ssti` · `rce` · `command-injection` · `file-upload` · `path-traversal-lfi` ·
`xxe` · `open-redirect` · `graphql` · `prototype-pollution` · `websocket-cswsh` · `hpp` ·
`clickjacking` · `crlf-hostheader` · `info-disclosure` · `cookie` · `403-bypass` ·
`registration` · `admin-panel`

**Tier 2 — reasoning / chained / framework**
`request-smuggling` · `web-cache` · `deserialization` · `race-condition` · `aem` · `jira` ·
`framework`

**Tier 3 — infra / mobile (surface-gated)**
`subdomain-takeover` · `mobile` · `dos`

## Top cross-class chaining recipes (memorize these)

- **IDOR/info-leak → ATO** — leaked/guessable id on an email or password field.
- **SSRF → cloud metadata → IAM creds** → infra takeover.
- **Open redirect → OAuth code/token theft → ATO.**
- **XSS → CSRF-token/session exfil → ATO**; stored XSS in admin view → admin ATO.
- **Subdomain takeover → OAuth redirect_uri / cookie scope → ATO** (detect-and-report only).
- **Source/JS-map leak → secret/API key → authed API abuse → IDOR/BOLA.**
- **Host-header injection → password-reset poisoning → ATO.**
- **Prompt injection → LLM tool/function abuse → IDOR/SSRF via the model.**
- **File upload / SSTI / deserialization / command-injection → RCE.**

See `rules/coverage-matrix.md` for the full class→tool routing and `rules/lead-commander.md`
for how the leader drives all of this in real-hunter flow.

> Attribution: techniques and report links are curated from the two public repos above for
> in-tool reference. Open the linked reports for full write-ups and credit to the original
> researchers.
