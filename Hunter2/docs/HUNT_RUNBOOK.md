# Hunter2 — HUNT RUNBOOK (the one doc to run a full hunt)

> **Operator shortcut:** in any new session say
> **"hunt `<target>` using this hunter — read HUNT_RUNBOOK.md"**
> and the agent follows this file top-to-bottom: show the connection board → confirm
> scope → full-power hunt with all tools/agents/playbooks → hunt like a human → validate
> → report. This works the same in **Claude Code** and **OpenCode**.

This runbook is the single readable entry point. The deeper detail lives in:
[`HOW_IT_HUNTS.md`](HOW_IT_HUNTS.md) (every class + method), [`TO_EXTREME.md`](TO_EXTREME.md)
(the active-hunter engine), `Hunter2/CLAUDE.md` + `Hunter2/AGENTS.md` (the auto-loaded
operating contract), and `Hunter2/rules/lead-commander.md` (the doctrine).

Working dir for all commands: `D:\bughunting\Axxx_Hunter\Hunter2`. Python = `py`.

---

## STEP 0 — Show the connection board FIRST (never skip)

Before touching the target, show the operator what is actually armed vs. not:

```bash
py tools/start.py <target>
```

This prints the **AXXX HUNTER** banner + **Connection Board**: which tools, MCPs, proxies
(Caido / Burp), the login browser, agents (16), skills (27), and the scope status are live.
**Report it plainly** — "X connected, Y needs setup." Never assume a tool/MCP is live just
because it ships. (MCP servers only load after a Claude Code restart + approval.)

> A hunt still runs with pieces missing — it just uses what's connected and says what it
> skipped. Caido/Burp is an OPTIONAL manual proxy; the scanners + two-account harness make
> their own authenticated requests and do not need it.

---

## STEP 1 — Scope (one out-of-scope request can get you banned)

```bash
py tools/scope_checker.py <target>        # or /scope
```

Read the program's in-scope + out-of-scope + excluded classes + safe-harbour. Confirm the
asset is in-scope before a single request. Every request is gated by the scope checker.

---

## STEP 2 — Authenticated? Capture the operator's own sessions (for the money bugs)

The high-value classes (IDOR/BOLA, payment, privilege escalation) need **two of the
operator's own accounts**. The agent NEVER types passwords/OTP — the operator logs in:

```bash
py tools/login_capture.py <login-url> --name <target>-A     # operator logs in as A
py tools/login_capture.py <login-url> --name <target>-B     # operator logs in as B
```

A real browser window opens; the operator authenticates on the actual site (email / OTP /
MFA); the tool captures the session to `.private/<name>.json`. Then wire both into `.env`:

```
ACCOUNT_A_TOKEN=...   ACCOUNT_A_COOKIE=...
ACCOUNT_B_TOKEN=...   ACCOUNT_B_COOKIE=...
```

`.env` and `.private/` are gitignored; token values never appear in chat. Confirm A ≠ B
(different accounts) or IDOR testing is invalid. Skip this step for an unauthenticated pass.

---

## STEP 3 — Run the full hunt (all tools, all classes)

```bash
py tools/hunt.py --target <target>                 # recon + freshness + playbooks + scanners
py tools/hunt.py --target <target> --two-account   # add the two-account IDOR/BOLA harness
py tools/hunt.py --target <target> --graphql --cve-hunt   # add GraphQL audit + nuclei CVE sweep
```

What `hunt.py` runs, in order (this IS the "full power"):
1. **Recon** — subfinder/dnsx/katana/gau/nuclei; JS endpoint + secret extraction.
2. **Freshness diff** (`recon_diff.py`) — new assets since last run → hunt first (Rule 12).
3. **Playbook context** (`playbook_router.py`) — writes `findings/<target>/PLAYBOOKS.md`;
   for every lead the agent OPENS the matching `references/<class>.md` and follows its
   checklist + rejection rules.
4. **Automated scanners** — CORS, CRLF, XXE, CSRF, NoSQLi, prototype-pollution, HPP,
   WebSocket, XSS (dalfox + Playwright DOM), SQLi, SSTI, JWT, race, SSRF+OOB, takeover.
5. **Two-account IDOR/BOLA** (`two_account_idor.py`) — replays A's requests with B's auth
   on `/orders`,`/payments`,`/customers`,`/account/*`; POSSIBLE_IDOR → validate by hand.
6. **Auto-chain** (`chain_engine.py`) — every confirmed hit → sibling rule + A→B next-tests.
7. **Learning memory** (`hunt_memory.py`) — records worked/rejected/dead-ends for next hunt.

Route specialist work to the agents as leads appear (see the table in
[`HOW_IT_HUNTS.md`](HOW_IT_HUNTS.md#4-the-agents-who-does-the-work)):
`api-hunter`, `business-logic-hunter`, `race-hunter`, `cloud-hunter`, `llm-hunter`,
`credential-hunter`, `novel-vuln-reasoner`, `chain-builder`, `web3-auditor`, `token-auditor`.

Use connected MCPs when present: Caido/Burp (manual replay), HackerOne (dup + scope),
Playwright browser (DOM/login), Nuclei, Shodan.

---

## STEP 4 — Hunt like a real human (the doctrine, always on)

- **Two-account testing** — the #1 move; scanners can't find cross-tenant bugs.
- **Sibling rule** — every working endpoint → test `/export`,`/delete`,`/v1/`…
- **A→B** — one bug means a class of mistake; find the same flaw nearby before reporting.
- **Follow the money** — billing/credits/refund/wallet/checkout = highest ROI.
- **Impact-first** — "what's the worst thing if auth broke here?" Skip low-value surface.
- **Hunt fresh** — features < 30 days old are weakest.
- **20-min rotation** — no progress → rotate endpoint/class.
- **Depth over breadth** — one target understood deeply beats ten scanned shallowly.

---

## STEP 5 — Validate (kill invalid findings before writing)

```bash
py tools/validate.py --program <handle>     # or /validate
```

Runs the **auto rejection-gate** first (`rejection_gate.py` — kills public keys, self-XSS,
missing headers, theoretical, out-of-scope), then the 7-Question Gate + 4 pre-submission
gates. One wrong answer = kill the finding and move on (protects your validity ratio).

---

## STEP 6 — Report

```bash
py tools/hunt.py --target <target> --report-only   # or /report, or the report-writer agent
```

Impact-first H1/Bugcrowd/Intigriti/Immunefi template + CVSS + PoC. Report submission and
any destructive HTTP method require the operator's explicit approval.

---

## Safety rails (full power ≠ reckless — never overridden)

- In-scope assets only; read full scope first; **no DoS / load testing**.
- **Never create accounts or enter the operator's credentials/OTP** — operator logs in.
- Subdomain takeover is **detect-and-report only** — never claim a resource.
- Minimal redacted PoCs — no bulk PII scraping; destroy PoC artifacts after.
- Safe HTTP methods by default; PUT/DELETE/PATCH need explicit approval.
- No secrets in chat/repo — `.env` + `.private/` are gitignored and masked.

---

## Quick reference — one target, start to finish

```bash
py tools/start.py acme.com                                   # 0. connection board
py tools/scope_checker.py acme.com                           # 1. scope
py tools/login_capture.py https://acme.com/login --name acme-A   # 2. auth (operator logs in)
py tools/login_capture.py https://acme.com/login --name acme-B
#   wire ACCOUNT_A_*/ACCOUNT_B_* into .env from .private/acme-A.json / acme-B.json
py tools/hunt.py --target acme.com --two-account --graphql --cve-hunt   # 3. full hunt
py tools/validate.py --program acme                          # 5. validate survivors
py tools/hunt.py --target acme.com --report-only             # 6. report
```

That's the whole hunt. Say **"hunt `<target>` — read HUNT_RUNBOOK.md"** and the agent runs
exactly this, showing the connection board first and using every connected tool, agent, and
playbook, the way a disciplined human hunter would.
