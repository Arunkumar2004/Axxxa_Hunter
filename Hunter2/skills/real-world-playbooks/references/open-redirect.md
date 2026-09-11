# Real-World Playbook — Open Redirect

**Class:** `open-redirect` · **Coverage-matrix tier:** 1 · **Hunter2:** vuln_scanner.sh · /client-side · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed Open Redirect reports peak at **$3,000**. Rewarded across: Expedia Group Bug Bounty, GitLab, Internet Bug Bounty, Keybase, LY Corporation, Ruby on Rails, Showmax, Slack.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Reflected XSS via Unvalidated / Open Redirect in uber.com** — Uber, $3,000 · 10👍 · [125791](https://hackerone.com/reports/125791)
- **open redirect in rfc6749** — Internet Bug Bounty, $3,000 · 6👍 · [26962](https://hackerone.com/reports/26962)
- **Open Redirect Vulnerability in Action Pack** — Internet Bug Bounty, $2,400 · 43👍 · [1865991](https://hackerone.com/reports/1865991)
- **XSS and Open Redirect on MoPub Login** — X / xAI, $1,540 · 247👍 · [683298](https://hackerone.com/reports/683298)
- **Open Redirect leak of authenticity_token lead to full account take over.** — X / xAI, $1,400 · 7👍 · [49759](https://hackerone.com/reports/49759)
- **Open redirect at https://inventory.upserve.com/http://google.com/** — Upserve, $1,200 · 178👍 · [469803](https://hackerone.com/reports/469803)
- **[dev.twitter.com] XSS and Open Redirect** — X / xAI, $1,120 · 74👍 · [260744](https://hackerone.com/reports/260744)
- **[dev.twitter.com] XSS and Open Redirect Protection Bypass** — X / xAI, $1,120 · 45👍 · [330008](https://hackerone.com/reports/330008)
- **Open Redirect in Logout & Login** — Expedia Group Bug Bounty, $1,000 · 169👍 · [1788006](https://hackerone.com/reports/1788006)
- **page.line.me Open Redirect Leading to OAuth Authorization Code Exposure and Access Token Compromise** — LY Corporation, $1,000 · 43👍 · [3423013](https://hackerone.com/reports/3423013)
- **Instant open redirect on Live preview WEB Ide opening** — GitLab, $1,000 · 20👍 · [437142](https://hackerone.com/reports/437142)
- **Open Redirect (6.0.0 \< rails \< 6.0.3.2)** — Ruby on Rails, $1,000 · 19👍 · [904059](https://hackerone.com/reports/904059)
- **Trick make all fixed open redirect links vulnerable again** — Slack, $1,000 · 4👍 · [104087](https://hackerone.com/reports/104087)
- **Chained open redirects and use of Ideographic Full Stop defeat Twitter's  approach to blocking links** — X / xAI, $560 · 70👍 · [1032610](https://hackerone.com/reports/1032610)
- **open redirect sends authenticity_token to any website or (ip address)** — X / xAI, $560 · 1👍 · [50752](https://hackerone.com/reports/50752)
- **Open Redirect in secure.showmax.com** — Showmax, $550 · 225👍 · [749338](https://hackerone.com/reports/749338)
- **[keybase.io] Open Redirect** — Keybase, $500 · 40👍 · [87027](https://hackerone.com/reports/87027)
- **CBC "cut and paste" attack may cause Open Redirect(even XSS)** — Uber, $500 · 22👍 · [126203](https://hackerone.com/reports/126203)

## Chaining — always ask "what does this unlock?"
- Open redirect → **OAuth token/code theft** → ATO
- Redirect → phishing on trusted domain
- Chain with SSRF filter bypass

## Hunter2 wiring
- **Run:** `vuln_scanner.sh · /client-side`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
