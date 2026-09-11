# Real-World Playbook — OAuth / OIDC Flaws

**Class:** `oauth` · **Coverage-matrix tier:** 1 · **Hunter2:** tools/h1_oauth_tester.py · /auth-hunt · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed OAuth / OIDC Flaws reports peak at **$5,000**. Rewarded across: Coinbase, Dropbox, GSA Bounty, GitLab, LY Corporation, Mattermost, Phabricator, Pornhub.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **OAuth authorization page vulnerable to clickjacking** — Coinbase, $5,000 · 15👍 · [65825](https://hackerone.com/reports/65825)
- **Unauthenticated blind SSRF in OAuth Jira authorization controller** — GitLab, $4,000 · 237👍 · [398799](https://hackerone.com/reports/398799)
- **Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties** — GitLab, $3,000 · 257👍 · [922456](https://hackerone.com/reports/922456)
- **Incorrect details on OAuth permissions screen allows DMs to be read without permission** — X / xAI, $2,940 · 80👍 · [434763](https://hackerone.com/reports/434763)
- **Twitter iOS fails to validate server certificate and sends oauth token** — X / xAI, $2,100 · 40👍 · [168538](https://hackerone.com/reports/168538)
- **Stealing Users OAuth authorization code via redirect_uri** — pixiv, $2,000 · 250👍 · [1861974](https://hackerone.com/reports/1861974)
- **`account_info.read` scope OAuth app access token can change token owner's account name.** — Dropbox, $1,728 · 34👍 · [1031240](https://hackerone.com/reports/1031240)
- **Problem with OAuth** — X / xAI, $1,260 · 7👍 · [46485](https://hackerone.com/reports/46485)
- **page.line.me Open Redirect Leading to OAuth Authorization Code Exposure and Access Token Compromise** — LY Corporation, $1,000 · 43👍 · [3423013](https://hackerone.com/reports/3423013)
- **Account takeover via Pornhub Oauth** — Pornhub, $1,000 · 17👍 · [192648](https://hackerone.com/reports/192648)
- **Mattermost Server OAuth Flow Cross-Site Scripting** — Mattermost, $900 · 44👍 · [1216203](https://hackerone.com/reports/1216203)
- **[Critical] - Steal OAuth Tokens** — X / xAI, $840 · 31👍 · [131202](https://hackerone.com/reports/131202)
- **Stealing Users OAuth Tokens through redirect_uri parameter** — GSA Bounty, $750 · 67👍 · [665651](https://hackerone.com/reports/665651)
- **Smuggle SocialClub's Facebook OAuth Code via Referer Leakage** — Rockstar Games, $750 · 39👍 · [342709](https://hackerone.com/reports/342709)
- **Broken OAuth leads to change photo profile users .** — Dropbox, $512 · 37👍 · [642475](https://hackerone.com/reports/642475)
- **Open redirection in OAuth** — Shopify, $500 · 14👍 · [55525](https://hackerone.com/reports/55525)
- **OAuth access_token stealing in Phabricator** — Phabricator, $450 · 9👍 · [3596](https://hackerone.com/reports/3596)
- **OAuth Stealing Attack (New)** — Phabricator, $400 · 10👍 · [3930](https://hackerone.com/reports/3930)

## Chaining — always ask "what does this unlock?"
- redirect_uri bypass → steal code/token → ATO
- Missing state param → OAuth CSRF (account linking) → ATO
- Referrer/open-redirect leak of code → ATO
- PKCE downgrade / code reuse

## Hunter2 wiring
- **Run:** `tools/h1_oauth_tester.py · /auth-hunt`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
