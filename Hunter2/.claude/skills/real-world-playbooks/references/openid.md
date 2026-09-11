# Real-World Playbook — OpenID Connect

**Class:** `openid` · **Coverage-matrix tier:** 1 · **Hunter2:** tools/h1_oauth_tester.py · /auth-hunt · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed OpenID Connect reports peak at **$10,500**. Rewarded across: Automattic, Bumble, Eternal, GitHub, HackerOne, Nextcloud, Rocket.Chat, Shopify.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Ability to DOS any organization's SSO and open up the door to account takeovers** — Superhuman (formerly Grammarly), $10,500 · 259👍 · [976603](https://hackerone.com/reports/976603)
- **SAML Authentication Bypass on uchat.uberinternal.com** — Uber, $8,500 · 87👍 · [223014](https://hackerone.com/reports/223014)
- **Stealing SSO Login Tokens (snappublisher.snapchat.com)** — Snapchat, $7,500 · 244👍 · [265943](https://hackerone.com/reports/265943)
- **SSO through odnoklassniki uses http rather than https** — Bumble, $150 · 14👍 · [703759](https://hackerone.com/reports/703759)
- **Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any Shop Owner by Taking Advantage of the Shopify SSO** — Shopify, $0 (disclosed) · 1916👍 · [791775](https://hackerone.com/reports/791775)
- **Able to Takeover Merchants Accounts Even They Have Already Setup SSO, After Bypassing the Email Confirmation** — Shopify, $0 (disclosed) · 310👍 · [796956](https://hackerone.com/reports/796956)
- **HackerOne SAML signup domain enforcement bypass results in unauthorized access to HackerOne PullRequest organization** — HackerOne, $0 (disclosed) · 227👍 · [2101076](https://hackerone.com/reports/2101076)
- **SAML Signature verification bypass allows logging into any user (with specific conditions)** — GitHub, $0 (disclosed) · 196👍 · [2579939](https://hackerone.com/reports/2579939)
- **Insecure Zendesk SSO implementation by generating JWT client-side** — Trint Ltd, $0 (disclosed) · 102👍 · [638635](https://hackerone.com/reports/638635)
- **Twitter SSO allows unverified e-mail registration, leads to Slack and social media hijacks** — Zendesk, $0 (disclosed) · 70👍 · [235139](https://hackerone.com/reports/235139)
- **ID4me feature of OpenID connect app available even when disabled** — Nextcloud, $0 (disclosed) · 66👍 · [2376929](https://hackerone.com/reports/2376929)
- **[auth2.zomato.com] Reflected XSS at `oauth2/fallbacks/error` | ORY Hydra an OAuth 2.0 and OpenID Connect Provider** — Eternal, $0 (disclosed) · 51👍 · [456333](https://hackerone.com/reports/456333)
- **(HackerOne SSO-SAML) Login CSRF, Open Redirect, and Self-XSS Possible Exploitation** — HackerOne, $0 (disclosed) · 44👍 · [171398](https://hackerone.com/reports/171398)
- **Authentication bypass on JetPack SSO manager - Allows to access the administration panel of wordpress without user interaction** — Automattic, $0 (disclosed) · 41👍 · [2037902](https://hackerone.com/reports/2037902)
- **Authentication Bypass via XML Signature Wrapping in SAML SSO** — Rocket.Chat, $0 (disclosed) · 35👍 · [3827674](https://hackerone.com/reports/3827674)
- **Accidental Access to Programs Information via SAML Login** — HackerOne, $0 (disclosed) · 34👍 · [438306](https://hackerone.com/reports/438306)
- **SAML Response Reuse on hackerone.com/users/saml/auth** — HackerOne, $0 (disclosed) · 26👍 · [888930](https://hackerone.com/reports/888930)
- **Ability to enumerate private programs using SAML** — HackerOne, $0 (disclosed) · 24👍 · [167828](https://hackerone.com/reports/167828)

## Chaining — always ask "what does this unlock?"
- id_token signature not verified → forge identity
- iss/aud confusion across providers → login as anyone

## Hunter2 wiring
- **Run:** `tools/h1_oauth_tester.py · /auth-hunt`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
