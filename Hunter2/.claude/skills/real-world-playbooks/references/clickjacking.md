# Real-World Playbook — Clickjacking / UI Redress

**Class:** `clickjacking` · **Coverage-matrix tier:** 1 · **Hunter2:** /client-side · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed Clickjacking / UI Redress reports peak at **$5,000**. Rewarded across: Automattic, BOHEMIA INTERACTIVE a.s., Coinbase, Mail.ru, Passit, PortSwigger Web Security, Shipt, TikTok.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **OAuth authorization page vulnerable to clickjacking** — Coinbase, $5,000 · 15👍 · [65825](https://hackerone.com/reports/65825)
- **RCE of Burp  Scanner / Crawler via Clickjacking** — PortSwigger Web Security, $3,000 · 171👍 · [1274695](https://hackerone.com/reports/1274695)
- **Twitter Periscope Clickjacking Vulnerability** — X / xAI, $1,120 · 143👍 · [591432](https://hackerone.com/reports/591432)
- **Clickjacking Periscope.tv on Chrome** — X / xAI, $560 · 11👍 · [198622](https://hackerone.com/reports/198622)
- **Clickjacking Vulnerability Can Leads To Delete Developer APP** — TikTok, $500 · 26👍 · [1416612](https://hackerone.com/reports/1416612)
- **Clickjacking Vulnerability In Whole Page Ads Tiktok** — TikTok, $500 · 7👍 · [1418857](https://hackerone.com/reports/1418857)
- **Modifying application settings via clickjacking on o2.mail.ru** — Mail.ru, $150 · 13👍 · [355774](https://hackerone.com/reports/355774)
- **Clickjacking at ylands.com** — BOHEMIA INTERACTIVE a.s., $80 · 22👍 · [405342](https://hackerone.com/reports/405342)
- **Highly wormable clickjacking in player card** — X / xAI, $0 (disclosed) · 134👍 · [85624](https://hackerone.com/reports/85624)
- **Clickjacking on donation page** — WordPress, $0 (disclosed) · 90👍 · [921709](https://hackerone.com/reports/921709)
- **Clickjacking in main domain https://topechelon.com/** — Top Echelon Software, $0 (disclosed) · 80👍 · [2964441](https://hackerone.com/reports/2964441)
- **Viral Direct Message Clickjacking via link truncation leading to capture of both Google credentials & installation of malicious 3rd party Twitter App** — X / xAI, $0 (disclosed) · 64👍 · [643274](https://hackerone.com/reports/643274)
- **Double Clickjacking Attack on WakaTime OAuth Authorization Flow at https://wakatime.com/oauth/authorize** — WakaTime, $0 (disclosed) · 57👍 · [3287060](https://hackerone.com/reports/3287060)
- **Sensitive Clickjacking on admin login page.** — Shipt, $0 (disclosed) · 55👍 · [389145](https://hackerone.com/reports/389145)
- **Stealing User emails by clickjacking cards.twitter.com/xxx/xxx** — X / xAI, $0 (disclosed) · 49👍 · [154963](https://hackerone.com/reports/154963)
- **Clickjacking vkpay** — VK.com, $0 (disclosed) · 44👍 · [374817](https://hackerone.com/reports/374817)
- **[api.tumblr.com] Exploiting clickjacking vulnerability to trigger self DOM-based XSS** — Automattic, $0 (disclosed) · 31👍 · [953579](https://hackerone.com/reports/953579)
- **URL is vulnerable to clickjacking  https://app.passit.io/** — Passit, $0 (disclosed) · 28👍 · [530008](https://hackerone.com/reports/530008)

## Chaining — always ask "what does this unlock?"
- Framing a state-change with no CSRF token → 1-click account change
- Only meaningful on sensitive authed actions — prove impact

## Hunter2 wiring
- **Run:** `/client-side`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
