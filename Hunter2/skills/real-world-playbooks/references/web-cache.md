# Real-World Playbook — Web Cache Poisoning / Deception

**Class:** `web-cache` · **Coverage-matrix tier:** 2 · **Hunter2:** novel-vuln-reasoner · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed Web Cache Poisoning / Deception reports peak at **$9,700**. Rewarded across: Algolia, Discourse, GSA Bounty, Glassdoor, Lyst, Mail.ru, OLX, PayPal.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **DoS on PayPal via web cache poisoning** — PayPal, $9,700 · 851👍 · [622122](https://hackerone.com/reports/622122)
- **https://themes.shopify.com::: Host header web cache poisoning lead to DoS** — Shopify, $2,900 · 82👍 · [1096609](https://hackerone.com/reports/1096609)
- **Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage** — Shopify, $800 · 48👍 · [1271944](https://hackerone.com/reports/1271944)
- **Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS** — GSA Bounty, $750 · 93👍 · [303730](https://hackerone.com/reports/303730)
- **Web cache poisoning attack leads to user information and more** — Postmates, $500 · 343👍 · [492841](https://hackerone.com/reports/492841)
- **Web Cache Deception vulnerability on algolia.com leads to personal information leakage** — Algolia, $400 · 46👍 · [1530066](https://hackerone.com/reports/1530066)
- **Web cache information leakage at sbermarket.ru** — Mail.ru, $400 · 22👍 · [893353](https://hackerone.com/reports/893353)
- **Web Cache Deception Attack (XSS)** — Discourse, $256 · 51👍 · [394016](https://hackerone.com/reports/394016)
- **Web cache deception attack on https://open.vanillaforums.com/messages/all** — Vanilla, $150 · 47👍 · [593712](https://hackerone.com/reports/593712)
- **Web Cache Poisoning leads to Stored XSS** — Glassdoor, $0 (disclosed) · 133👍 · [1424094](https://hackerone.com/reports/1424094)
- **Web Cache Poisoning leads to XSS and DoS** — Glassdoor, $0 (disclosed) · 71👍 · [1621540](https://hackerone.com/reports/1621540)
- **web cache deception in https://tradus.com lead to name/user_id enumeration and other info** — OLX, $0 (disclosed) · 63👍 · [537564](https://hackerone.com/reports/537564)
- **Web Cache Deception** — Glassdoor, $0 (disclosed) · 62👍 · [2265400](https://hackerone.com/reports/2265400)
- **[https://www.glassdoor.com] -  Web Cache Deception Leads to gdtoken Disclosure** — Glassdoor, $0 (disclosed) · 60👍 · [1343086](https://hackerone.com/reports/1343086)
- **CSRF-tokens on pages without no-cache headers, resulting in ATO when using CloudFlare proxy (Web Cache Deception)** — Discourse, $0 (disclosed) · 58👍 · [260697](https://hackerone.com/reports/260697)
- **Web Cache poisoning attack leads to User information Disclosure and more** — Lyst, $0 (disclosed) · 45👍 · [631589](https://hackerone.com/reports/631589)
- **Web cache poisoning leads to disclosure of CSRF token and sensitive information** — Smule, $0 (disclosed) · 39👍 · [504514](https://hackerone.com/reports/504514)
- **Web Cache Poisoning on  █████** — U.S. Dept Of Defense, $0 (disclosed) · 36👍 · [1183263](https://hackerone.com/reports/1183263)

## Chaining — always ask "what does this unlock?"
- Unkeyed header reflected + cached → stored XSS to all users
- Cache deception (/account/foo.css) → cache victim's private page → info leak

## Hunter2 wiring
- **Run:** `novel-vuln-reasoner`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 2 (Tier 0 = test first)
