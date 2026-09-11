# Real-World Playbook — Denial of Service (report-only class)

**Class:** `dos` · **Coverage-matrix tier:** 3 · **Hunter2:** (analyze only — NEVER run load/DoS) · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed Denial of Service reports peak at **$12,500**. Rewarded across: GitHub, GitLab, HackerOne, Internet Bug Bounty, PayPal, Rootstock Labs, Shopify, Superhuman (formerly Grammarly).

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API** — HackerOne, $12,500 · 175👍 · [3287208](https://hackerone.com/reports/3287208)
- **Ability to DOS any organization's SSO and open up the door to account takeovers** — Superhuman (formerly Grammarly), $10,500 · 259👍 · [976603](https://hackerone.com/reports/976603)
- **Range constructor type confusion DoS** — shopify-scripts, $10,000 · 7👍 · [181910](https://hackerone.com/reports/181910)
- **DoS on PayPal via web cache poisoning** — PayPal, $9,700 · 851👍 · [622122](https://hackerone.com/reports/622122)
- **Null target_class DoS** — shopify-scripts, $8,000 · 14👍 · [183405](https://hackerone.com/reports/183405)
- **Denial of service due to invalid memory access in mrb_ary_concat** — shopify-scripts, $8,000 · 9👍 · [184712](https://hackerone.com/reports/184712)
- **Denial of Service in mruby due to null pointer dereference** — shopify-scripts, $8,000 · 8👍 · [181232](https://hackerone.com/reports/181232)
- **ruby DoS https://www.mruby.science** — shopify-scripts, $8,000 · 5👍 · [180695](https://hackerone.com/reports/180695)
- **DOS via issue preview** — GitLab, $7,640 · 25👍 · [1543718](https://hackerone.com/reports/1543718)
- **Possible DoS Vulnerability with Range Header in Rack** — Internet Bug Bounty, $5,420 · 56👍 · [2520679](https://hackerone.com/reports/2520679)
- **DOS of RSKJ server** — Rootstock Labs, $5,000 · 120👍 · [2105808](https://hackerone.com/reports/2105808)
- **CVE-2024-34750 Apache Tomcat DoS vulnerability in HTTP/2 connector** — Internet Bug Bounty, $4,920 · 60👍 · [2586226](https://hackerone.com/reports/2586226)
- **important: Apache HTTP Server: Crash resulting in Denial of Service in mod_proxy via a malicious request (CVE-2024-38477)** — Internet Bug Bounty, $4,920 · 27👍 · [2585375](https://hackerone.com/reports/2585375)
- **Denial of Service caused by HTTP/2 CONTINUATION Flood** — Internet Bug Bounty, $4,860 · 42👍 · [2334401](https://hackerone.com/reports/2334401)
- **DoS via markdown API from unauthenticated user** — GitHub, $4,000 · 54👍 · [1619604](https://hackerone.com/reports/1619604)
- **DoS through PeerExplorer** — Rootstock Labs, $4,000 · 50👍 · [363636](https://hackerone.com/reports/363636)
- **DoS Vulnerability via Cache Poisoning on cdn.shopify.com and shopify-assets.shopifycdn.com** — Shopify, $3,800 · 264👍 · [1695604](https://hackerone.com/reports/1695604)
- **http: Reading unprocessed HTTP request with unbounded chunk extension allows DoS attacks** — Internet Bug Bounty, $3,495 · 40👍 · [2375446](https://hackerone.com/reports/2375446)

## Chaining — always ask "what does this unlock?"
- Algorithmic complexity / ReDoS / amplification — DESCRIBE, do not exploit
- Most programs treat volumetric DoS as out-of-scope; report logic-DoS carefully

## Hunter2 wiring
- **Run:** `(analyze only — NEVER run load/DoS)`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 3 (Tier 0 = test first)
