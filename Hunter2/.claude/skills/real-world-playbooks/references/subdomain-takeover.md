# Real-World Playbook — Subdomain Takeover

**Class:** `subdomain-takeover` · **Coverage-matrix tier:** 3 · **Hunter2:** /takeover · tools/takeover_scanner.sh (DETECT-ONLY) · **Skill:** cloud-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed Subdomain Takeover reports peak at **$3,000**. Rewarded across: Affirm, Eternal, Grab, HackerOne, Kubernetes, Lyst, Mail.ru, MetaMask.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Subdomain takeover on http://fastly.sc-cdn.net/** — Snapchat, $3,000 · 114👍 · [154425](https://hackerone.com/reports/154425)
- **Subdomain takeover of storybook.lystit.com** — Lyst, $1,000 · 163👍 · [779442](https://hackerone.com/reports/779442)
- **Subdomain Takeover Via Insecure CloudFront Distribution cdn.grab.com** — Grab, $1,000 · 142👍 · [352869](https://hackerone.com/reports/352869)
- **Subdomain Takeover at test.shipt.com** — Shipt, $750 · 73👍 · [387760](https://hackerone.com/reports/387760)
- **Subdomain Takeover of brand.zen.ly** — Zenly, $750 · 61👍 · [1474784](https://hackerone.com/reports/1474784)
- **Subdomain takeover of resources.hackerone.com** — HackerOne, $500 · 95👍 · [863551](https://hackerone.com/reports/863551)
- **Subdomain takeover on a subdomain under firefox.com** — Mozilla, $500 · 75👍 · [2899858](https://hackerone.com/reports/2899858)
- **Subdomain Takeover Via unclaimed Heroku Instance tim-exclusive.shopify.com** — Shopify, $500 · 68👍 · [424669](https://hackerone.com/reports/424669)
- **[ addons-preview-cdn.mozilla.net ] A subdomain takeover is available via unregistered domain in Fastly** — Mozilla, $500 · 66👍 · [2706358](https://hackerone.com/reports/2706358)
- **Subdomain takeover of www█████████.affirm.com** — Affirm, $500 · 55👍 · [1297689](https://hackerone.com/reports/1297689)
- **Sub-Domain Takeover at   http://www.codefi.consensys.net/** — MetaMask, $500 · 42👍 · [1717626](https://hackerone.com/reports/1717626)
- **Domain Takeover of Reddit.ru via DNS Hijacking** — Reddit, $500 · 20👍 · [1226891](https://hackerone.com/reports/1226891)
- **Subdomain takeover on s3.shopify.com** — Shopify, $500 · 13👍 · [207576](https://hackerone.com/reports/207576)
- **[supportlocal.delivery-club.ru] Subdomain Takeover** — Mail.ru, $500 · 13👍 · [1054765](https://hackerone.com/reports/1054765)
- **URGENT - Subdomain Takeover on users.tweetdeck.com , the same issue  of report #32825** — X / xAI, $420 · 4👍 · [42236](https://hackerone.com/reports/42236)
- **Subdomain takeover of fr1.vpn.zomans.com** — Eternal, $350 · 99👍 · [1182864](https://hackerone.com/reports/1182864)
- **Subdomain takeover at segway.shipt.com** — Shipt, $300 · 23👍 · [389783](https://hackerone.com/reports/389783)
- **Subdomain Takeover Via via Dangling NS records on Amazon Route 53 http://api.e2e-kops-aws-canary.test-cncf-aws.canary.k8s.io** — Kubernetes, $250 · 62👍 · [746000](https://hackerone.com/reports/746000)

## Chaining — always ask "what does this unlock?"
- Dangling CNAME → claim service → host content on trusted subdomain
- Takeover → OAuth redirect_uri / cookie-scope → ATO
- DETECT AND REPORT ONLY — never claim the resource

## Hunter2 wiring
- **Run:** `/takeover · tools/takeover_scanner.sh (DETECT-ONLY)`
- **Skill:** `cloud-security`
- **Coverage-matrix tier:** 3 (Tier 0 = test first)
