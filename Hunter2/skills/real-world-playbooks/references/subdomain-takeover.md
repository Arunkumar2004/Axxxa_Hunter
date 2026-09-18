# Real-World Playbook — Subdomain Takeover

**Class:** `subdomain-takeover` · **Coverage-matrix tier:** 3 · **Hunter2:** /takeover · tools/takeover_scanner.sh (DETECT-ONLY) · **Skill:** cloud-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

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

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Subdomain Takeover

|ID          |
|------------|
|WSTG-CONF-10|

#### Summary

A successful exploitation of this kind of vulnerability allows an adversary to claim and take control of the victim's subdomain. This attack relies on the following:

1. The victim's external DNS server subdomain record is configured to point to a non-existing or non-active resource/external service/endpoint. The proliferation of XaaS (Anything as a Service) products and public cloud services offer a lot of potential targets to consider.
2. The service provider hosting the resource/external service/endpoint does not handle subdomain ownership verification properly.

If the subdomain takeover is successful, a wide variety of attacks are possible (serving malicious content, phishing, stealing user session cookies, credentials, etc.). This vulnerability could be exploited for a wide variety of DNS resource records including: `A`, `CNAME`, `MX`, `NS`, `TXT` etc. In terms of the attack severity, an `NS` subdomain takeover (although less likely) has the highest impact, because a successful attack could result in full control over the whole DNS zone and the victim's domain.

##### GitHub

1. The victim (victim.com) uses GitHub for development and configured a DNS record (`coderepo.victim.com`) to access it.
2. The victim decides to migrate their code repository from GitHub to a commercial platform and does not remove `coderepo.victim.com` from their DNS server.
3. An adversary discovers that `coderepo.victim.com` is hosted on GitHub and claims it using GitHub Pages and their own GitHub account.

##### Expired Domain

1. The victim (victim.com) owns another domain (victimotherdomain.com) and uses a CNAME record (www) to reference the other domain (`www.victim.com` --> `victimotherdomain.com`)
2. At some point, victimotherdomain.com expires, becoming available for registration by anyone. Since the CNAME record is not deleted from the victim.com DNS zone, anyone who registers `victimotherdomain.com` has full control over `www.victim.com` until the DNS record is removed or updated.

#### Test Objectives

- Enumerate all possible domains (previous and current).
- Identify any forgotten or misconfigured domains.

#### How to Test

##### Black-Box Testing

Subdomain takeover testing follows three phases: subdomain enumeration, automated fingerprint-based detection, and manual validation.

A dangling DNS record occurs when a DNS entry points to an external resource that no longer exists or has been deprovisioned. For example, a CNAME record pointing to a GitHub Pages site that the owner deleted still resolves, but the underlying resource is unclaimed. An attacker can register that resource and take control of the subdomain.

###### Subdomain Enumeration

Use [subfinder](https://github.com/projectdiscovery/subfinder) to discover subdomains for the target domain: `subfinder -d victim.com -o subdomains.txt`

This produces a list of subdomains to use in the detection phase.

###### Fingerprint-Based Detection

Fingerprint-based detection works by comparing each subdomain's HTTP response against a database of known vulnerable service responses. The [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) project maintains this database, cataloging the specific response strings returned by service providers such as GitHub Pages, AWS S3, Heroku, and Fastly when a resource is unclaimed.

Use [subzy](https://github.com/LukaSikic/subzy) for a quick initial scan: `subzy run --targets subdomains.txt`

Follow up with [nuclei](https://github.com/projectdiscovery/nuclei) using the dedicated takeover templates for a more accurate result: `nuclei -l subdomains.txt -t takeovers/`

A positive result from either tool indicates that a subdomain's response matched a known vulnerable fingerprint, suggesting a dangling DNS record pointing to an unclaimed resource on a third-party service.

For example, a subdomain pointing to an unclaimed GitHub Pages site returns the following response:

```http
HTTP/1.1 404 Not Found
...

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### AI in Cybersecurity


#### Main Machine Learning Algorithms

The best starting point to learn about AI is to understand how the main machine learning algorithms work. This will help you to understand how AI works, how to use it and how to attack it:


./AI-Supervised-Learning-Algorithms.md


./AI-Unsupervised-Learning-Algorithms.md


./AI-Reinforcement-Learning-Algorithms.md


./AI-Deep-Learning.md

##### LLMs Architecture

In the following page you will find the basics of each component to build a basic LLM using transformers:

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Dangling CNAME → claim service → host content on trusted subdomain
- Takeover → OAuth redirect_uri / cookie-scope → ATO
- DETECT AND REPORT ONLY — never claim the resource

## Hunter2 wiring
- **Run:** `/takeover · tools/takeover_scanner.sh (DETECT-ONLY)`
- **Skill:** `cloud-security`
- **Coverage-matrix tier:** 3 (Tier 0 = test first)
