# Real-World Playbook — Information Disclosure

**Class:** `info-disclosure` · **Coverage-matrix tier:** 1 · **Hunter2:** recon · vuln_scanner.sh · tools/secrets_hunter.sh · tools/sourcemap_extract.py · **Skill:** web2-recon
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed Information Disclosure reports peak at **$10,000**. Rewarded across: Eternal, GitLab, HackerOne, Internet Bug Bounty, Mail.ru, New Relic, Postmates, Razer.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Information Disclosure in /skills call** — HackerOne, $10,000 · 285👍 · [188719](https://hackerone.com/reports/188719)
- **CVE-2025-24813: Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet** — Internet Bug Bounty, $4,323 · 56👍 · [3031518](https://hackerone.com/reports/3031518)
- **information disclosure of secret_key_base via encoding charcters** — GitLab, $3,500 · 146👍 · [460545](https://hackerone.com/reports/460545)
- **[Information Disclosure] Amazon S3 Bucket of Shopify Ping (iOS) have public access of other users image** — Shopify, $2,900 · 135👍 · [1021906](https://hackerone.com/reports/1021906)
- **Possible PII Disclosure via Advanced Vetting Process - ██████** — HackerOne, $2,500 · 82👍 · [2421796](https://hackerone.com/reports/2421796)
- **Flash Player information disclosure (etc.) CVE-2015-3044, PSIRT-3298** — Internet Bug Bounty, $2,000 · 8👍 · [63324](https://hackerone.com/reports/63324)
- **Security bypass could lead to information disclosure** — Internet Bug Bounty, $2,000 · 3👍 · [7803](https://hackerone.com/reports/7803)
- **Information disclosure with sensitive data** — Mail.ru, $1,500 · 156👍 · [703600](https://hackerone.com/reports/703600)
- **Improper access control on easytopup.in.th transaction page leads to user's information disclosure and may lead to account hijacking** — Razer, $1,000 · 41👍 · [776877](https://hackerone.com/reports/776877)
- **User sensitive information disclosure** — Shopify, $1,000 · 40👍 · [975047](https://hackerone.com/reports/975047)
- **Restricted user can view all account invoices, payment method details, PII of account owner through zoura_api endpoints** — New Relic, $900 · 7👍 · [501672](https://hackerone.com/reports/501672)
- **Information Disclosure through Sentry Instance ███████** — Eternal, $750 · 178👍 · [697512](https://hackerone.com/reports/697512)
- **[Zomato Order] Insecure deeplink leads to sensitive information disclosure** — Eternal, $750 · 113👍 · [532225](https://hackerone.com/reports/532225)
- **Information Disclosure on stun.screenhero.com** — Slack, $700 · 14👍 · [175061](https://hackerone.com/reports/175061)
- **Information Disclosure through .DS_Store in ██████████** — X / xAI, $560 · 27👍 · [142549](https://hackerone.com/reports/142549)
- **Twitter Ads Campaign information disclosure through admin without any authentication.** — X / xAI, $560 · 6👍 · [49806](https://hackerone.com/reports/49806)
- **Web cache poisoning attack leads to user information and more** — Postmates, $500 · 343👍 · [492841](https://hackerone.com/reports/492841)
- **Unauthenticated access to sensitive user information** — Razer, $500 · 184👍 · [702677](https://hackerone.com/reports/702677)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

<h4>Summary:</h4>
When a user uploads an image in example.com, the uploaded image’s EXIF Geolocation Data does not gets stripped. As a result, anyone can get sensitive information of example.com users like their Geolocation, their Device information like Device Name, Version, Software & Software version used etc.

<h4>Steps to reproduce:</h4>

1. Got to Github ( https://github.com/ianare/exif-samples/tree/master/jpg) <br>
2. There are lot of images having resolutions (i.e 1280 * 720 ) , and also whith different MB’s . <br>
3. Go to Upload option on the website <br>
4. Upload the image<br>
5. see the path of uploaded image ( Either by right click on image then copy image address OR right click, inspect the image, the URL will come in the inspect ,   edit it as html )</br>
6. open it (http://exif.regex.info/exif.cgi)</br>
7. See wheather is that still showing exif data , if it is then Report it.

# Reports (Hackerone)

- [IDOR with Geolocation data not stripped from images](https://hackerone.com/reports/906907)

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Stealing Sensitive Information from a Web Page


If a **web page displays sensitive information based on the current session**—such as cookies, account data, or credit card details—an attacker may try to exfiltrate it. The main techniques include:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): A CORS misconfiguration may allow a malicious origin to read sensitive responses through cross-origin requests.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): An XSS vulnerability in the target origin may allow injected JavaScript to read and exfiltrate the information.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): When script injection is unavailable, injected HTML elements may still capture sensitive content.
- [**Clickjacking**](../pentesting-web/clickjacking.md): If framing protections are absent, an attacker may trick a user into interacting with the sensitive page. The linked case study demonstrates this technique.<sup>[[1]](#references)</sup>

#### References

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

## Chaining — always ask "what does this unlock?"
- Leaked userID/email → targeted IDOR/BOLA
- Leaked API key/secret (JS, .git, source map) → authed API abuse
- Verbose stack trace → tech stack → targeted CVE / SSTI

## Hunter2 wiring
- **Run:** `recon · vuln_scanner.sh · tools/secrets_hunter.sh · tools/sourcemap_extract.py`
- **Skill:** `web2-recon`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- Low-impact version/banner disclosure or verbose errors with no sensitive data → informational
- Internal IP in an error message; mixed content; SSL weak ciphers
- Missing security headers (CSP/HSTS), missing HttpOnly/Secure cookie flags alone
- SAML metadata / public signing cert exposed (documented by the IdP, no private key or cert extracted)
- Stack trace revealing the tech stack with no secret, credential, or PII
- Nuclei `info` template match — detection, not exploitation

**Conditionally valid (only WITH a chain):** leaked API key/secret in a JS bundle, `.git`, or source map → authed API abuse; S3/bucket listing + keys in JS → Medium/High; leaked userID/email → chained IDOR/BOLA with the other user's data actually read.
