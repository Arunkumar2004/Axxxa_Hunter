# Real-World Playbook — SSTI (Template Injection)

**Class:** `ssti` · **Coverage-matrix tier:** 1 · **Hunter2:** vuln_scanner.sh · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed SSTI reports peak at **$2,300**. Rewarded across: GitHub Security Lab, Glovo, HubSpot Inactive, Mail.ru, Node.js third-party modules, Ruby on Rails, Shopify, Unikrn.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **[Ruby]: Server Side Template Injection** — GitHub Security Lab, $2,300 · 13👍 · [1928279](https://hackerone.com/reports/1928279)
- **Path traversal, SSTI and RCE on a MailRu acquisition** — Mail.ru, $2,000 · 152👍 · [536130](https://hackerone.com/reports/536130)
- **H1514 Server Side Template Injection in Return Magic email templates?** — Shopify, $0 (disclosed) · 409👍 · [423541](https://hackerone.com/reports/423541)
- **Urgent: Server side template injection via Smarty template allows for RCE** — Unikrn, $0 (disclosed) · 122👍 · [164224](https://hackerone.com/reports/164224)
- **Reflected XSS and Server Side Template Injection  in all HubSpot CMSes** — HubSpot Inactive, $0 (disclosed) · 64👍 · [399462](https://hackerone.com/reports/399462)
- **Python : Add query to detect Server Side Template Injection** — GitHub Security Lab, $0 (disclosed) · 29👍 · [944359](https://hackerone.com/reports/944359)
- **Server Side Template Injection on Name parameter during Sign Up process** — Glovo, $0 (disclosed) · 26👍 · [1104349](https://hackerone.com/reports/1104349)
- **SSTI leads to Command injection** — curl, $0 (disclosed) · 24👍 · [3584149](https://hackerone.com/reports/3584149)
- **CodeQL query to detect Server-Side Template Injections (JavaScript)** — GitHub Security Lab, $0 (disclosed) · 8👍 · [894872](https://hackerone.com/reports/894872)
- **Server-side Template Injection in lodash.js** — Node.js third-party modules, $0 (disclosed) · 8👍 · [904672](https://hackerone.com/reports/904672)
- **Server-side template injection at ujs test server** — Ruby on Rails, $0 (disclosed) · 5👍 · [942103](https://hackerone.com/reports/942103)
- **Java : Add query to detect Server Side Template Injection (SSTI)** — GitHub Security Lab, $0 (disclosed) · 4👍 · [1490372](https://hackerone.com/reports/1490372)

## Chaining — always ask "what does this unlock?"
- SSTI → **RCE** (Jinja2/Twig/Freemarker gadget)
- Sandboxed SSTI → file read / SSRF at minimum

## Hunter2 wiring
- **Run:** `vuln_scanner.sh`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
