# Real-World Playbook — Path Traversal / LFI / File Reading

**Class:** `path-traversal-lfi` · **Coverage-matrix tier:** 1 · **Hunter2:** vuln_scanner.sh · manual · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed Path Traversal / LFI / File Reading reports peak at **$12,000**. Rewarded across: GitHub Security Lab, GitLab, Internet Bug Bounty, Keybase, Kubernetes, Mail.ru, Mozilla, Semmle.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Path traversal, to RCE** — GitLab, $12,000 · 142👍 · [733072](https://hackerone.com/reports/733072)
- **Path traversal in Nuget Package Registry** — GitLab, $12,000 · 87👍 · [822262](https://hackerone.com/reports/822262)
- **Arbitrary File Reading on Uber SSL VPN** — Uber, $6,500 · 38👍 · [617543](https://hackerone.com/reports/617543)
- **Mozilla VPN Clients: RCE via file write and path traversal** — Mozilla, $6,000 · 171👍 · [2995025](https://hackerone.com/reports/2995025)
- **Keybase client (Windows 10): Write files anywhere in userland using relative path in "download attachement" feature** — Keybase, $5,000 · 196👍 · [713006](https://hackerone.com/reports/713006)
- **important: Apache HTTP Server weakness in mod_rewrite when first segment of substitution matches filesystem path. (CVE-2024-38475)** — Internet Bug Bounty, $4,920 · 30👍 · [2585378](https://hackerone.com/reports/2585378)
- **Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49** — Internet Bug Bounty, $4,000 · 96👍 · [1394916](https://hackerone.com/reports/1394916)
- **[Android] Directory traversal leading to disclosure of auth tokens** — Slack, $3,500 · 50👍 · [1378889](https://hackerone.com/reports/1378889)
- **Path traversal through path stored in Uint8Array in Node.js 20** — Internet Bug Bounty, $3,495 · 44👍 · [2256167](https://hackerone.com/reports/2256167)
- **[Source Engine] Material path truncation leads to Remote Code Execution** — Valve, $2,500 · 60👍 · [544096](https://hackerone.com/reports/544096)
- **Ingress-nginx path allows retrieval of ingress-nginx serviceaccount token** — Kubernetes, $2,500 · 17👍 · [1382919](https://hackerone.com/reports/1382919)
- **Path traversal by monkey-patching Buffer internals** — Internet Bug Bounty, $2,430 · 67👍 · [2434811](https://hackerone.com/reports/2434811)
- **Permission model improperly protects against path traversal in Node.js 20** — Internet Bug Bounty, $2,330 · 42👍 · [2225660](https://hackerone.com/reports/2225660)
- **Worker container escape lead to arbitrary file reading in host machine [again]** — Semmle, $2,000 · 178👍 · [697055](https://hackerone.com/reports/697055)
- **Path traversal, SSTI and RCE on a MailRu acquisition** — Mail.ru, $2,000 · 152👍 · [536130](https://hackerone.com/reports/536130)
- **Worker container escape lead to arbitrary file reading in host machine** — Semmle, $2,000 · 112👍 · [694181](https://hackerone.com/reports/694181)
- **[Java]: CWE-073 - File path injection with the JFinal framework** — GitHub Security Lab, $1,800 · 4👍 · [1483918](https://hackerone.com/reports/1483918)
- **[JAVA]: Partial Path Traversal** — GitHub Security Lab, $1,800 · 3👍 · [1678405](https://hackerone.com/reports/1678405)

## Chaining — always ask "what does this unlock?"
- LFI → read secrets/config → creds → authed access
- LFI + log poisoning / PHP wrappers → RCE
- Path traversal in download/preview/import param

## Hunter2 wiring
- **Run:** `vuln_scanner.sh · manual`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
