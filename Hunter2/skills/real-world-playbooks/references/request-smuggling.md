# Real-World Playbook — HTTP Request Smuggling

**Class:** `request-smuggling` · **Coverage-matrix tier:** 2 · **Hunter2:** novel-vuln-reasoner · vuln_scanner.sh · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed HTTP Request Smuggling reports peak at **$7,500**. Rewarded across: Basecamp, Cloudflare Public Bug Bounty, GSA Bounty, Internet Bug Bounty, Lob, Mail.ru, New Relic, Visma Public.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **HTTP Request Smuggling via HTTP/2** — Basecamp, $7,500 · 298👍 · [1211724](https://hackerone.com/reports/1211724)
- **HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function** — Cloudflare Public Bug Bounty, $6,000 · 115👍 · [1478633](https://hackerone.com/reports/1478633)
- **HTTP request smuggling (?) canpol.deti.mail.ru** — Mail.ru, $5,000 · 241👍 · [957881](https://hackerone.com/reports/957881)
- **Possibility of Request smuggling attack** — Internet Bug Bounty, $4,660 · 93👍 · [2280391](https://hackerone.com/reports/2280391)
- **CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)** — Internet Bug Bounty, $4,660 · 57👍 · [2327341](https://hackerone.com/reports/2327341)
- **Request Smuggling in Apache Tomcat (Important, CVE-2023-45648)** — Internet Bug Bounty, $4,660 · 51👍 · [2299692](https://hackerone.com/reports/2299692)
- **HTTP request smuggling with Origin Rules using newlines in the host_header action parameter** — Cloudflare Public Bug Bounty, $3,100 · 46👍 · [1575912](https://hackerone.com/reports/1575912)
- **Password theft login.newrelic.com via Request Smuggling** — New Relic, $3,000 · 490👍 · [498052](https://hackerone.com/reports/498052)
- **Apache HTTP Server: mod_proxy_ajp: Possible request smuggling** — Internet Bug Bounty, $2,400 · 21👍 · [1594627](https://hackerone.com/reports/1594627)
- **HTTP Request Smuggling Due to Incorrect Parsing of Header Fields** — Internet Bug Bounty, $1,800 · 15👍 · [1888760](https://hackerone.com/reports/1888760)
- **HTTP Request Smuggling via Empty headers separated by CR** — Internet Bug Bounty, $1,800 · 15👍 · [2032842](https://hackerone.com/reports/2032842)
- **CVE-2022-32213 - HTTP Request Smuggling Due to Flawed Parsing of Transfer-Encoding** — Internet Bug Bounty, $1,800 · 13👍 · [1630668](https://hackerone.com/reports/1630668)
- **CVE-2022-32214 - HTTP Request Smuggling Due To Improper Delimiting of Header Fields** — Internet Bug Bounty, $1,800 · 11👍 · [1630669](https://hackerone.com/reports/1630669)
- **CVE-2022-32215 - HTTP Request Smuggling Due to Incorrect Parsing of Multi-line Transfer-Encoding** — Internet Bug Bounty, $1,800 · 6👍 · [1630667](https://hackerone.com/reports/1630667)
- **HTTP Request Smuggling on https://labs.data.gov** — GSA Bounty, $750 · 160👍 · [726773](https://hackerone.com/reports/726773)
- **http request smuggling in pscp.tv and periscope.tv** — X / xAI, $560 · 24👍 · [713285](https://hackerone.com/reports/713285)
- **HTTP Request Smuggling at app.workbox.dk** — Visma Public, $500 · 139👍 · [919988](https://hackerone.com/reports/919988)
- **HTTP Request Smuggling on vpn.lob.com** — Lob, $500 · 123👍 · [694604](https://hackerone.com/reports/694604)

## Chaining — always ask "what does this unlock?"
- CL.TE / TE.CL desync → poison next user's request → cred/session theft
- Smuggle → bypass front-end auth/WAF → reach internal path
- Smuggle → cache poisoning at scale

## Hunter2 wiring
- **Run:** `novel-vuln-reasoner · vuln_scanner.sh`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 2 (Tier 0 = test first)
