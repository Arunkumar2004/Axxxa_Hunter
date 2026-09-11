# Real-World Playbook — XXE (XML External Entities)

**Class:** `xxe` · **Coverage-matrix tier:** 1 · **Hunter2:** /xxe · tools/xxe_scanner.py · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed XXE reports peak at **$6,000**. Rewarded across: DuckDuckGo, GitHub Security Lab, Informatica, Mail.ru, Open-Xchange, Pornhub, Rockstar Games, Semrush.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **XXE on pulse.mail.ru** — Mail.ru, $6,000 · 264👍 · [505947](https://hackerone.com/reports/505947)
- **Multiple endpoints are vulnerable to XML External Entity injection (XXE)** — Pornhub, $2,500 · 138👍 · [72272](https://hackerone.com/reports/72272)
- **Blind XXE via Powerpoint files** — Open-Xchange, $2,000 · 86👍 · [334488](https://hackerone.com/reports/334488)
- **[Python]: CWE-611: XXE** — GitHub Security Lab, $1,800 · 4👍 · [1512937](https://hackerone.com/reports/1512937)
- **LFI and SSRF via XXE in emblem editor** — Rockstar Games, $1,500 · 79👍 · [347139](https://hackerone.com/reports/347139)
- **blind XXE when uploading avatar in mymail phone app** — Mail.ru, $1,000 · 12👍 · [277341](https://hackerone.com/reports/277341)
- **Blind XXE on my.mail.ru** — Mail.ru, $800 · 23👍 · [276276](https://hackerone.com/reports/276276)
- **Blind OOB XXE At "http://ubermovement.com/"** — Uber, $500 · 56👍 · [154096](https://hackerone.com/reports/154096)
- **Blind XXE on pu.vk.com** — VK.com, $500 · 18👍 · [296622](https://hackerone.com/reports/296622)
- **OOB XXE** — Mail.ru, $500 · 12👍 · [690387](https://hackerone.com/reports/690387)
- **OOB XXE** — Mail.ru, $500 · 5👍 · [690295](https://hackerone.com/reports/690295)
- **XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx** — Starbucks, $0 (disclosed) · 318👍 · [500515](https://hackerone.com/reports/500515)
- **XXE on sms-be-vip.twitter.com in SXMP Processor** — X / xAI, $0 (disclosed) · 258👍 · [248668](https://hackerone.com/reports/248668)
- **XXE on https://duckduckgo.com** — DuckDuckGo, $0 (disclosed) · 218👍 · [483774](https://hackerone.com/reports/483774)
- **Phone Call to XXE via Interactive Voice Response** — ██████, $0 (disclosed) · 172👍 · [395296](https://hackerone.com/reports/395296)
- **Partial bypass of #483774 with Blind XXE on https://duckduckgo.com** — DuckDuckGo, $0 (disclosed) · 159👍 · [486732](https://hackerone.com/reports/486732)
- **XXE through injection of a payload in the XMP metadata of a JPEG file** — Informatica, $0 (disclosed) · 137👍 · [836877](https://hackerone.com/reports/836877)
- **XXE in Site Audit function exposing file and directory contents** — Semrush, $0 (disclosed) · 114👍 · [312543](https://hackerone.com/reports/312543)

## Chaining — always ask "what does this unlock?"
- XXE → file read (/etc/passwd, config) → secrets
- XXE → **SSRF** → cloud metadata → creds
- Blind XXE → OOB exfil via external DTD
- Hidden XXE in SVG/DOCX/XLSX upload, SOAP, SAML

## Hunter2 wiring
- **Run:** `/xxe · tools/xxe_scanner.py`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
