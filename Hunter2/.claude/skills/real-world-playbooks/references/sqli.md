# Real-World Playbook — SQL Injection

**Class:** `sqli` · **Coverage-matrix tier:** 1 · **Hunter2:** vuln_scanner.sh (nuclei/ghauri/sqlmap) · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed SQL Injection reports peak at **$25,000**. Rewarded across: Eternal, GitHub Security Lab, Grab, Internet Bug Bounty, Mail.ru, Razer, Uber, Valve.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **SQL Injection in report_xml.php through countryFilter[] parameter** — Valve, $25,000 · 406👍 · [383127](https://hackerone.com/reports/383127)
- **Time-Based SQL injection at city-mobil.ru** — Mail.ru, $15,000 · 631👍 · [868436](https://hackerone.com/reports/868436)
- **SQL injection at fleet.city-mobil.ru** — Mail.ru, $10,000 · 372👍 · [881901](https://hackerone.com/reports/881901)
- **SQL Injection [unauthenticated] with direct output at https://news.mail.ru/** — Mail.ru, $7,500 · 156👍 · [818972](https://hackerone.com/reports/818972)
- **[windows10.hi-tech.mail.ru]  Blind SQL Injection** — Mail.ru, $5,000 · 330👍 · [786044](https://hackerone.com/reports/786044)
- **turboslim.lady.mail.ru - Blind sql-injection.** — Mail.ru, $5,000 · 93👍 · [795291](https://hackerone.com/reports/795291)
- **SQL injection  delivery-club.ru (ClickHouse)** — Mail.ru, $5,000 · 76👍 · [1024773](https://hackerone.com/reports/1024773)
- **[www.zomato.com] SQLi - /php/██████████ - item_id** — Eternal, $4,500 · 326👍 · [403616](https://hackerone.com/reports/403616)
- **www.drivegrab.com SQL injection** — Grab, $4,500 · 203👍 · [273946](https://hackerone.com/reports/273946)
- **C++: Support Pqxx connector to search for sql injections to Postgres** — GitHub Security Lab, $4,500 · 15👍 · [1241583](https://hackerone.com/reports/1241583)
- **CVE-2024-42005: Potential SQL injection in QuerySet.values() and values_list()** — Internet Bug Bounty, $4,263 · 52👍 · [2646493](https://hackerone.com/reports/2646493)
- **Blind SQL injection on id.indrive.com** — inDrive, $4,134 · 198👍 · [2051931](https://hackerone.com/reports/2051931)
- **[api.easy2pay.co]  SQL Injection at fortumo via TransID parameter [Bypassing Signature Validation🔥]** — Razer, $4,000 · 232👍 · [894325](https://hackerone.com/reports/894325)
- **SQL Injection on sctrack.email.uber.com.cn** — Uber, $4,000 · 93👍 · [150156](https://hackerone.com/reports/150156)
- **Blind SQL injection on [city-mobil.ru/taxiserv/] in filter{"id_locality"}** — Mail.ru, $3,500 · 30👍 · [1133083](https://hackerone.com/reports/1133083)
- **Blind SQL Injection on news.mail.ru** — Mail.ru, $3,000 · 52👍 · [732430](https://hackerone.com/reports/732430)
- **SQL injection in Wordpress Plugin Huge IT Video Gallery at https://drive.uber.com/frmarketplace/** — Uber, $3,000 · 39👍 · [125932](https://hackerone.com/reports/125932)
- **SQL injection in 3rd party software Anomali** — Uber, $2,500 · 61👍 · [206872](https://hackerone.com/reports/206872)

## Chaining — always ask "what does this unlock?"
- Auth-bypass SQLi at login → ATO/admin
- Union/error → dump users+hashes → crack → ATO
- Blind boolean/time → confirm via OOB; stacked → RCE where supported

## Hunter2 wiring
- **Run:** `vuln_scanner.sh (nuclei/ghauri/sqlmap)`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
