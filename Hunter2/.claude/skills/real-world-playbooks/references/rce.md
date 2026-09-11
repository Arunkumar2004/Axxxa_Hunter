# Real-World Playbook — Remote Code Execution

**Class:** `rce` · **Coverage-matrix tier:** 1 · **Hunter2:** oob_listener.py (blind) · vuln_scanner.sh · /deser-hunt · **Skill:** web2-vuln-classes, deserialization
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed Remote Code Execution reports peak at **$33,510**. Rewarded across: Elastic, GitLab, Mail.ru, Mozilla, PayPal, Uber, Valve, X / xAI.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag)** — GitLab, $33,510 · 381👍 · [1609965](https://hackerone.com/reports/1609965)
- **RCE via npm misconfig -- installing internal libraries from the public registry** — PayPal, $30,000 · 936👍 · [925585](https://hackerone.com/reports/925585)
- **Potential pre-auth RCE on Twitter VPN** — X / xAI, $20,160 · 1241👍 · [591295](https://hackerone.com/reports/591295)
- **RCE when removing metadata with ExifTool** — GitLab, $20,000 · 508👍 · [1154542](https://hackerone.com/reports/1154542)
- **RCE via unsafe inline Kramdown options when rendering certain Wiki pages** — GitLab, $20,000 · 427👍 · [1125425](https://hackerone.com/reports/1125425)
- **Struct type confusion RCE** — shopify-scripts, $18,000 · 14👍 · [181879](https://hackerone.com/reports/181879)
- **Git flag injection - local file overwrite to remote code execution** — GitLab, $12,000 · 777👍 · [658013](https://hackerone.com/reports/658013)
- **Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)** — Mozilla, $12,000 · 270👍 · [3782701](https://hackerone.com/reports/3782701)
- **Path traversal, to RCE** — GitLab, $12,000 · 142👍 · [733072](https://hackerone.com/reports/733072)
- **RCE on shared.mail.ru due to "widget" plugin** — Mail.ru, $10,000 · 359👍 · [518637](https://hackerone.com/reports/518637)
- **uber.com may RCE by Flask Jinja2 Template Injection** — Uber, $10,000 · 136👍 · [125980](https://hackerone.com/reports/125980)
- **RCE hazard in reporting (via Chromium)** — Elastic, $10,000 · 25👍 · [1168765](https://hackerone.com/reports/1168765)
- **RCE via npm misconfig -- installing internal libraries from the public registry** — Uber, $9,000 · 325👍 · [1007014](https://hackerone.com/reports/1007014)
- **RCE on CS:GO client using unsanitized entity ID in EntityMsg message** — Valve, $9,000 · 208👍 · [584603](https://hackerone.com/reports/584603)
- **Remote code execution and exfiltration of secret tokens by poisoning the mozilla/fxa CI build cache** — Mozilla, $8,000 · 58👍 · [2255750](https://hackerone.com/reports/2255750)
- **OOB reads in network message handlers leads to RCE** — Valve, $7,500 · 219👍 · [807772](https://hackerone.com/reports/807772)
- **Specially Crafted Closed Captions File can lead to Remote Code Execution in CS:GO and other Source Games** — Valve, $7,500 · 109👍 · [463286](https://hackerone.com/reports/463286)
- **CS:GO Server -\> Client RCE through OOB access in CSVCMsg_SplitScreen + Info leak in HTTP download** — Valve, $7,500 · 66👍 · [1070835](https://hackerone.com/reports/1070835)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

1- RCE via Dependency Confusion
```
Writeup:-
https://systemweakness.com/rce-via-dependency-confusion-e0ed2a127013
https://chevonphillip.medium.com/rce-due-to-dependency-confusion-5000-bounty-fd1b294d645f
https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
https://hackerone.com/reports/1104693
```

2- rce via file upload
```
Writeup:-
https://book.hacktricks.xyz/pentesting-web/file-upload
https://sidblog.medium.com/file-upload-to-rce-7c04b3b252de
https://hackerone.com/reports/678727
```

3- rce via sql injection
```
https://www.oxeye.io/resources/rce-through-sql-injection-vulnerability-in-hashicorps-vault
https://systemweakness.com/sql-injection-to-remote-command-execution-rce-dd9a75292d1d
```

4- rce via lfi
```
https://github.com/RoqueNight/LFI---RCE-Cheat-Sheet
https://himanshugurjar-10413.medium.com/rce-via-lfi-log-poisoning-3a33632caf4a
https://aditya-chauhan17.medium.com/local-file-inclusion-lfi-to-rce-7594e15870e1
```

5- rce via ssrf
```
https://www.youtube.com/watch?v=Vj6oY6IaJdU
https://infosecwriteups.com/exploiting-server-side-request-forgery-ssrf-vulnerability-faeb7ddf5d0e
https://aditya-chauhan17.medium.com/server-side-request-forgery-ssrf-to-rce-c0cb5fc88a94
```

6- rce via xxe
```
https://airman604.medium.com/from-xxe-to-rce-with-php-expect-the-missing-link-a18c265ea4c7
https://www.youtube.com/watch?v=Gz4iPauycKs
https://hackerone.com/reports/227880
```

7- rce via command injection
```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection#command-execution
```

8- rce via Insecure deserialization
```
https://secure-cookie.io/attacks/insecuredeserialization/
https://www.bugbountyhunter.com/hackevents/report?id=867
https://www.bugbountyhunter.com/hackevents/report?id=776
https://portswigger.net/web-security/deserialization/exploiting
```

9- rce via SSTI
```
https://medium.com/r3d-buck3t/rce-with-server-side-template-injection-b9c5959ad31e
https://github.com/epinna/tplmap
https://secure-cookie.io/attacks/ssti/
```

## Chaining — always ask "what does this unlock?"
- Via: upload, SSTI, deserialization, command injection, or known CVE
- Blind RCE → confirm via OOB DNS/HTTP callback → escalate to reverse shell (authorized)

## Hunter2 wiring
- **Run:** `oob_listener.py (blind) · vuln_scanner.sh · /deser-hunt`
- **Skill:** `web2-vuln-classes, deserialization`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
