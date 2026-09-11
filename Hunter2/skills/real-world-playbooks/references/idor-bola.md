# Real-World Playbook — IDOR / BOLA (Broken Object-Level Auth)

**Class:** `idor-bola` · **Coverage-matrix tier:** 0 · **Hunter2:** tools/h1_idor_scanner.py · tools/h1_mutation_idor.py · tools/apispec_idor.py · /api-audit · **Skill:** api-security, auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed IDOR / BOLA reports peak at **$10,500**. Rewarded across: GitLab, Judge.me, Mail.ru, New Relic, Open-Xchange, PayPal, Pornhub, Reddit.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users** — PayPal, $10,500 · 791👍 · [415081](https://hackerone.com/reports/415081)
- **IDOR on GraphQL queries BillingDocumentDownload and BillDetails** — Shopify, $5,000 · 186👍 · [2207248](https://hackerone.com/reports/2207248)
- **Getting access of mod logs from any public or restricted subreddit with IDOR vulnerability** — Reddit, $5,000 · 159👍 · [1658418](https://hackerone.com/reports/1658418)
- **An IDOR that can lead to enumeration of a user and disclosure of email and phone number within cashier** — Unikrn, $3,000 · 232👍 · [1966006](https://hackerone.com/reports/1966006)
- **[api.pandao.ru] IDOR for order delivery address** — Mail.ru, $3,000 · 125👍 · [723461](https://hackerone.com/reports/723461)
- **IDOR the ability to view support tickets of any user on seller platform** — TikTok, $2,500 · 74👍 · [1392630](https://hackerone.com/reports/1392630)
- **[NR Insights] IDOR - Modify the filter settings for any NR Insights dashboard through internal_api endpoint** — New Relic, $2,500 · 28👍 · [459443](https://hackerone.com/reports/459443)
- **idor allows you to delete photos and album from a gallery** — Pornhub, $1,500 · 266👍 · [380410](https://hackerone.com/reports/380410)
- **IDOR allows any user to edit others videos** — Pornhub, $1,500 · 248👍 · [681473](https://hackerone.com/reports/681473)
- **IDOR via internal_api "users" endpoint** — New Relic, $1,500 · 77👍 · [349291](https://hackerone.com/reports/349291)
- **IDOR - disclosure of private videos - /api_android_v3/getUserVideos** — Pornhub, $1,500 · 32👍 · [186279](https://hackerone.com/reports/186279)
- **[NR Alerts/Synthetics] IDOR through /policies.json with Synthetics exposes full name of other NR users** — New Relic, $1,500 · 14👍 · [419875](https://hackerone.com/reports/419875)
- **IDOR: leak buyer info & Publish/Hide foreign comments** — Judge.me, $1,250 · 46👍 · [1410498](https://hackerone.com/reports/1410498)
- **IDOR Exposes All Machine Learning Models** — GitLab, $1,160 · 115👍 · [2528293](https://hackerone.com/reports/2528293)
- **[api.pandao.ru] IDOR позволяет изменять адрес любого пользователя** — Mail.ru, $1,000 · 33👍 · [484339](https://hackerone.com/reports/484339)
- **IDOR expire other user sessions** — Shopify, $1,000 · 29👍 · [56511](https://hackerone.com/reports/56511)
- **IDOR - Downloading all attachements if having access to a shared link** — Open-Xchange, $888 · 26👍 · [194790](https://hackerone.com/reports/194790)
- **IDOR - Accessing other user's attachements via PUT /appsuite/api/files?action=saveAs** — Open-Xchange, $888 · 20👍 · [204984](https://hackerone.com/reports/204984)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

Base Steps:
```bash
1. Create two accounts if possible or else enumerate users first. 
2. Check if the endpoint is private or public and does it contains any kind of id param.
3. Try changing the param value to some other user and see if does anything to their account.
4. Done !!
```

[ ]
[ ] image profilie
[ ] delete acount 
[ ] infromation acount
[ ] VIEW & DELETE & Create api_key
[ ] allows to read any comment
[ ] change price
[ ] chnage the coin from dollar to uaro
[ ] Try decode the ID, if the ID encoded using md5,base64,etc
```html
GET /GetUser/dmljdGltQG1haWwuY29t
[...]
```

[ ] change HTTP method
```bash
GET /users/delete/victim_id  ->403
POST /users/delete/victim_id ->200
```

[ ] Try replacing parameter names
```bash
Instead of this:
GET /api/albums?album_id=<album id>

Try This:
GET /api/albums?account_id=<account id>

Tip: There is a Burp extension called Paramalyzer which will help with this by remembering all the parameters you have passed to a host.
```

[ ] Path Traversal
```bash
POST /users/delete/victim_id          ->403
POST /users/delete/my_id/..victim_id  ->200
```

[ ] change request content-type
```bash
Content-Type: application/xml ->
Content-Type: application/json
```

[ ] swap non-numeric with numeric id
```bash
GET /file?id=90djbkdbkdbd29dd
GET /file?id=302
```

[ ] Missing Function Level Acess Control 
```bash
GET /admin/profile ->401
GET /Admin/profile ->200
GET /ADMIN/profile ->200
GET /aDmin/profile ->200
GET /adMin/profile ->200
GET /admIn/profile ->200
GET /admiN/profile ->200
```

[ ]send wildcard instead of an id
```bash
GET /api/users/user_id ->
GET /api/users/*
```

[ ] Never ignore encoded/hashed ID
```bash
for hashed ID ,create multiple accounts and understand the ppattern application users to allot an iD
```

[ ] Google Dorking/public form
```bash
search all the endpoints having ID which the search engine may have already indexed
```

[ ] Bruteforce Hidden HTTP  parameters
```bash
use tools like arjun , paramminer 
```

[ ] Bypass object level authorization Add parameter onto the endpoit if not present by defualt
```bash
GET /api_v1/messages ->200
GET /api_v1/messages?user_id=victim_uuid ->200
```

[ ] HTTP Parameter POllution Give mult value for same parameter
```bash
GET /api_v1/messages?user_id=attacker_id&user_id=victim_id
GET /api_v1/messages?user_id=victim_id&user_id=attacker_id
```

[ ] change file type
```bash
GET /user_data/2341        -> 401
GET /user_data/2341.json   -> 200
GET /user_data/2341.xml    -> 200
GET /user_data/2341.config -> 200
GET /user_data/2341.txt    -> 200
```

[ ] json parameter pollution
```bash
{"userid":1234,"userid":2542}
```

[ ] Wrap the ID with an array in the body
```bash
{"userid":123} ->401
{"userid":[123]} ->200
```

[ ] wrap the id with a json object
```bash
{"userid":123} ->401
{"userid":{"userid":123}} ->200
```

[ ] Test an outdata API version 
```bash
GET /v3/users_data/1234 ->401
GET /v1/users_data/1234 ->200
```

[ ] If the website using graphql, try to find IDOR using graphql!
```bash
GET /graphql
[...]
```
```html
GET /graphql.php?query=
[...]
```

## Chaining — always ask "what does this unlock?"
- IDOR on email/password field → **full ATO** (no interaction)
- IDOR read → PII/enumeration → targeted phishing or credential-stuffing list
- Write/DELETE IDOR → destroy/modify other users' objects (campaigns, tickets, photos)
- IDOR price/quantity field → payment/business-logic abuse
- Decode the object id first (base64/md5/seq) — most IDORs hide behind a reversible id

## Hunter2 wiring
- **Run:** `tools/h1_idor_scanner.py · tools/h1_mutation_idor.py · tools/apispec_idor.py · /api-audit`
- **Skill:** `api-security, auth-attacks`
- **Coverage-matrix tier:** 0 (Tier 0 = test first)
