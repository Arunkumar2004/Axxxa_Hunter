# Real-World Playbook — IDOR / BOLA (Broken Object-Level Auth)

**Class:** `idor-bola` · **Coverage-matrix tier:** 0 · **Hunter2:** tools/h1_idor_scanner.py · tools/h1_mutation_idor.py · tools/apispec_idor.py · /api-audit · **Skill:** api-security, auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed IDOR / BOLA reports peak at **$10,500**. Rewarded across: GitLab, Judge.me, Mail.ru, New Relic, Open-Xchange, PayPal, Pornhub, Reddit.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users** — PayPal, $10,500 · 793👍 · [415081](https://hackerone.com/reports/415081)
- **IDOR on GraphQL queries BillingDocumentDownload and BillDetails** — Shopify, $5,000 · 187👍 · [2207248](https://hackerone.com/reports/2207248)
- **Getting access of mod logs from any public or restricted subreddit with IDOR vulnerability** — Reddit, $5,000 · 160👍 · [1658418](https://hackerone.com/reports/1658418)
- **An IDOR that can lead to enumeration of a user and disclosure of email and phone number within cashier** — Unikrn, $3,000 · 232👍 · [1966006](https://hackerone.com/reports/1966006)
- **[api.pandao.ru] IDOR for order delivery address** — Mail.ru, $3,000 · 125👍 · [723461](https://hackerone.com/reports/723461)
- **IDOR the ability to view support tickets of any user on seller platform** — TikTok, $2,500 · 74👍 · [1392630](https://hackerone.com/reports/1392630)
- **[NR Insights] IDOR - Modify the filter settings for any NR Insights dashboard through internal_api endpoint** — New Relic, $2,500 · 28👍 · [459443](https://hackerone.com/reports/459443)
- **idor allows you to delete photos and album from a gallery** — Pornhub, $1,500 · 266👍 · [380410](https://hackerone.com/reports/380410)
- **IDOR allows any user to edit others videos** — Pornhub, $1,500 · 248👍 · [681473](https://hackerone.com/reports/681473)
- **IDOR via internal_api "users" endpoint** — New Relic, $1,500 · 77👍 · [349291](https://hackerone.com/reports/349291)
- **IDOR - disclosure of private videos - /api_android_v3/getUserVideos** — Pornhub, $1,500 · 32👍 · [186279](https://hackerone.com/reports/186279)
- **[NR Alerts/Synthetics] IDOR through /policies.json with Synthetics exposes full name of other NR users** — New Relic, $1,500 · 14👍 · [419875](https://hackerone.com/reports/419875)
- **IDOR: leak buyer info & Publish/Hide foreign comments** — Judge.me, $1,250 · 47👍 · [1410498](https://hackerone.com/reports/1410498)
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

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
<?php
    $user_id = $_GET['user_id'];
    $user_info = get_user_info($user_id);
    ...
```
```
https://example.com/profile?user_id=124
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Insecure Direct Object References

|ID          |
|------------|
|WSTG-ATHZ-04|

#### Summary

Insecure Direct Object References (IDOR) occur when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability attackers can bypass authorization and access resources in the system directly, for example database records or files.
Insecure Direct Object References allow attackers to bypass authorization and access resources directly by modifying the value of a parameter used to directly point to an object. Such resources can be database entries belonging to other users, files in the system, and more. This is caused by the fact that the application takes user supplied input and uses it to retrieve an object without performing sufficient authorization checks.

#### Test Objectives

- Identify points where object references may occur.
- Assess the access control measures and if they're vulnerable to IDOR.

#### How to Test

To test for this vulnerability the tester first needs to map out all locations in the application where user input is used to reference objects directly. For example, locations where user input is used to access a database row, a file, application pages and more. Next the tester should modify the value of the parameter used to reference objects and assess whether it is possible to retrieve objects belonging to other users or otherwise bypass authorization.

The best way to test for direct object references would be by having at least two (often more) users to cover different owned objects and functions. For example two users each having access to different objects (such as purchase information, private messages, etc.), and (if relevant) users with different privileges (for example administrator users) to see whether there are direct references to application functionality. By having multiple users the tester saves valuable testing time in guessing different object names as he can attempt to access objects that belong to the other user.

Below are several typical scenarios for this vulnerability and the methods to test for each:

##### The Value of a Parameter Is Used Directly to Retrieve a Database Record

Sample request:

```text
https://foo.bar/somepage?invoice=12345
```

In this case, the value of the *invoice* parameter is used as an index in an invoices table in the database. The application takes the value of this parameter and uses it in a query to the database. The application then returns the invoice information to the user.

Since the value of *invoice* goes directly into the query, by modifying the value of the parameter it is possible to retrieve any invoice object, regardless of the user to whom the invoice belongs. To test for this case the tester should obtain the identifier of an invoice belonging to a different test user (ensuring he is not supposed to view this information per application business logic), and then check whether it is possible to access objects without authorization.

##### The Value of a Parameter Is Used Directly to Perform an Operation in the System

Sample request:

```text
https://foo.bar/changepassword?user=someuser
```

In this case, the value of the `user` parameter is used to tell the application for which user it should change the password. In many cases this step will be a part of a wizard, or a multi-step operation. In the first step the application will get a request stating for which user's password is to be changed, and in the next step the user will provide a new password (without asking for the current one).

The `user` parameter is used to directly reference the object of the user for whom the password change operation will be performed. To test for this case the tester should attempt to provide a different test username than the one currently logged in, and check whether it is possible to modify the password of another user.

##### The Value of a Parameter Is Used Directly to Retrieve a File System Resource

Sample request:

```text
https://foo.bar/showImage?img=img00011
```

In this case, the value of the `file` parameter is used to tell the application what file the user intends to retrieve. By providing the name or identifier of a different file (for example file=image00012.jpg) the attacker will be able to retrieve objects belonging to other users.

To test for this case, the tester should obtain a reference the user is not supposed to be able to access and attempt to access it by using it as the value of `file` parameter. Note: This vulnerability is often exploited in conjunction with a directory/path traversal vulnerability (see [Path Traversal](01-Directory_Traversal_File_Include.md))


*(truncated — open the source link for the full method)*

### From AllAboutBugBounty
### Insecure Direct Object Reference (IDOR)

#### Introduction
IDOR stands for Insecure Direct Object Reference is a security vulnerability in which a user is able to access and make changes to data of any other user present in the system.

#### Where to find
- Usually it can be found in APIs.
- Check the HTTP request that contain unique ID, for example `user_id` or `id`

#### How to exploit
1. Add parameters onto the endpoints for example, if there was
```
GET /api/v1/getuser HTTP/1.1
Host: example.com
...
```
Try this to bypass
```
GET /api/v1/getuser?id=1234 HTTP/1.1
Host: example.com
...
```

2. HTTP Parameter pollution
```
POST /api/get_profile HTTP/1.1
Host: example.com
...

user_id=hacker_id&user_id=victim_id
```

3. Add .json to the endpoint
```
GET /v2/GetData/1234 HTTP/1.1
Host: example.com
...
```
Try this to bypass
```
GET /v2/GetData/1234.json HTTP/1.1
Host: example.com
...
```

4. Test on outdated API Versions
```
POST /v2/GetData HTTP/1.1
Host: example.com
...

id=123
```
Try this to bypass
```
POST /v1/GetData HTTP/1.1
Host: example.com
...

id=123
```

5. Wrap the ID with an array.
```
POST /api/get_profile HTTP/1.1
Host: example.com
...

{"user_id":111}
```

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### IDOR (Insecure Direct Object Reference)


IDOR (Insecure Direct Object Reference) / Broken Object Level Authorization (BOLA) appears when a web or API endpoint discloses or accepts a user–controllable identifier that is used **directly** to access an internal object **without verifying that the caller is authorized** to access/modify that object.  
Successful exploitation normally allows horizontal or vertical privilege-escalation such as reading or modifying other users’ data and, in the worst case, full account takeover or mass-data exfiltration.

---
#### 1. Identifying Potential IDORs

1. Look for **parameters that reference an object**:
   * Path: `/api/user/1234`, `/files/550e8400-e29b-41d4-a716-446655440000`  
   * Query: `?id=42`, `?invoice=2024-00001`  
   * Body / JSON: `{"user_id": 321, "order_id": 987}`  
   * Headers / Cookies: `X-Client-ID: 4711`
2. Prefer endpoints that **read or update** data (`GET`, `PUT`, `PATCH`, `DELETE`).
3. Note when identifiers are **sequential or predictable** – if your ID is `64185742`, then `64185741` probably exists.
4. Explore hidden or alternate flows (e.g. *"Paradox team members"* link in login pages) that might expose extra APIs.
5. Use an **authenticated low-privilege session** and change only the ID **keeping the same token/cookie**. The absence of an authorization error is usually a sign of IDOR.<sup>[[3]](#references)</sup>

##### Quick manual tampering (Burp Repeater)
```
PUT /api/lead/cem-xhr HTTP/1.1

*(truncated — open the source link for the full method)*

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

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- "IDOR" where the ID in the response is your own account (attacker == victim) — own-data only
- Only a 200 status returned, no actual other-user data visible in the response body
- Works only with NO auth header → that's missing-auth, not IDOR (different bug, different severity)
- Reproduces under only one identity — fails the Q8 cross-identity / stale-cred check
- "API returns more fields than necessary" where the extra fields aren't actually sensitive
- "Admin can do X on behalf of a user" — admin-precondition centralization risk

**Conditionally valid (only WITH a chain):** must prove cross-account access — session A reading/writing session B's object. On an email/password field → full ATO (Critical); write/DELETE on other users' objects → High.
