# Real-World Playbook — Web Cache Poisoning / Deception

**Class:** `web-cache` · **Coverage-matrix tier:** 2 · **Hunter2:** novel-vuln-reasoner · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed Web Cache Poisoning / Deception reports peak at **$9,700**. Rewarded across: Algolia, Discourse, GSA Bounty, Glassdoor, Lyst, Mail.ru, OLX, PayPal.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **DoS on PayPal via web cache poisoning** — PayPal, $9,700 · 851👍 · [622122](https://hackerone.com/reports/622122)
- **https://themes.shopify.com::: Host header web cache poisoning lead to DoS** — Shopify, $2,900 · 82👍 · [1096609](https://hackerone.com/reports/1096609)
- **Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage** — Shopify, $800 · 48👍 · [1271944](https://hackerone.com/reports/1271944)
- **Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS** — GSA Bounty, $750 · 93👍 · [303730](https://hackerone.com/reports/303730)
- **Web cache poisoning attack leads to user information and more** — Postmates, $500 · 343👍 · [492841](https://hackerone.com/reports/492841)
- **Web Cache Deception vulnerability on algolia.com leads to personal information leakage** — Algolia, $400 · 46👍 · [1530066](https://hackerone.com/reports/1530066)
- **Web cache information leakage at sbermarket.ru** — Mail.ru, $400 · 22👍 · [893353](https://hackerone.com/reports/893353)
- **Web Cache Deception Attack (XSS)** — Discourse, $256 · 51👍 · [394016](https://hackerone.com/reports/394016)
- **Web cache deception attack on https://open.vanillaforums.com/messages/all** — Vanilla, $150 · 47👍 · [593712](https://hackerone.com/reports/593712)
- **Web Cache Poisoning leads to Stored XSS** — Glassdoor, $0 (disclosed) · 133👍 · [1424094](https://hackerone.com/reports/1424094)
- **Web Cache Poisoning leads to XSS and DoS** — Glassdoor, $0 (disclosed) · 71👍 · [1621540](https://hackerone.com/reports/1621540)
- **web cache deception in https://tradus.com lead to name/user_id enumeration and other info** — OLX, $0 (disclosed) · 63👍 · [537564](https://hackerone.com/reports/537564)
- **Web Cache Deception** — Glassdoor, $0 (disclosed) · 62👍 · [2265400](https://hackerone.com/reports/2265400)
- **[https://www.glassdoor.com] -  Web Cache Deception Leads to gdtoken Disclosure** — Glassdoor, $0 (disclosed) · 60👍 · [1343086](https://hackerone.com/reports/1343086)
- **CSRF-tokens on pages without no-cache headers, resulting in ATO when using CloudFlare proxy (Web Cache Deception)** — Discourse, $0 (disclosed) · 58👍 · [260697](https://hackerone.com/reports/260697)
- **Web Cache poisoning attack leads to User information Disclosure and more** — Lyst, $0 (disclosed) · 45👍 · [631589](https://hackerone.com/reports/631589)
- **Web cache poisoning leads to disclosure of CSRF token and sensitive information** — Smule, $0 (disclosed) · 39👍 · [504514](https://hackerone.com/reports/504514)
- **Web Cache Poisoning on  █████** — U.S. Dept Of Defense, $0 (disclosed) · 36👍 · [1183263](https://hackerone.com/reports/1183263)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
    Values: User-Agent
    Values: Cookie
    Header: X-Forwarded-Host
    Header: X-Host
    Header: X-Forwarded-Server
    Header: X-Forwarded-Scheme (header; also in combination with X-Forwarded-Host)
    Header: X-Original-URL (Symfony)
    Header: X-Rewrite-URL (Symfony)
```
```
    GET /test?buster=123 HTTP/1.1
    Host: target.com
    X-Forwarded-Host: test"><script>alert(1)</script>

    HTTP/1.1 200 OK
    Cache-Control: public, no-cache
    [..]
    <meta property="og:image" content="https://test"><script>alert(1)</script>">
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From AllAboutBugBounty
### Web Cache Deception

#### Introduction
Web Cache Deception is an attack in which an attacker deceives a caching proxy into improperly storing private information sent over the internet and gaining unauthorized access to that cached data

#### Where to find
`-`

#### How to exploit
* Normal Request (For example in the settings profile feature)
```
GET /profile/setting HTTP/1.1
Host: www.vuln.com
```
The response is
```
HTTP/2 200 OK 
Content-Type: text/html
Cf-Cache-Status: HIT 
...
```

1. Try to add cacheable extension (For example .js / .css / .jpg, etc.)
```
GET /profile/setting/.js HTTP/1.1
Host: www.vuln.com
```
The response is
```
HTTP/2 200 OK 
Content-Type: text/html
Cf-Cache-Status: HIT 
...
```
If the `Cf-Cache-Status` response the request with `HIT` not `MISS` or `Error`. And then try to open the url in incognito mode

1. Add `;` before the extension (For example `;.js` / `;.css` / `;.jpg`, etc.)
```
GET /profile/setting/;.js HTTP/1.1
Host: www.vuln.com
```
The response is
```
HTTP/2 200 OK 
Content-Type: text/html
Cf-Cache-Status: HIT 
...
```
If the `Cf-Cache-Status` response the request with `HIT` not `MISS` or `Error`. And then try to open the url in incognito mode

#### References
* [@bxmbn](https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9)

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Cache Poisoning and Cache Deception


#### The difference

> **What is the difference between web cache poisoning and web cache deception?**
>
> - In **web cache poisoning**, the attacker causes the application to store some malicious content in the cache, and this content is served from the cache to other application users.
> - In **web cache deception**, the attacker causes the application to store some sensitive content belonging to another user in the cache, and the attacker then retrieves this content from the cache.

#### Cache Poisoning

Web cache poisoning manipulates a shared cache into storing a harmful response that is later served to other users. Impact depends on the cache key, cache lifetime, affected route, and traffic reaching the poisoned entry.<sup>[[1]](#references)</sup>

The execution of a cache poisoning assault involves several steps:

1. **Identification of Unkeyed Inputs**: These are parameters that, although not required for a request to be cached, can alter the response returned by the server. Identifying these inputs is crucial as they can be exploited to manipulate the cache.
2. **Exploitation of the Unkeyed Inputs**: After identifying the unkeyed inputs, the next step involves figuring out how to misuse these parameters to modify the server's response in a way that benefits the attacker.
3. **Ensuring the Poisoned Response is Cached**: The final step is to ensure that the manipulated response is stored in the cache. This way, any user accessing the affected page while the cache is poisoned will receive the tainted response.

##### Discovery: Check HTTP headers


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Unkeyed header reflected + cached → stored XSS to all users
- Cache deception (/account/foo.css) → cache victim's private page → info leak

## Hunter2 wiring
- **Run:** `novel-vuln-reasoner`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 2 (Tier 0 = test first)
