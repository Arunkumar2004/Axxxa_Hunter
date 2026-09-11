# Real-World Playbook — Authentication & Session Flaws

**Class:** `auth-session` · **Coverage-matrix tier:** 0 · **Hunter2:** /auth-hunt · tools/jwt_scanner.py · tools/h1_oauth_tester.py · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed Authentication & Session Flaws reports peak at **$20,160**. Rewarded across: Basecamp, GitHub, GitHub Security Lab, Internet Bug Bounty, LY Corporation, Nextcloud, Slack, TikTok.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Potential pre-auth RCE on Twitter VPN** — X / xAI, $20,160 · 1241👍 · [591295](https://hackerone.com/reports/591295)
- **Spring Actuator endpoints publicly available and broken authentication** — LY Corporation, $12,500 · 233👍 · [838635](https://hackerone.com/reports/838635)
- **Account Takeover via Authentication Bypass in TikTok Account Recovery** — TikTok, $12,000 · 171👍 · [2443228](https://hackerone.com/reports/2443228)
- **Authentication bypass on gist.github.com through SSH Certificates** — GitHub, $10,000 · 181👍 · [1901040](https://hackerone.com/reports/1901040)
- **OneLogin authentication bypass on WordPress sites** — Uber, $10,000 · 58👍 · [136169](https://hackerone.com/reports/136169)
- **SAML Authentication Bypass on uchat.uberinternal.com** — Uber, $8,500 · 87👍 · [223014](https://hackerone.com/reports/223014)
- **OneLogin authentication bypass on WordPress sites via XMLRPC** — Uber, $7,000 · 83👍 · [138869](https://hackerone.com/reports/138869)
- **[JAVA]: CWE-347 - Improper Verification of Cryptographic Signature : Potential for Auth Bypass** — GitHub Security Lab, $4,500 · 2👍 · [1184041](https://hackerone.com/reports/1184041)
- **[JAVA]: CWE-347 - Improper Verification of Cryptographic Signature : Potential for Auth Bypass** — GitHub Security Lab, $4,000 · 4👍 · [1212274](https://hackerone.com/reports/1212274)
- **[Android] Directory traversal leading to disclosure of auth tokens** — Slack, $3,500 · 50👍 · [1378889](https://hackerone.com/reports/1378889)
- **Missing authentication in buddy group API of LINE TIMELINE** — LY Corporation, $3,000 · 47👍 · [1283938](https://hackerone.com/reports/1283938)
- **Authentication Bypass in ID4me handling via Missing JWT Signature Verification in User OIDC** — Nextcloud, $2,500 · 51👍 · [3489490](https://hackerone.com/reports/3489490)
- **Java: CWE-522 Insecure basic authentication** — GitHub Security Lab, $2,300 · 10👍 · [963815](https://hackerone.com/reports/963815)
- **TLS client authentication can be bypassed due to ticket resumption** — Internet Bug Bounty, $2,162 · 31👍 · [2978267](https://hackerone.com/reports/2978267)
- **Improper bot-authentication allows to impersonate any user when sending messages in a room** — Basecamp, $2,000 · 126👍 · [3329310](https://hackerone.com/reports/3329310)
- **Pre-auth Remote Code Execution on multiple Uber SSL VPN servers** — Uber, $2,000 · 80👍 · [540242](https://hackerone.com/reports/540242)
- **Authentication Bypass with usage of PreSignedURL** — ownCloud, $2,000 · 43👍 · [2337427](https://hackerone.com/reports/2337427)
- **Authentication bypass leads to sensitive data exposure (token+secret)** — Slack, $2,000 · 10👍 · [129918](https://hackerone.com/reports/129918)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

## Authentication Bypass
[ ] 
```
1. Check if post authentication URLs are directly accessible and do not have any session bound to it.
2. In case the URL is stolen/guessable/brute-forceable, it can lead to account takeover.
```

[ ] CAPTCHA Bypass - X-Forwarded-For
```
1. Bypass the CAPTCHA check by injecting a random value into the **X-Forwarded-For header
```

[ ] Lack of Password Confirmation
```
Test if password confirmation is necessary with these actions:
- Change Email Address
- Change Password
- Delete Account
- Manage 2FA
```

[ ] Lack of Verification Email
```
1. Check that during the registration process, an email verification is necessary
```


[ ] No Rate Limiting on a Form
```
1. Send a form and intercept the request with Burp proxy
2. Send the request to intruder
3. Repeat sending the same request 20-30 times
4. Observe that all of these forms are sent without any restrictions
```


[ ] No Rate Limiting or Captcha on Login Page
```
1. Go to login page and send the unsuccessful login attempt request to Burp Intruder
2. Change the password values for brute force as random values
3. Observe that the response to the 20 or 30th request doesn't change and the account is not locked.
```

[ ] Username Email Address Enumeration
```
1. Go to password reset/login/register or any other area that allows writing username or email address input
2. Write an existing username/email address with wrong password to observe error message
3. Write a non-existing username/email address to observe error message
4. See if error message leaks the information of the existence of username/email addresses
```

[ ] Weak Password Policy
```
1. Change password to only numerical
2. Change password to only lower case
3. Change password to common passwords
4. Change password to short passwords
5. Observe that the application has weak or no password policy
```

[ ] Weak Registration Implementation over HTTP
```
1. Intercept the request during the registration to the application via Burp
2. Observe that registration request is sent over HTTP
```

[ ] secure data transport
```
1. search on login page 
2. Send a form and intercept the request with Burp proxy
3. intercept the request with wireshark
4. make sure that the data transport is encryption or not 
```

[ ] Username enumeration
```
1. Status codes
2. Error messages
3. Response times 
   X-Forwarded-For: 
```
   
[ ] Broken Authentication Session Token Bug
```
1. Create a courier account or use existing one.
2. Confirm Your email address.
3. Now log out from your account and request for password reset code for your account .
4. Don't use the code that has been sent to your email address.
5. In new tab or new browser log in back to your account.
6. Go to account setting and change your password .
7. Now go to email and check the password reset code that we requested in step 3.
8. Change Your password using that reset password code .
9. You can see that your password has been changed.
```

[ ] Broken Authentication and Session Management
```
1. Create a Phabricator account having email address "a@x.com".
2. Now Logout and ask for password reset link. Don't use the password reset link sent to your mail address.
3. Login using the same password back and update your email address to "b@x.com" and verify the same. Remove "a@x.com".
4. Now logout and use the password reset link which was mailed to "a@x.com" in step 2.
5. Password will be changed.
```

## Chaining — always ask "what does this unlock?"
- Weak/session-fixation → hijack → ATO
- Auth bypass on one endpoint → pivot to authed-only IDOR/BFLA
- Verbose login errors → username enumeration → spray target list

## Hunter2 wiring
- **Run:** `/auth-hunt · tools/jwt_scanner.py · tools/h1_oauth_tester.py`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 0 (Tier 0 = test first)
