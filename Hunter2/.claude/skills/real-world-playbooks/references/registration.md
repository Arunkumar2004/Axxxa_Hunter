# Real-World Playbook — Registration / Signup Flaws

**Class:** `registration` · **Coverage-matrix tier:** 1 · **Hunter2:** /auth-hunt · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

## register vulnerability
[ ] Duplicate registration overwrite existing user
```
1. create first account in application with email say abc@gmail.com and password
2. logout of the account and create another account with same email and different password
3. you can even try to change email case like from abc2gmail.com to Abc@gmail.com
4. finish the creation proccess and see that it succceed
5. now go back and try to login with email and the new password ,you are seccess logged in
```
[ ] Dos at name /password field in sign up page
```
1. go to sign up form
2. fill the form and enter a long string in password 
3. click on enter and you will get 500 internal server error if it is vulnerability
```

[ ] no rate limit at signup page
```
1. enter your details in signuo form and submit the form
2. capture the signuo request and send it to intruder
3. add $$ to email parameter
4. in the payload add different email address
5. fire up intruder and check whether it return 200 ok
```

[ ] xss in username,email
```
xss can be test in any of parameter
1. payload for text field:
2. payload for email field:
3. you can use bypassing filter
```

[ ] email varification can be easily bypassed with following method
```
1. response manipulation change the bad respone with good one like false to true
2. status code manipulation change the 403 to 200
```

[ ] weak register implemntation
```
1. check whether the allows disposable email addresses
2. register form on non-https page
```

[ ] weak password policy
```
1. check whether application allows easily guessable passsword like 123456
2. check if you can use username same as the email address
3. check if can use password same as that email address
4. improperly implemented password recovery link functionality
```

[ ] Path Overwrite
```
If an application allows users to check their profile with direct path /{username} always try to signup with system reserved file names, such as index.php, signup.php, login.php, etc. In some cases what happens here is, when you signup with username: index.php, now upon visiting target.tld/index.php, your profile will comeup and occupy the index.php page of an application. Similarly, if an attacker is able to signup with username login.php, Imagine login page getting takeovered.
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### User Registration Process

|ID          |
|------------|
|WSTG-IDNT-02|

#### Summary

Some websites offer a user registration process that automates (or semi-automates) the provisioning of system access to users. The identity requirements for access vary from positive identification to none at all, depending on the security requirements of the system. Many public applications completely automate the registration and provisioning process because the size of the user base makes it impossible to manage manually. However, many corporate applications will provision users manually, so this test case may not apply.

#### Test Objectives

- Verify that the identity requirements for user registration are aligned with business and security requirements.
- Validate the registration process.

#### How to Test

Verify that the identity requirements for user registration are aligned with business and security requirements:

1. Can anyone register for access?
2. Are registrations vetted by a human prior to provisioning, or are they automatically granted if the criteria are met?
3. Can the same person or identity register multiple times?
4. Can users register for different roles or permissions?
5. What proof of identity is required for a registration to be successful?
6. Are registered identities verified?

Validate the registration process:

1. Can identity information be easily forged or faked?
2. Can the exchange of identity information be manipulated during registration?

##### Example

In the WordPress example below, the only identification requirement is an email address that is accessible to the registrant.

*Figure 4.3.2-1: WordPress Registration Page*

In contrast, in the Google example below the identification requirements include name, date of birth, country, mobile phone number, email address and CAPTCHA response. While only two of these can be verified (email address and mobile number), the identification requirements are stricter than WordPress.

*Figure 4.3.2-2: Google Registration Page*

Some applications may also automatically grant privileged roles to users when they register an account with an email address from a trusted domain. If ownership of the email address is not validated as part of the registration process, this could allow an attacker to gain access to a privileged account by registering a new user on that domain.

Alternatively, if they only perform partial matching of the domain then it may be possible to register a privileged account using other similar domains. For example, if the application checks for email addresses ending in `example.org` then it may be possible to use the `notexample.org` domain; or if it checks for `@example.org` in the email address then it may be possible to use `@example.org.attacker.com`.

#### Remediation

Implement identification and verification requirements that correspond to the security requirements of the information the credentials protect.

#### Tools

A HTTP proxy can be a useful tool to test this control.

#### References

[User Registration Design](https://mashable.com/2011/06/09/user-registration-design/)

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Registration & Takeover Vulnerabilities


#### Registration Takeover

##### Duplicate Registration

- Try to generate using an existing username
- Check varying the email:
  - uppercase
  - +1@
  - add some dot in the email
  - special characters in the email name (%00, %09, %20)
  - Put blank characters after the email: `test@test.com a`
  - victim@gmail.com@attacker.com
  - victim@attacker.com@gmail.com
  - Try email provider canonicalization tricks (service-dependent):
    - Gmail ignores dots and subaddressing: `victim+1@gmail.com`, `v.ic.tim@gmail.com` deliver to `victim@gmail.com`
    - Some providers are case-insensitive in the local-part
    - Some providers accept unicode confusables. Try homoglyphs and soft hyphen `\u00AD` within the local-part
  - Abuse these to: bypass uniqueness checks, obtain duplicate accounts/workspace invites, or block victim sign‑ups (temporary DoS) while you prepare a takeover


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Pre-account takeover (register victim email before they do)
- Email verification bypass → trusted account
- Duplicate/normalization (unicode, +alias, case) → collision

## Hunter2 wiring
- **Run:** `/auth-hunt`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- No-rate-limit on the signup form alone (non-critical, often behind Cloudflare) — no OTP/payment surface abused
- Weak password policy / disposable-email acceptance / autocomplete-on — best-practice nits, not vulns
- DoS via long password/username field (500 error) with no real availability impact
- Self-only duplicate registration that doesn't collide with or lock out a victim account
- XSS-in-username "found" but never rendered/executed against another user
- Pre-account takeover claimed without the very specific preconditions actually met

**Conditionally valid (only WITH a chain):** email-verification bypass → trusted/privileged account; duplicate/normalization collision (unicode, +alias, case) that overwrites a victim's account → ATO; pre-ATO with all conditions proven.
