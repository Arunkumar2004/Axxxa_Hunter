# Phase 1 Public Report Catalog

This catalog was generated from 50 public HackerOne JSON summaries downloaded
to the untracked D: research directory. It stores compact metadata and redacted
summaries only; it does not store credentials, cookies, attachments, or raw
authenticated traffic.

The 20 external research cases are recorded in `PHASE1_EXTERNAL_CASES.md` and are
included in the Phase 1 total. They are concrete public case studies, not generic
methodology pages.

## IDOR / BOLA / BFLA

### 1. [415081](https://hackerone.com/reports/415081) - IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Severity/bounty:** high / $10,500
- **Scope:** *.paypal.com
- **Public summary:** PayPal Business Accounts allow account owners to create multiple secondary users with specific privileges assigned to their employees. This submission identified a method that made it possible for a Business Account owner to assign secondary users from other accounts. The new secondary user would be granted access to the login allowing for unauthorized access to the functions of that single user login. PayPal remediated the vulnerability and found no evidence of abuse associated with it.

### 2. [2207248](https://hackerone.com/reports/2207248) - IDOR on GraphQL queries BillingDocumentDownload and BillDetails
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Severity/bounty:** medium / $5,000
- **Scope:** admin.shopify.com
- **Public summary:** There was an IDOR vulnerability that affected the BillingInvoice ID in both the BillingDocumentDownload and BillDetails GraphQL operations. Staff could gain access to some information on other shops through this IDOR. An IDOR with numerical, predictable (incremental) ID allowed anyone to dump billing details for every other shops, which allowed to leak some PII and details from every other Shop owners/employees, through Billing GraphQL operations.

### 3. [1658418](https://hackerone.com/reports/1658418) - Getting access of mod logs from any public or restricted subreddit with IDOR vulnerability
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Severity/bounty:** high / $5,000
- **Scope:** gql.reddit.com
- **Public summary:** No public summary was available.

### 4. [1966006](https://hackerone.com/reports/1966006) - An IDOR that can lead to enumeration of a user and disclosure of email and phone number within cashier
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Severity/bounty:** high / Not stated
- **Scope:** unikrn.com
- **Public summary:** As an attacker, it was possible to exploit IDOR on https://cashier.unikrn.com. Huge thanks to Miquinho for spotting that vulnerability on https://cashier.unikrn.com. It was during the https://cashier.unikrn.com/cashier/transaction-history session handshake where we found out you could actually get access to another customer's data. Miquinho, the initial report was hard for our security team to reproduce, but you really helped to reproduce the issue. Thank you!

### 5. [2122671](https://hackerone.com/reports/2122671) - IDOR - Delete all Licenses and certifications from users account using CreateOrUpdateHackerCertification GraphQL query
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Severity/bounty:** high / Not stated
- **Scope:** hackerone.com
- **Public summary:** No public summary was available.

### 6. [1392630](https://hackerone.com/reports/1392630) - IDOR the ability to view support tickets of any user on seller platform
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Severity/bounty:** medium / $2,500
- **Scope:** *.tiktok.com
- **Public summary:** Due to an Insecure Direct Object Reference (IDOR) vulnerability, an attacker could have potentially viewed support tickets on seller platform. We thank @lewaperbb for reporting this to our team.

### 7. [1969141](https://hackerone.com/reports/1969141) - Insecure Direct Object Reference (IDOR) - Delete Campaigns
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Severity/bounty:** high / Not stated
- **Scope:** hackerone.com
- **Public summary:** No public summary was available.

### 8. [2487889](https://hackerone.com/reports/2487889) - Insecure Direct Object Reference (IDOR) Allows Viewing Private Report Details via /bugs.json Endpoint
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Severity/bounty:** critical / Not stated
- **Scope:** hackerone.com
- **Public summary:** No public summary was available.

### 9. [876300](https://hackerone.com/reports/876300) - Singapore - Account Takeover via IDOR
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Severity/bounty:** critical / Not stated
- **Scope:** card.starbucks.com.sg
- **Public summary:** ko2sec discovered that an alternate site shared database and cookie credentials with card.starbucks.com.sg. By exploiting an endpoint on the alternate site, ko2sec was able to copy a PHPSESSID cookie value from that site over to card.starbucks.com.sg and then see user information, update the password and perform an account takeover. ko2sec was awarded a bounty multiplier for this report as they had also submitted a 2nd report for another site that mimicked this behavior. @ko2sec — thank you for 

### 10. [1527906](https://hackerone.com/reports/1527906) - IDOR on TikTok Ads Endpoint
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Severity/bounty:** medium / Not stated
- **Scope:** ads.tiktok.com
- **Public summary:** An Insecure Direct Object Reference (IDOR) vulnerability was found on a TikTok Ads endpoint, which could have resulted in an unauthorized user adding products into another user's catalogue. We thank @sinayeganeh for reporting this to our team.

## Authentication / Account Takeover

### 1. [2293343](https://hackerone.com/reports/2293343) - Account Takeover via Password Reset without user interactions
- **Weakness:** Improper Access Control - Generic
- **Severity/bounty:** critical / $35,000
- **Scope:** gitlab.com
- **Public summary:** @asterion04 submitted a report to GitLab. Summary I found a way to change the password of a GitLab account via the password reset form and successfully retrieve the final reset link without user interactions, using just its email address. Steps to reproduce Go to "Forgot Your Password?" link Enter the victim's email and intercept the submit request via Burp Suite . Then right-click on the HTTP Editor inside Burp Suite and select Extensions -> Content-Type Converter -> Convert to JSON (make sure 

### 2. [745324](https://hackerone.com/reports/745324) - Account takeover via leaked session cookie
- **Weakness:** Insufficiently Protected Credentials
- **Severity/bounty:** high / $20,000
- **Scope:** hackerone.com
- **Public summary:** # Incident Report \| 2019-11-24 Account Takeover via Disclosed Session Cookie *Last updated: 2019-11-27* ## Issue Summary On November 24, 2019 at 13:08 UTC, HackerOne was notified through the HackerOne Bug Bounty Program by a HackerOne community member (“hacker”) that they had accessed a HackerOne Security Analyst’s HackerOne account. A session cookie was disclosed due to a human error, which led to the hacker being able to access the account. The session cookie was revoked at 15:11 UTC, blocking

### 3. [2443228](https://hackerone.com/reports/2443228) - Account Takeover via Authentication Bypass in TikTok Account Recovery
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Severity/bounty:** critical / $12,000
- **Scope:** *.tiktokv.com
- **Public summary:** An improper authentication mechanism in TikTok's account recovery process could have been used for account takeovers on Android devices. There was no evidence of exploitation and this vulnerability has now been completely fixed. We thank @xtt0k for reporting this to our team and confirming its remediation. I identified a critical vulnerability in one of TikTok's endpoints that permitted unauthorized changes to user accounts due to improper parameter handling. This flaw could have allowed a TikTo

### 4. [976603](https://hackerone.com/reports/976603) - Ability to DOS any organization's SSO and open up the door to account takeovers
- **Weakness:** Improper Authentication - Generic
- **Severity/bounty:** high / $10,500
- **Scope:** www.grammarly.com
- **Public summary:** The vulnerability was fixed before SSO became available to Grammarly customers.

### 5. [173551](https://hackerone.com/reports/173551) - password reset token leaking allowed for ATO of an Uber account
- **Weakness:** Improper Authentication - Generic
- **Severity/bounty:** critical / $10,000
- **Scope:** Not stated
- **Public summary:** With an email address for a valid Uber account, it was possible to take over that account because the reset token was exposed in the response of a password reset HTTP request. This meant an attacker could initiate password reset for an account and immediately receive the reset token for that account. We consider the security of our user's data top priority, so we were very interested in this report. Furthermore, @procode701 was a pleasure to work with and we look forward to more reports in the f

### 6. [136885](https://hackerone.com/reports/136885) - [CRITICAL] -- Complete Account Takeover
- **Weakness:** Improper Authentication - Generic
- **Severity/bounty:** Not stated / $8,000
- **Scope:** Not stated
- **Public summary:** Thanks for another great find @parth!

### 7. [394329](https://hackerone.com/reports/394329) - Account Takeover via billing
- **Weakness:** Improper Authorization
- **Severity/bounty:** critical / $8,000
- **Scope:** chaturbate.com
- **Public summary:** The hacker found that when subscribing to a fanclub the parameters could be manipulated to purchase a fanclub subscription for another user. This will set the email of the target account if they had no email on file. This could then be used to reset the password for the target user. The purchasing logic was fixed to not allow modifying of these parameters. The attack could only target accounts with no email on file, and required a purchase.

### 8. [862589](https://hackerone.com/reports/862589) - Spring Actuator endpoints publicly available, leading to account takeover
- **Weakness:** Misconfiguration
- **Severity/bounty:** critical / $5,000
- **Scope:** *.line.me
- **Public summary:** Due to insufficient access controls, it was possible to access the Spring Boot Actuator endpoints /heapdump and /env. The /heapdump endpoint leaks data from the Java Virtual Machine, leading to disclosure of admin credentials, user tokens and a combination of other data. This endpoint was not discovered by the internal security team due to being put on a custom path, avoiding detection through our usual means. The reporter accessing this endpoint also triggered a warning for our CSIRT team, allo

### 9. [1923672](https://hackerone.com/reports/1923672) - Account takeover due to insufficient URL validation on RelayState parameter
- **Weakness:** Cross-Site Request Forgery (CSRF)
- **Severity/bounty:** medium / $2,450
- **Scope:** gitlab.com
- **Public summary:** No public summary was available.

### 10. [397497](https://hackerone.com/reports/397497) - Stored XSS on auth.uber.com/oauth/v2/authorize via redirect_uri parameter leads to Account Takeover
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Severity/bounty:** medium / $3,000
- **Scope:** Not stated
- **Public summary:** By getting an authenticated victim to visit a malicious link, an attacker can cause that victim to execute arbitrary JavaScript in the context of the login.uber.com or auth.uber.com domains.

## SSRF

### 1. [2262382](https://hackerone.com/reports/2262382) - Server Side Request Forgery (SSRF) via Analytics Reports
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** critical / $25,000
- **Scope:** hackerone.com
- **Public summary:** We recently received a critical server-side request forgery (SSRF) vulnerability report through our bug bounty program. The issue allowed attackers to make internal requests from our application servers by exploiting a lack of output sanitization in an error message. By crafting malicious requests, an attacker could have accessed internal AWS services and obtained temporary credentials. Upon receiving the report, we were able to reproduce and verify the issue. We have implemented a fix that is n

### 2. [398799](https://hackerone.com/reports/398799) - Unauthenticated blind SSRF in OAuth Jira authorization controller
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** high / $4,000
- **Scope:** Not stated
- **Public summary:** No public summary was available.

### 3. [826361](https://hackerone.com/reports/826361) - SSRF on project import via the remote_attachment_url on a Note
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** high / $10,000
- **Scope:** gitlab.com
- **Public summary:** No public summary was available.

### 4. [1960765](https://hackerone.com/reports/1960765) - Blind SSRF to internal services in matrix preview_link API
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** high / $6,000
- **Scope:** *.reddit.com
- **Public summary:** Matrix Chat endpoint at https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=* allowed partially blind SSRF to internal services. The data that could be exfiltrated was limited only to the service names and their IPs before a fix was implemented. This endpoint should not be able to query internal services, but external IPs, domains and services are fine for this to query. Matrix endpoint at https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url= allowed Partially Blind SSRF

### 5. [1409727](https://hackerone.com/reports/1409727) - Full read SSRF via Lark Docs `import as docs` feature
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** critical / $5,000
- **Scope:** larksuite.com
- **Public summary:** A SSRF (server side request forgery) vulnerability was found in the LarkDocs using the "import as docs" feature, which could have potentially been used to access services running on the internal network. We thank @sirleeroyjenkins for reporting this to our team and confirming the resolution.

### 6. [1547877](https://hackerone.com/reports/1547877) - [Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia
- **Weakness:** Unrestricted Upload of File with Dangerous Type
- **Severity/bounty:** critical / $5,000
- **Scope:** Aiven for Apache Kafka managed and hosted service 
- **Public summary:** No public summary was available.

### 7. [776017](https://hackerone.com/reports/776017) - Half-Blind SSRF found in kube/cloud-controller-manager can be upgraded to complete SSRF (fully crafted HTTP requests) in vendor managed k8s service.
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** high / $5,000
- **Scope:** https://github.com/kubernetes/kube-controller-manager
- **Public summary:** No public summary was available.

### 8. [374737](https://hackerone.com/reports/374737) - Blind SSRF on errors.hackerone.net due to Sentry misconfiguration
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** low / $3,500
- **Scope:** errors.hackerone.net
- **Public summary:** No public summary was available.

### 9. [2429894](https://hackerone.com/reports/2429894) - Libuv: Improper Domain Lookup that potentially leads to SSRF attacks
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** high / $4,860
- **Scope:** https://github.com/libuv/libuv
- **Public summary:** Improper Domain Lookup that potentially leads to SSRF attacks Summary The uv_getaddrinfo function in src/unix/getaddrinfo.c (and its windows counterpart src/win/getaddrinfo.c), truncates hostnames to 256 characters before calling getaddrinfo. This behavior can be exploited to create addresses like 0x00007f000001, which are considered valid by getaddrinfo and could allow an attacker to craft payloads that resolve to unintended IP addresses, bypassing developer checks. Full GHSA: https://github.co

### 10. [746024](https://hackerone.com/reports/746024) - SSRF on music.line.me through getXML.php
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** high / $4,500
- **Scope:** music.line.me
- **Public summary:** The reporter found an endpoint through which limited SSRF could be achieved. It was only possible to issue GET requests served over HTTPS. LFI was not possible. The maximum impact found for this issue was minor service disruption and/or limited information leakage.

## Command Injection / RCE

### 1. [1609965](https://hackerone.com/reports/1609965) - RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag)
- **Weakness:** Command Injection - Generic
- **Severity/bounty:** critical / $33,510
- **Scope:** Your Own GitLab Instance
- **Public summary:** No public summary was available.

### 2. [925585](https://hackerone.com/reports/925585) - RCE via npm misconfig -- installing internal libraries from the public registry
- **Weakness:** Code Injection
- **Severity/bounty:** critical / $30,000
- **Scope:** *.paypal.com
- **Public summary:** A Bug Bounty researcher identified an issue where certain development projects defaulted to the public NPM registry, instead of using the intended internal packages. Since the packages on the public registry did not exist, the researcher created these and observed they were downloaded. Had these packages been registered with malicious intent, it is possible for internal development to have included this code. While there are additional checks and controls in the development pipeline, this could 

### 3. [591295](https://hackerone.com/reports/591295) - Potential pre-auth RCE on Twitter VPN
- **Weakness:** OS Command Injection
- **Severity/bounty:** critical / $20,160
- **Scope:** *.twitter.com
- **Public summary:** Thanks Twitter Security Team again :) The details can be found here! * [Attacking SSL VPN - Part 3: The Golden Pulse Secure SSL VPN RCE Chain, with Twitter as Case Study!](https://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html)

### 4. [1154542](https://hackerone.com/reports/1154542) - RCE when removing metadata with ExifTool
- **Weakness:** Code Injection
- **Severity/bounty:** critical / $20,000
- **Scope:** gitlab.com
- **Public summary:** No public summary was available.

### 5. [1125425](https://hackerone.com/reports/1125425) - RCE via unsafe inline Kramdown options when rendering certain Wiki pages
- **Weakness:** Code Injection
- **Severity/bounty:** critical / $20,000
- **Scope:** Your Own GitLab Instance
- **Public summary:** No public summary was available.

### 6. [181879](https://hackerone.com/reports/181879) - Struct type confusion RCE
- **Weakness:** Code Injection
- **Severity/bounty:** critical / $18,000
- **Scope:** Not stated
- **Public summary:** No public summary was available.

### 7. [658013](https://hackerone.com/reports/658013) - Git flag injection - local file overwrite to remote code execution
- **Weakness:** Command Injection - Generic
- **Severity/bounty:** critical / $12,000
- **Scope:** gitlab.com
- **Public summary:** No public summary was available.

### 8. [3782701](https://hackerone.com/reports/3782701) - Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)
- **Weakness:** Code Injection
- **Severity/bounty:** critical / $12,000
- **Scope:** firefox-ci-tc.services.mozilla.com
- **Public summary:** No public summary was available.

### 9. [733072](https://hackerone.com/reports/733072) - Path traversal, to RCE
- **Weakness:** Command Injection - Generic
- **Severity/bounty:** high / $12,000
- **Scope:** Your Own GitLab Instance
- **Public summary:** No public summary was available.

### 10. [125980](https://hackerone.com/reports/125980) - uber.com may RCE by Flask Jinja2 Template Injection
- **Weakness:** Code Injection
- **Severity/bounty:** Not stated / $10,000
- **Scope:** Not stated
- **Public summary:** No public summary was available.

## Business Logic / Race Conditions

### 1. [689314](https://hackerone.com/reports/689314) - Project Template functionality can be used to copy private project data, such as repository, confidential issues, snippets, and merge requests
- **Weakness:** Privilege Escalation
- **Severity/bounty:** critical / $12,000
- **Scope:** gitlab.com
- **Public summary:** No public summary was available.

### 2. [1478633](https://hackerone.com/reports/1478633) - HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function
- **Weakness:** HTTP Request Smuggling
- **Severity/bounty:** critical / $6,000
- **Scope:** Not stated
- **Public summary:** The Edge Rules engine used by Cloudflare Transform Rules features string modifying functions like lower() and concat(), which accepted hexadecimal-encoded characters such as ”\x0a\x0d“. This allowed for manipulation of request headers (e.g. injecting an additional header) and, as a consequence, made HTTP smuggling attack (TE.CL) possible. This vulnerability enabled an attacker to bypass security products such as Cloudflare Access and view the content of internal origin servers. This bug in hexad

### 3. [1628209](https://hackerone.com/reports/1628209) - SSRF in Functional Administrative Support Tool pdf generator (████) [HtUS]
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** critical / $4,000
- **Scope:** Not stated
- **Public summary:** No public summary was available.

### 4. [1520931](https://hackerone.com/reports/1520931) - Time-of-check to time-of-use vulnerability in the std::fs::remove_dir_all() function of the Rust standard library
- **Weakness:** Time-of-check Time-of-use (TOCTOU) Race Condition
- **Severity/bounty:** high / $4,000
- **Scope:** https://github.com/rust-lang/rust
- **Public summary:** Race condition in std::fs::remove_dir_all Description This is a cross-post of the official security advisory. The official advisory contains a signed version with our PGP key, as well. The Rust Security Response WG was notified that the std::fs::remove_dir_all standard library function is vulnerable a race condition enabling symlink following (CWE-363). An attacker could use this security issue to trick a privileged program into deleting files and directories the attacker couldn't otherwise acce

### 5. [1330529](https://hackerone.com/reports/1330529) - Claiming the listing of a non-delivery restaurant through OTP manipulation
- **Weakness:** Improper Authorization
- **Severity/bounty:** critical / $3,250
- **Scope:** *.zomato.com
- **Public summary:** Thanks to @ashoka_rao for reporting this issue. The Researcher demonstrated a way to takeover an unclaimed non-delivery restaurant on our platform.

### 6. [484745](https://hackerone.com/reports/484745) - GoldSrc: Buffer Overflow in DELTA_ParseDelta function leads to RCE
- **Weakness:** Stack Overflow
- **Severity/bounty:** critical / $3,000
- **Scope:** hl.exe
- **Public summary:** ## Description The bug is triggered by 2 packets. First one is `svc_deltadescription` which describes memory layout of such structures as `event_t`, `weapon_data_t`, ... It is sent as a list of fields' descriptions: type, offset and others. Next, `DELTA_ParseDelta` fills these structures when corresponding delta packets are received. The problem is that this function doesn't check if `field_offset + field_size` doesn't exceed bounds of allocated memory for these structures which can lead to buff

### 7. [2301565](https://hackerone.com/reports/2301565) - Server Side Request Forgery (SSRF) in webhook functionality
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Severity/bounty:** medium / $2,500
- **Scope:** hackerone.com
- **Public summary:** No public summary was available.

### 8. [364843](https://hackerone.com/reports/364843) - OLO Total price manipulation using negative quantities
- **Weakness:** Business Logic Errors
- **Severity/bounty:** critical / Not stated
- **Scope:** orders.upserve.com
- **Public summary:** The total amount of an order could be modified by including an item with a negative quantity.

### 9. [3255473](https://hackerone.com/reports/3255473) - Business Logic Error – Bypass of OTP Verification During Signup on hover.com
- **Weakness:** Business Logic Errors
- **Severity/bounty:** none / Not stated
- **Scope:** Not stated
- **Public summary:** No public summary was available.

### 10. [429026](https://hackerone.com/reports/429026) - Race condition in performing retest allows duplicated payments
- **Weakness:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Severity/bounty:** medium / Not stated
- **Scope:** hackerone.com
- **Public summary:** No public summary was available.

