# Real-World Playbook — Business Logic Abuse

**Class:** `business-logic` · **Coverage-matrix tier:** 0 · **Hunter2:** business-logic-hunter agent · tools/h1_race.py · **Skill:** race-conditions
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed Business Logic Abuse reports peak at **$12,000**. Rewarded across: Cloudflare Public Bug Bounty, Eternal, GitHub Security Lab, GitLab, HackerOne, Internet Bug Bounty, Lob, New Relic.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Project Template functionality can be used to copy private project data, such as repository, confidential issues, snippets, and merge requests** — GitLab, $12,000 · 457👍 · [689314](https://hackerone.com/reports/689314)
- **HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function** — Cloudflare Public Bug Bounty, $6,000 · 116👍 · [1478633](https://hackerone.com/reports/1478633)
- **SSRF in Functional Administrative Support Tool pdf generator (████) [HtUS]** — U.S. Dept Of Defense, $4,000 · 46👍 · [1628209](https://hackerone.com/reports/1628209)
- **Time-of-check to time-of-use vulnerability in the std::fs::remove_dir_all() function of the Rust standard library** — Internet Bug Bounty, $4,000 · 9👍 · [1520931](https://hackerone.com/reports/1520931)
- **Claiming the listing of a non-delivery restaurant through OTP manipulation** — Eternal, $3,250 · 108👍 · [1330529](https://hackerone.com/reports/1330529)
- **GoldSrc: Buffer Overflow in DELTA_ParseDelta function leads to RCE** — Valve, $3,000 · 26👍 · [484745](https://hackerone.com/reports/484745)
- **Server Side Request Forgery (SSRF) in webhook functionality** — HackerOne, $2,500 · 137👍 · [2301565](https://hackerone.com/reports/2301565)
- **Account Takeover via Email ID Change and Forgot Password Functionality** — New Relic, $2,048 · 214👍 · [1089467](https://hackerone.com/reports/1089467)
- **ihsinme: CPP Add query for CWE-783 Operator Precedence Logic Error When Use Bool Type** — GitHub Security Lab, $1,800 · 5👍 · [1241578](https://hackerone.com/reports/1241578)
- **ihsinme: CPP Add query for CWE-401 memory leak on unsuccessful call to realloc function** — GitHub Security Lab, $1,800 · 2👍 · [1093242](https://hackerone.com/reports/1093242)
- **Null pointer dereference in SMTP server function smtp_string_parse** — Open-Xchange, $1,500 · 105👍 · [827729](https://hackerone.com/reports/827729)
- **Old WebKit HTML agent in Template Preview function has multiple known vulnerabilities leading to RCE** — Lob, $1,500 · 68👍 · [520717](https://hackerone.com/reports/520717)
- **[stored xss, pornhub.com] stream post function** — Pornhub, $1,500 · 35👍 · [138075](https://hackerone.com/reports/138075)
- **Exploitable live argument in onClick Function leads to Data Leakage of Inactive/Suspended Products** — TikTok, $1,000 · 128👍 · [2295958](https://hackerone.com/reports/2295958)
- **Authorization Token on PlayStation Network Leaks via postMessage function** — PlayStation, $1,000 · 74👍 · [826394](https://hackerone.com/reports/826394)
- **Unrestricted access to quiesce functionality in dss.api.playstation.com REST API leads to unavailability of application** — PlayStation, $1,000 · 49👍 · [993722](https://hackerone.com/reports/993722)
- **SSRF in VCARD photo upload functionality** — Open-Xchange, $850 · 49👍 · [296045](https://hackerone.com/reports/296045)
- **[CVE-2020-27194] Linux kernel: eBPF verifier bug in `or` binary operation tracking function leads to LPE** — Internet Bug Bounty, $750 · 11👍 · [1010340](https://hackerone.com/reports/1010340)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

1. change the price with other price :100->50
2. change the price with nagative price :100->-100
3. change the price with other price by add nagative value: 100 ->(+-120)
4. change the price with other price by mult by 0.5: 100->(0.5*100)
5. Retrieving a Profile
```
For example, Jack’s profile can be fetched with id=1001 and if this value  
changed to 1089 we get another user’s information. A scanner may go on and  
change the value from 1001 to **‘1001** to find SQL injection, but not to 1089 and  
would miss deducing that the application is vulnerable to authorization bypass. By changing the “id” from 1001 to 1089, a pen tester can see that John’s profile , rather than Jack’s, is being displayed.
```

6. Shopping Cart
```
Let us consider an online store application where customers add items to their shopping cart. The application sends the customers to a secure payment gateway where they submit their order. To complete the order, customers are required to make a credit card payment. In this shopping cart application, business logic errors  
may make it possible for attackers to bypass the authentication processes to  
directly log into the shopping cart application and avoid paying for “purchased” items.
```

7. **Review Functionality**
   - Some applications have an option where verified reviews are marked with some tick or it's mentioned. Try to see if you can post a review as a Verified Reviewer without purchasing that product.
   - Some app provides you with an option to provide a rating on a scale of 1 to 5, try to go beyond/below the scale-like provide 0 or 6 or -ve.
   - Try to see if the same user can post multiple ratings for a product. This is an interesting endpoint to check for Race Conditions.
   - Try to see if the file upload field is allowing any exts, it's often observed that the devs miss out on implementing protections on such endpoints. 
   - Try to post reviews like some other users.
   - Try performing CSRF on this functionality, often is not protected by tokens

8. **Coupon Code Functionality**
   - Apply the same code more than once to see if the coupon code is reusable. 
   - If the coupon code is uniquely usable, try testing for Race Condition on this function by using the same code for two accounts at a parallel time.
   - Try Mass Assignment or HTTP Parameter Pollution to see if you can add multiple coupon codes while the application only accepts one code from the Client Side. 
   - Try performing attacks that are caused by missing input sanitization such as XSS, SQLi, etc. on this field
   - Try adding discount codes on the products which are not covered under discounted items by tampering with the request on the server-side. 

9. **Delivery Charges Abuse **
   - Try tampering with the delivery charge rates to -ve values to see if the final amount can be reduced.
   - Try checking for the free delivery by tampering with the params.

10. **Currency Arbitrage **
   - Pay in 1 currency say USD and try to get a refund in EUR. Due to the diff in conversion rates, it might be possible to gain more amount.
  
11. **Premium Feature Abuse **
   - Try forcefully browsing the areas or some particular endpoints which come under premium accounts.
   - Pay for a premium feature and cancel your subscription. If you get a refund but the feature is still usable, it's a monetary impact issue.
   - Some applications use true-false request/response values to validate if a user is having access to premium features or not.
   - Try using Burp's Match & Replace to see if you can replace these values whenever you browse the app & access the premium features.
   - Always check cookies or local storage to see if any variable is checking if the user should have access to premium features or not.

12. **Refund Feature Abuse**
   - Purchase a product (usually some subscription) and ask for a refund to see if the feature is still accessible.
   - Try for currency arbitrage explained yesterday.
   - Try making multiple requests for subscription cancellation (race conditions) to see if you can get multiple refunds.

13. **Cart/Wishlist Abuse **
   - Add a product in negative quantity with other products in positive quantity to balance the amount.
   - Add a product in more than the available quantity.
   - Try to see when you add a product to your wishlist and move it to a cart if it is possible to move it to some other user's cart or delete it from there.

14. **Thread Comment Functionality**
   - Unlimited Comments on a thread
   - Suppose a user can comment only once, try race conditions here to see if multiple comments are possible.
   - Suppose there is an option: comment by the verified user (or some privileged user) try to tamper with various parameters in order to see if you can do this activity.
   - Try posting comments impersonating some other users.

15. **Parameter Tampering **
   - Tamper Payment or Critical Fields to manipulate their values
   - Add multiple fields or unexpected fields by abusing HTTP Parameter Pollution & Mass Assignment
   - Response Manipulation to bypass certain restrictions such as 2FA Bypass 

16. **Parameter tampering can result in product price manipulation**
   - https://www.youtube.com/watch?v=3VMlV7j_yzg

17. **Manipulation of exam results at Semrush.Academy**
  - In this situation, it was possible to bypass the exam process. That is to replace the results of the exam with the correct ones and send a request to get the certificate right away. And to replace the results with the correct ones turned out, because the body of the request was json, where 1 = true, and empty = false.

Steps To Reproduce:

1.  Finished exams with any answers
2.  Retake exam
3.  Send the last request of our answer

Example body: `{"answers":{"503":"","504":"","505":"1","506":"","507":"","591":"1","592":"","593":"","594":"","595":"","596":"","1340":"1","1341":"","1342":"","1343":"","1344":"","1345":"","1351":"1","1352":"","1353":"","1354":"","1355":"","1356":"","1357":"","1358":"1","1359":"","1360":"","1361":"","1362":"","1363":"","1365":"1"}}


18. **Authentication flags and privilege escalations at application layer.**
Applications have their own access control lists (ACLs) and privileges. The most critical aspect of the application related to security is authentication. An authenticated user has access to  
the internal pages and structures that  reside behind the login section. These privileges can be maintained by the database, LDAP, file etc. If the implementation of authorization is weak, it  
opens up possible vulnerabilities. If  these vulnerabilities are identified  
during a test, then there is the potential for exploitation. This exploitation  would likely include accessing another user’s content or becoming a higher-level user with greater permissions  to do greater damage
***How to test for this business logic flaw:***
```
• During the profiling phase or through a proxy observe the HTTP traffic, both request and response blocks.  
• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both the name of  
the parameter and the value need to be analyzed.  
• If the parameter name is suspicions and suggests that it has something to do with ACL/Permission then that becomes a  
target.  
• Once the target is identified, the next step is evaluating the value, it can be encoded in hex, binary, string, etc.. The tester  
should do some tampering and try to define its behavior with bit of fuzzing.  
• In this case, fuzzing may need a logical approach, changing bit patterns or permission flags like 1 to 0 or Y to N and so  
on. Some combination of bruteforcing, logical deduction and artistic tampering will help to decipher the logic. If this is  
successful then we get a point for exploitation and end up escalating privileges or bypassing authorization.
```


19. **Critical Parameter  Manipulation and Access  to Unauthorized  Information/Content.**
HTTP GET and POST requests are typically accompanied with several parameters when submitted to the application. These parameters can be in the form of name/value pairs, JSON, XML etc. Interestingly, these parameters can be tampered with and guessed (predicted) as well. If the business logic of the application is processing these parameters before validating them, it can lead to information/content disclosure. This is another common business  logic flaw that is easy to exploit
***How to test for this business logic flaw:***
```
• During the profiling phase or through a proxy, observe HTTP traffic, both request and response blocks.  
• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both the name of  
the parameter and the value need to be analyzed.  
• Observe the values in the traffic and look for incrementing numbers and easily guessable values across all parameters.  
• This parameter’s value can be changed and one may gain unauthorized access.  
In the above case we were able to access other users profiles
```


20. **Developer’s cookie tampering and business process/logic bypass.**
Cookies are an essential component to maintain state over HTTP. In many cases, developers are not using session cookies only, but instead are building data internally using session only variables. Application developers set new cookies on the browser at important junctures which exposes logical holes. After authentication logic sets several parameters based  
on credentials, developers have two options to maintain these credentials  across applications. The developer can set the parameters in session variables or set cookies in the browser  
with appropriate values. If application developers are passing cookies, then  
they might be reverse engineered or have values that can be guessed/ deciphered. It can create a possible logical hole or bypass. If an attacker can identify this hole then they can exploit it with ease
***How to test for this business logic flaw:***
```
• During the profiling phase or through a proxy observe the HTTP traffic, both request and responseblocks.  
• Analyze all cookies delivered during the profiling, some of these cookies will be defined by developers and are not  
session cookies defined by the web application server.  
• Observe cookie values in specific, look for incrementing easily guessable values across all cookies.  
• Cookie value can be changed and one may gain unauthorized access or logical escalation
```



21. ** LDAP Parameter Identification and Critical Infrastructure Access**
LDAP is becoming an important aspect for large applications and it may get integrated with ”single sign on” as  well. Many infrastructure layer tools like Site Minder or Load Balancer use  LDAP for both authentication and  authorization. LDAP parameters can  carry business logic decision flags and those can be abused and leveraged. LDAP filtering being done at the business application layer enable logical injections to be possible on those parameters. If the application is  
not doing enough validation then LDAP injection and business layer bypasses are possible.

***How to test for this business logic flaw:***
```
• During the profiling phase or through a proxy observe the HTTP traffic, both request and response blocks.  
• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both the name of  
the parameter and the value need to be analyzed.  
• Analyze parameters and their values, look for ON,CN,DN etc. Usually these parameters are linked with LDAP. Also look  
for the parameter taking email or usernames, these parameters can be prospective targets.  
• These target parameters can be manipulated and injected with “*” or any other LDAP specific filters like OR, AND etc. It  
can lead to logical bypass over LDAP and end up escalating access rights.
```


22. **Business Constraint Exploitation**
The application’s business logic should have defined rules and constraints that are very critical for an application. If these constraints are bypassed by an attacker, then it can be exploited. User  
fields that have poor design or implementation are often controlled by these business constraints. If business logic is processing variables controlled as hidden values then it leads to easy discovery and exploitation. While crawling and profiling the application, one can list all these possible different values and their injection places. It is easy to browse through these hidden fields and understand their context; if context is leveraged to control the business rules then manipulation of  this information can lead to critical business logic vulnerabilities.
***How to test for this business logic flaw:***
```
• During the profiling phase or through a proxy observe the HTTP traffic, both the request and response blocks.  
• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both the name of  
the parameter and the value need to be analyzed.  
• Analyze hidden parameters and their values, look for business specific calls like transfer money, max limit etc. All these parameters which are dictating a business constraint can become a target.  
• These target parameters can be manipulated and values can be changed. It is possible to avoid the business constraint and inject an unauthorized transaction.
```


23. **Business Flow Bypass**
Applications include flows that are controlled by redirects and page transfers. After a successful login, for example, the application will transfer the user to the money transfer page.During these transfers, the user’s session is maintained by a session cookie or other mechanism. In many cases,  
this flow can be bypassed which can lead to an error condition or information leakage. This leakage can help an attacker identify critical back-end information. If this flow is controlling  
and giving critical information out then it can be exploited in various use cases and scenarios
***How to test for this business logic flaw:***
```
• During the profiling phase or through a proxy observe the HTTP traffic, both request and response blocks.  
• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both the name of the parameter and the value need to be analyzed.  
• Identify business functionalities which are in specific steps (e.g. a shopping cart or wire transfer).  
• Analyze all steps carefully and look for possible parameters which are added by the application either using hidden values or through JavaScript.  
• These parameters can be tampered through a proxy while making the transaction. This disrupts the flow and can end up  bypassing some business constraints.
```


24. ** Identity or Profile Extraction**
A user’s identity is one of the most critical parameters in authenticated applications. The identities of users  are maintained using session or other forms of tokens. Poorly designed and  
developed applications allow an attacker to identify these token parameters from the client side and in some cases they are not closely maintained on the server side of the session as well. This scenario opens  up a potential opportunity for abuse and system wide exploitation. The  
token is either using only a sequential number or a guessable username
***How to test for this business logic flaw:***
```
• During the profiling phase or through particular proxy observe HTTP traffic, both request and response blocks.  
• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both name of  parameter and value need to be analyzed.  
• Look for parameters which are controlling profiles.  
• Once these target parameters are identified, one can decipher, guess or reverse engineer tokens. If tokens are guessed  and reproduced – game over!
```


25. **File or Unauthorized URL Access and Business  Information Extraction  Identity**
Business applications contain critical information in their features, in the files that are exported and in the export functionality itself. A user can export their data in a selected file format (PDF, XLS or CSV) and download it. If this functionality is not carefully implemented, it can enable asset leakage. An attacker can extract  this information from the application layer. This is one of the most common mistakes and easy to exploit as well. These files can be fetched directly  
from URLs or by using some internal  parameters.
***How to test for this business logic flaw:***
```
• During the profiling phase or through a particular proxy, observe the HTTP traffic, both request and response blocks.  
• POST/GET requests would have typical parameters either in a name-value pair, JSON, XML or Cookie. Both the name of parameter and value need to be analyzed.  
• Identify file call functionalities based on parameter names like file, doc, dir etc. These parameters will point you to possible unauthorized file access vulnerabilities.  
• Once a target parameter has been identified start doing basic brute force or guess work to fetch another user’s files  from server.
```

26. null pyloads
27. in change password try to delete current password

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Introduction to Business Logic

Identifying business logic flaws in a multi-functional dynamic web application requires thinking in unconventional methods. If an application's authentication mechanism is developed with the intention of performing steps 1, 2, 3 in that specific order to authenticate a user. What happens if the user goes from step 1 straight to step 3? In this simplistic example, does the application provide access by failing open; deny access, or just error out with a 500 message?

There are many examples that can be made, but the one constant lesson is "think outside of conventional wisdom". This type of vulnerability cannot be detected by a vulnerability scanner and relies upon the skills and creativity of the penetration tester. In addition, this type of vulnerability is usually one of the hardest to detect, and usually application specific but, at the same time, usually one of the most detrimental to the application, if exploited.

The classification of business logic flaws has been under-studied; although exploitation of business flaws frequently happens in real-world systems, and many applied vulnerability researchers investigate them. The greatest focus is in web applications. There is debate within the community about whether these problems represent particularly new concepts, or if they are variations of well-known principles.

Testing of business logic flaws is similar to the test types used by functional testers that focus on logical or finite state testing. These types of tests require that security professionals think a bit differently, develop abuse and misuse cases and use many of the testing techniques embraced by functional testers. Automation of business logic abuse cases is not possible and remains a manual art relying on the skills of the tester and their knowledge of the complete business process and its rules.

#### Business Limits and Restrictions

Consider the rules for the business function being provided by the application. Are there any limits or restrictions on people's behavior? Then consider whether the application enforces those rules. It's generally pretty easy to identify the test and analysis cases to verify the application if you're familiar with the business. If you are a third-party tester, then you're going to have to use your common sense or ask the business if different operations should be allowed by the application.

Sometimes, in very complex applications, the tester will not have a full understanding of every aspect of the application initially. In these situations, it is best to have the client walk the tester through the application, so that they may gain a better understanding of the limits and intended functionality of the application before the actual test begins. Additionally, having a direct line to the developers (if possible) during testing will help out greatly, if any questions arise regarding the application's functionality.

#### Challenges of Logic Testing

Automated tools find it hard to understand context, hence it's up to a person to perform these kinds of tests. The following two examples will illustrate how understanding the functionality of the application, the developer's intentions, and some creative "out-of-the-box" thinking can break the application's logic. The first example starts with a simplistic parameter manipulation, whereas the second is a real world example of a multi-step process leading to completely subverting the application.

**Example 1**:

Suppose an e-commerce site allows users to select items to purchase, view a summary page and then tender the sale. What if an attacker was able to go back to the summary page, maintaining their same valid session and inject a lower cost for an item and complete the transaction, and then check out?

**Example 2**:

Holding/locking resources and keeping others from purchasing these items online may result in attackers purchasing items at a lower price. The countermeasure to this problem is to implement timeouts and mechanisms to ensure that only the correct price can be charged.

**Example 3**:

What if a user was able to start a transaction linked to their club/loyalty account and then after points have been added to their account cancel out of the transaction? Will the points/credits still be applied to their account?

#### Tools

While there are tools for testing and verifying that business processes are functioning correctly in valid situations these tools are incapable of detecting logical vulnerabilities. For example, tools have no means of detecting if a user is able to circumvent the business process flow through editing parameters, predicting resource names or escalating privileges to access restricted resources nor do they have any mechanism to help the human testers to suspect this state of affairs.

The following are some common tool types that can be useful in identifying business logic issues.

When installing addons you should always be diligent in considering the permissions they request and your browser usage habits.

##### Intercepting Proxy

To Observe the Request and Response Blocks of HTTP Traffic

- [Zed Attack Proxy (ZAP)](https://www.zaproxy.org)
- [Burp Proxy](https://portswigger.net/burp)

##### Browser Developer Tools

To View and Modify HTTP/HTTPS Headers, Post Parameters, and Observe the DOM of the Browser

- Built-in browser developer tools (Network, Application/Storage, and Elements panels)

#### Miscellaneous Test Tools

- [Web Developer toolbar](https://chrome.google.com/webstore/detail/bfbameneiokkgbdmiekhjnmfkcnldhhm)
    - The Web Developer extension adds a toolbar button to the browser with various web developer tools. This is the official port of the Web Developer extension for Firefox.
- [HTTP Request Maker for Chrome](https://chrome.google.com/webstore/detail/kajfghlhfkcocafkcjlajldicbikpgnp)
- [HTTP Request Maker for Firefox](https://addons.mozilla.org/en-US/firefox/addon/http-request-maker)
    - Request Maker is a tool for penetration testing. With it you can easily capture requests made by web pages, tamper with the URL, headers and POST data and, of course, make new requests

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Price/quantity/currency tamper → buy for free / negative totals
- Coupon/referral/cashback stacking → infinite credit
- Workflow/state-machine skip → reach a step without paying/authorizing
- Quota/limit bypass via race (see race-condition playbook)

## Hunter2 wiring
- **Run:** `business-logic-hunter agent · tools/h1_race.py`
- **Skill:** `race-conditions`
- **Coverage-matrix tier:** 0 (Tier 0 = test first)
