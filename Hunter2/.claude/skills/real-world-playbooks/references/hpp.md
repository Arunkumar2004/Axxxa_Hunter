# Real-World Playbook — HTTP Parameter Pollution + postMessage

**Class:** `hpp` · **Coverage-matrix tier:** 1 · **Hunter2:** /hpp · tools/hpp_postmessage_scanner.py · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
/app?debug=false&debug=true
/transfer?amount=1&amount=5000
```
```
    param=value1&param=value2
```
```
    param[]=value1
    param[]=value1&param[]=value2
    param[]=value1&param=value2
    param=value1&param[]=value2
```
```
    param=value1%26other=value2
```
```
    param[key1]=value1&param[key2]=value2
```
```
    {
        "test": "user",
        "test": "admin"
    }
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### HTTP Parameter Pollution

|ID          |
|------------|
|WSTG-INJT-04|

#### Summary

HTTP Parameter Pollution tests the applications response to receiving multiple HTTP parameters with the same name; for example, if the parameter `username` is included in the GET or POST parameters twice.

Supplying multiple HTTP parameters with the same name may cause an application to interpret values in unanticipated ways. By exploiting these effects, an attacker may be able to bypass input validation, trigger application errors or modify internal variables values. As HTTP Parameter Pollution (in short *HPP*) affects a building block of all web technologies, server and client-side attacks exist.

Current HTTP standards do not include guidance on how to interpret multiple input parameters with the same name. For instance, [RFC 3986](https://www.ietf.org/rfc/rfc3986.txt) simply defines the term *Query String* as a series of field-value pairs and [RFC 2396](https://www.ietf.org/rfc/rfc2396.txt) defines classes of reversed and unreserved query string characters. Without a standard in place, web application components handle this edge case in a variety of ways (see the table below for details).

By itself, this is not necessarily an indication of vulnerability. However, if the developer is not aware of the problem, the presence of duplicated parameters may produce an anomalous behavior in the application that can be potentially exploited by an attacker. As often in security, unexpected behaviors are a usual source of weaknesses that could lead to HTTP Parameter Pollution attacks in this case. To better introduce this class of vulnerabilities and the outcome of HPP attacks, it is interesting to analyze some real-life examples that have been discovered in the past.

##### Input Validation and Filters Bypass

In 2009, immediately after the publication of the first research on HTTP Parameter Pollution, the technique received attention from the security community as a possible way to bypass web application firewalls.

One of these flaws, affecting *ModSecurity SQL Injection Core Rules*, represents a perfect example of the impedance mismatch between applications and filters. The ModSecurity filter would correctly apply a deny list for the following string: `select 1,2,3 from table`, thus blocking this example URL from being processed by the web server: `/index.aspx?page=select 1,2,3 from table`. However, by exploiting the concatenation of multiple HTTP parameters, an attacker could cause the application server to concatenate the string after the ModSecurity filter already accepted the input. As an example, the URL `/index.aspx?page=select 1&page=2,3` from table would not trigger the ModSecurity filter, yet the application layer would concatenate the input back into the full malicious string.

Another HPP vulnerability turned out to affect *Apple Cups*, the well-known printing system used by many Unix systems. Exploiting HPP, an attacker could easily trigger a Cross-Site Scripting vulnerability using the following URL: `https://127.0.0.1:631/admin/?kerberos=onmouseover=alert(1)&kerberos`. The application validation checkpoint could be bypassed by adding an extra `kerberos` argument having a valid string (e.g. empty string). As the validation checkpoint would only consider the second occurrence, the first `kerberos` parameter was not properly sanitized before being used to generate dynamic HTML content. Successful exploitation would result in JavaScript code execution under the context of the hosting site.

##### Authentication Bypass

An even more critical HPP vulnerability was discovered in *Blogger*, the popular blogging platform. The bug allowed malicious users to take ownership of the victim’s blog by using the following HTTP request (`https://www.blogger.com/add-authors.do`):

```html
POST /add-authors.do HTTP/1.1
[...]

security_token=attackertoken&blogID=attackerblogidvalue&blogID=victimblogidvalue&authorsList=goldshlager19test%40gmail.com(attacker email)&ok=Invite
```

The flaw resided in the authentication mechanism used by the web application, as the security check was performed on the first `blogID` parameter, whereas the actual operation used the second occurrence.

##### Expected Behavior by Application Server

How duplicate parameters are handled depends on the framework, server, and how the application reads the value (for example, first value, last value, or the full collection). Treat any table of defaults as a starting point only: verify the actual behavior of the target stack, including reverse proxies, web application firewalls (WAFs), and API gateways that may normalize query strings differently.

Given the URL and query string: `https://example.com/?color=red&color=blue`

| Typical Stack | Common Default Parsing | Example |
|---------------|------------------------|---------|
| ASP.NET / IIS | All occurrences concatenated with a comma | `color=red,blue` |
| ASP.NET Core / Kestrel | All occurrences available (`StringValues`; comma-joined when stringified) | `color=red,blue` |
| PHP (Apache / php-fpm / Nginx) | Last occurrence only | `color=blue` |
| Java Servlet (Tomcat, Jetty, and similar) | First occurrence only | `color=red` |
| Node.js / Express | First occurrence only | `color=red` |
| Python (Django, Flask, and similar) | All occurrences in a list / MultiDict | `color=['red','blue']` |

Behaviors for other servers and older platforms vary; always confirm on the system under test. Historical research on this topic includes AppSec EU 2009 (Carettoni & di Paola).

#### Test Objectives

- Identify the back end and the parsing method used.
- Assess injection points and try bypassing input filters using HPP.

#### How to Test

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Parameter Pollution | JSON Injection




#### HTTP Parameter Pollution (HPP) Overview

HTTP Parameter Pollution (HPP) is a technique where attackers manipulate HTTP parameters to change the behavior of a web application in unintended ways. This manipulation is done by adding, modifying, or duplicating HTTP parameters. The effect of these manipulations is not directly visible to the user but can significantly alter the application's functionality on the server side, with observable impacts on the client side.

##### Example of HTTP Parameter Pollution (HPP)

A banking application transaction URL:

- **Original URL:** `https://www.victim.com/send/?from=accountA&to=accountB&amount=10000`

By inserting an additional `from` parameter:

- **Manipulated URL:** `https://www.victim.com/send/?from=accountA&to=accountB&amount=10000&from=accountC`

The transaction may be incorrectly charged to `accountC` instead of `accountA`, showcasing the potential of HPP to manipulate transactions or other functionalities such as password resets, 2FA settings, or API key requests.

###### **Technology-Specific Parameter Parsing**

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Param pollution → bypass WAF/validation, alter server parsing
- postMessage listener without origin check → DOM XSS / data theft

## Hunter2 wiring
- **Run:** `/hpp · tools/hpp_postmessage_scanner.py`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
