# Real-World Playbook — Admin Panel Exposure

**Class:** `admin-panel` · **Coverage-matrix tier:** 1 · **Hunter2:** recon · /bypass-403 · /param-discover · **Skill:** web2-recon
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

[ ] defualt credentials
[defualt credentials](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force#default-credentials)
```
admin:admin
admin:password
author:author
administrator:password
admin123:password
username:pass12345
and many of defualt credentials
```

[ ] Bypass by SQL Injection
```
inject username or paswword with a lot of payloads:
=> error based
=> time  based
```

[ ] By Cross Site Scripting(XSS)
```
inject username or password with xss payloads:
=> url encode
=> base64 encode 
```

[ ] By Manipulating the Response
```
change the status of response from 
200 => 302
failed => success
error => success
403 => 200
403 => 302
false => true
```

[ ] Bypass by Brute Force Attack
```
https://medium.com/@uttamgupta_/1-how-to-perform-login-brute-force-using-burp-suite-9d06b67fb53d
https://medium.com/@uttamgupta_/broken-brute-force-protection-ip-block-aae835895a74
```

[ ] Bypass by Directory Fuzzing Attack
```
use this list to fuzz
https://github.com/six2dez/OneListForAll
```

[ ] By Removing Parameter in Request
```
When you enter wrong credentials the site shows error like username and password is incorrect/does not match,
password is incorrect for this username etc,
this type of response is shown by the site so can try this method Huh.
First you intercept the request and remove the password parameter in the request and forward the request.
Then the server sees that the username is available and logs you in to the site.
This problem occurs when the server does not analyze the request properly
```

[ ] check js file in login page 
```
it can contain a important path or username and password
```

[ ] Check for comments inside the page
```
it can contain a important info  such as username and password
```

[ ] Check the PHP comparisons error: 
```
user[]=a&pwd=b , user=a&pwd[]=b , user[]=a&pwd[]=b
```

[ ] Change content type to json and send json values (bool true included)
```
If you get a response saying that POST is not supported you can try to send the JSON in the body but with a GET request with Content-Type: application/json
```

[ ] Check nodejs potential parsing error 

[check this article](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4)
```
1. Nodejs will transform that payload to a query similar to the following one: SELECT id, username, left(password, 8) AS snipped_password, email FROM accounts WHERE username='admin' AND`` ``password=password=1; which makes the password bit to be always true.
2. If you can send a JSON object you can send "password":{"password": 1} to bypass the login.
3. Remember that to bypass this login you still need to know and send a valid username.
4. Adding "stringifyObjects":true option when calling mysql.createConnection will eventually block all unexpected behaviours when Object is passed in the parameter.
```

[ ] No SQL Injection
```
https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass
```

[ ] XPath Injection
```
' or '1'='1
' or ''='
' or 1]%00
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
'or string-length(name(.))<10 or'
'or contains(name,'adm') or'
'or contains(.,'adm') or'
'or position()=2 or'
admin' or '
admin' or '1'='2
```

[ ] LDAP Injection
```
*
*)(&
*)(|(&
pwd)
*)(|(*
*))%00
admin)(&)
pwd
admin)(!(&(|
pwd))
admin))(|(|
```

[ ] Authorization
```
https://www.securify.nl/en/advisory/authorization-bypass-in-infinitewp-admin-panel/
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Enumerate Infrastructure and Application Admin Interfaces

|ID          |
|------------|
|WSTG-CONF-05|

#### Summary

Administrator interfaces may be present in the application or on the application server to allow certain users to perform privileged activities on the site. Tests should be undertaken to reveal if and how this privileged functionality can be accessed by an unauthorized or standard user.

An application may require an administrator interface to enable a privileged user to access functionality that may make changes to how the site functions. Such changes may include:

- User account provisioning
- Site design and layout
- Data manipulation
- Configuration changes

In many instances, such interfaces do not have sufficient controls to protect them from unauthorized access. Testing is aimed at discovering these administrator interfaces and accessing functionality intended for the privileged users.

#### Test Objectives

- Identify hidden administrator interfaces and functionality.

#### How to Test

##### Black Box Testing

The following section describes vectors that may be used to test for the presence of administrative interfaces. These techniques may also be used to test for related issues including privilege escalation, and are described elsewhere in this guide (for example, [bypassing authorization schema](../05-Authorization/02-Bypassing_Authorization_Schema.md) and [Insecure Direct Object References](../05-Authorization/04-Insecure_Direct_Object_References.md)) in greater detail.

- Directory and file enumeration: An administrative interface may be present but not visibly available to the tester. The path of the administrative interface may be guessed by simple requests such as /admin or /administrator. In some scenarios, these paths can be revealed within seconds using advanced Google search techniques - [Google dorks](https://www.exploit-db.com/google-hacking-database). There are many tools available to perform brute forcing of server contents, see the tools section below for more information. A tester may have to also identify the filename of the administration page. Forcibly browsing to the identified page may provide access to the interface.
- Comments and links in source code: Many sites use common code that is loaded for all site users. By examining all source sent to the client, links to administrator functionality may be discovered and should be investigated.
- Reviewing server and application documentation: If the application server or application is deployed in its default configuration it may be possible to access the administration interface using information described in configuration or help documentation. Default password lists should be consulted if an administrative interface is found and credentials are required.
- Publicly available information: Many applications, such as WordPress, have administrative interfaces that are available by default.
- Alternative server port: Administration interfaces may be seen on a different port on the host than the main application. For example, Apache Tomcat's Administration interface can often be seen on port 8080.
- Parameter tampering: A GET or POST parameter, or a cookie may be required to enable the administrator functionality. Clues to this include the presence of hidden fields such as:

```html
<input type="hidden" name="admin" value="no">
```

or in a cookie:

`Cookie: session_cookie; useradmin=0`

Once an administrative interface has been discovered, a combination of the above techniques may be used to attempt to bypass authentication. If this fails, the tester may wish to attempt a brute force attack. In such an instance, the tester should be aware of the potential for administrative account lockout if such functionality is present.

##### Gray Box Testing

A more detailed examination of the server and application components should be undertaken to ensure hardening (i.e. administrator pages are not accessible to everyone through the use of IP filtering or other controls), and where applicable, verification that all components do not use default credentials or configurations.
Source code should be reviewed to ensure that the authorization and authentication model ensures clear separation of duties between normal users and site administrators. User interface functions shared between normal and administrator users should be reviewed to ensure clear separation between the rendering of such components and the information leakage from such shared functionality.

Each web framework may have its own default admin pages or paths, as in the following examples:

PHP:

```html
/phpinfo
/phpmyadmin/
/phpMyAdmin/
/mysqladmin/

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Admin Protection Bypasses via UIAccess


#### Overview
- Windows AppInfo exposes the internal `RAiLaunchAdminProcess` path used to start UIAccess applications for accessibility. UIAccess permits selected interaction across User Interface Privilege Isolation (UIPI) boundaries; it is not a general bypass of every process-security boundary.<sup>[[1]](#references)[[3]](#references)</sup>
- Enabling UIAccess directly requires `NtSetInformationToken(TokenUIAccess)` with **SeTcbPrivilege**, so low-priv callers rely on the service. The service performs three checks on the target binary before setting UIAccess:
  - Embedded manifest contains `uiAccess="true"`.
  - Signed by any certificate trusted by the Local Machine root store (no EKU/Microsoft requirement).
  - Located in an administrator-only path on the system drive (e.g., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluding specific writable subpaths).
- `RAiLaunchAdminProcess` performs no consent prompt for UIAccess launches (otherwise accessibility tooling could not drive the prompt).<sup>[[1]](#references)</sup>

#### Token shaping and integrity levels
- If the checks succeed, AppInfo **copies the caller token**, enables UIAccess, and bumps Integrity Level (IL):
  - Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
  - Non-admin user ➜ IL increased by **+16 levels** up to a **High** cap (System IL is never assigned).
  - If the caller token already has UIAccess, IL is left unchanged.
- “Ratchet” trick: a UIAccess process can disable UIAccess on itself, relaunch via `RAiLaunchAdminProcess`, and gain another +16 IL increment. Medium➜High takes 255 relaunches (noisy, but works).<sup>[[1]](#references)</sup>

#### Why UIAccess enables an Admin Protection escape
- UIAccess lets a lower-IL process send window messages to higher-IL windows (bypassing UIPI filters). At **equal IL**, classic UI primitives like `SetWindowsHookEx` **do allow code injection/DLL loading** into any process that owns a window (including **message-only windows** used by COM). 
- Admin Protection launches the UIAccess process under the **limited user’s identity** but at **High IL**, silently. Once arbitrary code runs inside that High-IL UIAccess process, the attacker can inject into other High-IL processes on the desktop (even belonging to different users), breaking the intended separation.<sup>[[1]](#references)</sup>


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Exposed/again-reachable admin → BFLA → full control
- Default creds / no-auth admin API

## Hunter2 wiring
- **Run:** `recon · /bypass-403 · /param-discover`
- **Skill:** `web2-recon`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- Admin panel that loads but still enforces auth (login page reachable ≠ access) — no bypass, no creds
- "An admin can do X" — privileged-user capability is expected behavior, not a bug (Q4 KILL rule)
- Login page found via directory fuzzing with no auth bypass, working default creds, or exposed function behind it
- Response manipulation (403→200, false→true) that changes only the client view, not server-side access
- Missing security headers / version banner / internal IP on the admin host with no working exploit

**Conditionally valid (only WITH a chain):** unauthenticated reach to admin functionality, working default creds, or a non-admin user invoking an admin-only action (BFLA/privesc) → High/Critical.
