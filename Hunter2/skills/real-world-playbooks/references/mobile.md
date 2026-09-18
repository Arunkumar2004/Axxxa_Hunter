# Real-World Playbook — Mobile (APK/IPA)

**Class:** `mobile` · **Coverage-matrix tier:** 3 · **Hunter2:** /mobile-scan · **Skill:** mobile-pentest
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed Mobile reports peak at **$10,000**. Rewarded across: GitHub Security Lab, Mail.ru, Nextcloud, Pornhub, Razer, Slack, Uber, VK.com.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **read new emails from any inbox IOS APP in notification center** — Mail.ru, $10,000 · 186👍 · [977212](https://hackerone.com/reports/977212)
- **Weak user aunthentication on mobile application - I just broken userKey secret password** — Pornhub, $5,000 · 29👍 · [138101](https://hackerone.com/reports/138101)
- **[Java] CWE-312: Query to detect cleartext storage of sensitive information using Android SharedPreferences** — GitHub Security Lab, $4,500 · 9👍 · [1122661](https://hackerone.com/reports/1122661)
- **Уязвимость в приложении для Android** — VK.com, $3,000 · 52👍 · [1343528](https://hackerone.com/reports/1343528)
- **Possibility to enumerate and bruteforce promotion codes in Uber iOS App** — Uber, $3,000 · 24👍 · [125707](https://hackerone.com/reports/125707)
- **Changing email address on Twitter for Android unsets "Protect your Tweets"** — X / xAI, $2,940 · 119👍 · [472013](https://hackerone.com/reports/472013)
- **Periscope iOS app CSRF in follow action due to deeplink** — X / xAI, $2,940 · 58👍 · [805073](https://hackerone.com/reports/805073)
- **Java: CWE-749 Unsafe resource loading in Android WebView leaking to injection attacks** — GitHub Security Lab, $2,300 · 60👍 · [1011956](https://hackerone.com/reports/1011956)
- **Twitter iOS fails to validate server certificate and sends oauth token** — X / xAI, $2,100 · 40👍 · [168538](https://hackerone.com/reports/168538)
- **[Java] CWE-755: Query to detect Local Android DoS caused by NFE** — GitHub Security Lab, $1,800 · 16👍 · [1061211](https://hackerone.com/reports/1061211)
- **Java: Detect remote source from Android intent extra** — GitHub Security Lab, $1,800 · 7👍 · [1030295](https://hackerone.com/reports/1030295)
- **[Java] CWE-200: Query to detect exposure of sensitive information from android file intent** — GitHub Security Lab, $1,800 · 4👍 · [1365761](https://hackerone.com/reports/1365761)
- **Periscope android app deeplink leads to CSRF in follow action** — X / xAI, $1,540 · 224👍 · [583987](https://hackerone.com/reports/583987)
- **AWS bucket leading to iOS test build code and configuration exposure** — Slack, $1,500 · 321👍 · [404822](https://hackerone.com/reports/404822)
- **(Pornhub & Youporn & Brazzers ANDROID APP) : Upload Malicious APK / Overrite Existing APK  / Android BackOffice Access** — Pornhub, $1,500 · 16👍 · [142352](https://hackerone.com/reports/142352)
- **End to end encryption public key is not properly verified on Desktop and Android** — Nextcloud, $1,500 · 13👍 · [1189162](https://hackerone.com/reports/1189162)
- **url that twitter mobile site can not load** — X / xAI, $1,120 · 142👍 · [500686](https://hackerone.com/reports/500686)
- **[Razer Pay  Mobile App] Broken access control allowing other user's bank account to be deleted** — Razer, $1,000 · 311👍 · [757095](https://hackerone.com/reports/757095)

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Android Malware Post-Exploitation


This page collects Android malware behavior that happens after installation or execution: payload staging, persistence, C2, Accessibility-driven control, overlays, SMS/OTP abuse, fraud automation, and botnet tasking. Keep Android app pentesting methodology focused on testing legitimate apps, and use this page when reversing malicious Android samples or documenting post-install tradecraft.

#### C2-Gated Permission Abuse and Background Collection

Some malicious APK campaigns only reveal their real behaviour after a C2-controlled gate, such as an invitation code, operator validation, or server-side risk check. This keeps sandbox runs benign unless the analyst reaches the malicious branch.<sup>[[4]](#references)</sup>

Common pattern:

1. The app asks for an **invitation / verification code** on first run.
2. The code is **POSTed over HTTP** to the C2.
3. The C2 replies with a success flag.
4. Dangerous permissions and collection routines are requested only after that positive response.<sup>[[4]](#references)</sup>

Example permission set:

```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Hardcoded secret/endpoint in APK → authed API abuse
- Exported activity / deeplink / WebView bridge → injection
- SSL-pin bypass → proxy hidden API → IDOR/BOLA

## Hunter2 wiring
- **Run:** `/mobile-scan`
- **Skill:** `mobile-pentest`
- **Coverage-matrix tier:** 3 (Tier 0 = test first)
