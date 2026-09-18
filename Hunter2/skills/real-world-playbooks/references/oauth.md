# Real-World Playbook — OAuth / OIDC Flaws

**Class:** `oauth` · **Coverage-matrix tier:** 1 · **Hunter2:** tools/h1_oauth_tester.py · /auth-hunt · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed OAuth / OIDC Flaws reports peak at **$4,000**. Rewarded across: Coinbase, Dropbox, GSA Bounty, GitLab, LY Corporation, Mattermost, Phabricator, Pornhub.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Unauthenticated blind SSRF in OAuth Jira authorization controller** — GitLab, $4,000 · 238👍 · [398799](https://hackerone.com/reports/398799)
- **Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties** — GitLab, $3,000 · 257👍 · [922456](https://hackerone.com/reports/922456)
- **Incorrect details on OAuth permissions screen allows DMs to be read without permission** — X / xAI, $2,940 · 80👍 · [434763](https://hackerone.com/reports/434763)
- **Twitter iOS fails to validate server certificate and sends oauth token** — X / xAI, $2,100 · 40👍 · [168538](https://hackerone.com/reports/168538)
- **Stealing Users OAuth authorization code via redirect_uri** — pixiv, $2,000 · 252👍 · [1861974](https://hackerone.com/reports/1861974)
- **`account_info.read` scope OAuth app access token can change token owner's account name.** — Dropbox, $1,728 · 34👍 · [1031240](https://hackerone.com/reports/1031240)
- **Problem with OAuth** — X / xAI, $1,260 · 7👍 · [46485](https://hackerone.com/reports/46485)
- **page.line.me Open Redirect Leading to OAuth Authorization Code Exposure and Access Token Compromise** — LY Corporation, $1,000 · 43👍 · [3423013](https://hackerone.com/reports/3423013)
- **Account takeover via Pornhub Oauth** — Pornhub, $1,000 · 17👍 · [192648](https://hackerone.com/reports/192648)
- **Mattermost Server OAuth Flow Cross-Site Scripting** — Mattermost, $900 · 44👍 · [1216203](https://hackerone.com/reports/1216203)
- **Stealing Users OAuth Tokens through redirect_uri parameter** — GSA Bounty, $750 · 67👍 · [665651](https://hackerone.com/reports/665651)
- **Smuggle SocialClub's Facebook OAuth Code via Referer Leakage** — Rockstar Games, $750 · 39👍 · [342709](https://hackerone.com/reports/342709)
- **Broken OAuth leads to change photo profile users .** — Dropbox, $512 · 37👍 · [642475](https://hackerone.com/reports/642475)
- **Open redirection in OAuth** — Shopify, $500 · 14👍 · [55525](https://hackerone.com/reports/55525)
- **OAuth access_token stealing in Phabricator** — Phabricator, $450 · 9👍 · [3596](https://hackerone.com/reports/3596)
- **OAuth Stealing Attack (New)** — Phabricator, $400 · 10👍 · [3930](https://hackerone.com/reports/3930)
- **Race Condition in Oauth 2.0 flow can lead to malicious applications create multiple valid sessions** — Razer, $250 · 8👍 · [699112](https://hackerone.com/reports/699112)
- **OAUTH pemission set as true= lead to authorize malicious application** — Coinbase, $100 · 5👍 · [87561](https://hackerone.com/reports/87561)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```
```
https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F
```
```
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```
```
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### OAuth Weaknesses

|ID          |
|------------|
|WSTG-ATHZ-05|

#### Summary

[OAuth2.0](https://oauth.net/2/) (hereinafter referred to as OAuth) is an authorization framework that allows a client to access resources on the behalf of its user.

In order to achieve this, OAuth heavily relies on tokens to communicate between the different entities, each entity having a different [role](https://datatracker.ietf.org/doc/html/rfc6749#section-1.1):

- **Resource Owner:** The entity who grants access to a resource, the owner, and in most cases is the user themselves
- **Client:** The application that is requesting access to a resource on behalf of the Resource Owner. These clients come in two [types](https://oauth.net/2/client-types/):
    - **Public:** clients that can't protect a secret (*e.g.* frontend focused applications, such as SPAs, mobile applications, etc.)
    - **Confidential:** clients that are able to securely authenticate with the authorization server by keeping their registered secrets safe (*e.g.* backend services)
- **Authorization Server:** The server that holds authorization information and grants the access
- **Resource Server:** The application that serves the content accessed by the client

Since OAuth's responsibility is to delegate access rights by the owner to the client, this is a very attractive target for attackers, and bad implementations lead to unauthorized access to the users' resources and information.

In order to provide access to a client application, OAuth relies on several [authorization grant types](https://oauth.net/2/grant-types/) to generate an access token:

- [Authorization Code](https://oauth.net/2/grant-types/authorization-code/): used by both confidential and public clients to exchange an authorization code for an access token, but recommended only for confidential clients
- [Proof Key for Code Exchange (PKCE)](https://oauth.net/2/pkce/): PKCE builds on top of the Authorization Code grant, providing stronger security for it to be used by public clients, and improving the posture of confidential ones
- [Client Credentials](https://oauth.net/2/grant-types/client-credentials/): used for machine to machine communication, where the "user" here is the machine requesting access to its own resources from the Resource Server
- [Device Code](https://oauth.net/2/grant-types/device-code/): used for devices with limited input capabilities.
- [Refresh Token](https://oauth.net/2/grant-types/refresh-token/): tokens provided by the authorization server to allow clients to refresh users' access tokens once they become invalid or expire. This grant type is used in conjunction with one other grant type.

Two flows will be deprecated in the release of [OAuth2.1](https://oauth.net/2.1/), and their usage is not recommended:

- [Implicit Flow*](https://oauth.net/2/grant-types/implicit/): PKCE's secure implementation renders this flow obsolete. Prior to PKCE, the implicit flow was used by client-side applications such as [single page applications](https://en.wikipedia.org/wiki/Single-page_application) since [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) relaxed the [same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) for sites to inter-communicate. For more information on why the implicit grant is not recommended, review this [section](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.2).
- [Resource Owner Password Credentials](https://oauth.net/2/grant-types/password/):used to exchange users' credentials directly with the client, which then sends them to the authorization to exchange them for an access token. For information on why this flow is not recommended, review this [section](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4).

*: The implicit flow in OAuth only is deprecated, yet is still a viable solution within Open ID Connect (OIDC) to retrieve `id_tokens`. Be careful to understand how the implicit flow is being used, which can be identified if only the `/authorization` endpoint is being used to gain an access token, without relying on `/token` endpoint in any way. An example on this can be found [here](https://auth0.com/docs/get-started/authentication-and-authorization-flow/implicit-flow-with-form-post).

*Please note that OAuth flows are a complex topic, and the above includes only a summary of the key areas. The inline references contain further information about the specific flows.*

#### Test Objectives

- Determine if OAuth2 implementation is vulnerable or using a deprecated or custom implementation.

#### How to Test

##### Deprecated Grant Types

Deprecated grant types were obsoleted for security and functionality reasons. Identifying if they're being used allows us to quickly review if they're susceptible to any of the threats pertaining to their usage. Some might be out of scope to the attacker, such as the way a client might be using the users' credentials. This should be documented and raised to the internal engineering teams.

For public clients, it is generally possible to identify the grant type in the request to the `/token` endpoint. It is indicated in the token exchange with the parameter `grant_type`.

The following example shows the Authorization Code grant with PKCE.

```http
POST /oauth/token HTTP/1.1
Host: as.example.com
[...]

{
  "client_id":"example-client",
  "code_verifier":"example",

*(truncated — open the source link for the full method)*

### From HowToHunt
### Some MindMap
---
##### OAuth by Hack3rSr0lls

##### Source
* [https://twitter.com/hackerscrolls/status/1269266750467649538](https://twitter.com/hackerscrolls/status/1269266750467649538)

##### Author
* [KathanP19](https://twitter.com/KathanP19)

### From AllAboutBugBounty
### OAuth Misconfiguration

#### Introduction
The most infamous OAuth-based vulnerability is when the configuration of the OAuth service itself enables attackers to steal authorization codes or access tokens associated with other users’ accounts. By stealing a valid code or token, the attacker may be able to access the victim's account.

#### Where to find
In the SSO feature. For example the URL will be looks like this
```
https://example/signin?response_type=code&redirect_uri=https://callback_url/auth&client_id=FQ9RGtMkztAgmAApKOqACrBNq&state=7tvPJiv8StrAqo9IQE9xsJaDso4&scope=+profile+email+phone+group+role+resource
```

#### How to exploit
1. OAuth token stealing by changing `redirect_uri` and Use IDN Homograph
   * Normal parameter
        ```
        &redirect_uri=https://example.com
        ```
    * IDN Homograph
        ```
        &redirect_uri=https://еxamplе.com
        ```
    If you notice, im not using the normal `e`
2. Create an account with victim@gmail.com with normal functionality. Create account with victim@gmail.com using OAuth functionality. Now try to login using previous credentials.
3. OAuth Token Re-use.
4. Improper handling of state parameter

    To exploit this, go through the authorization process under your account and pause immediately after authorization. Then send this URL to the logged-in victim
    * CSRF Attack
        ```html
        <a href="https://example.com/authorize?client_id=client1&response_type=code&redirect_uri=http://callback&scope=openid+email+profile">Press Here</a>
        ```
5. Lack of origin check.
6. Open Redirection on `redirect_uri` parameter
    * Normal parameter
        ```
        &redirect_uri=https://example.com
        ```
    * Open Redirect
        ```
        &redirect_uri=https://evil.com
        &redirect_uri=https://example.com.evil.com
        etc.
        ```
7. If there is an email parameter after signin then try to change the email parameter to victim's one.
8.  Try to remove email from the scope and add victim's email manually.
9.  Check if its leaking `client_secret`

#### References
* [tuhin1729_](https://twitter.com/tuhin1729_/status/1417843523177484292)
* [c0d3x27](https://infosecwriteups.com/the-oauth-misconfiguration-15e66dd19a6e)

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### OAuth to Account Takeover


#### Basic Information <a href="#d4a8" id="d4a8"></a>

OAuth has several versions and grant types; [oauth.net provides a concise OAuth 2.0 overview](https://oauth.net/2/) and a focused guide to the [authorization-code grant](https://oauth.net/2/grant-types/authorization-code/). This page focuses on that widely used grant, an **authorization framework that lets an application access or perform approved actions on a user's resources managed by another service**.<sup>[[24]](#references)</sup>

Consider a hypothetical website _**https://example.com**_, designed to **showcase all your social media posts**, including private ones. To achieve this, OAuth 2.0 is employed. _https://example.com_ will request your permission to **access your social media posts**. Consequently, a consent screen will appear on _https://socialmedia.com_, outlining the **permissions being requested and the developer making the request**. Upon your authorization, _https://example.com_ gains the ability to **access your posts on your behalf**.

It's essential to grasp the following components within the OAuth 2.0 framework:

- **resource owner**: You, as the **user/entity**, authorize access to your resource, like your social media account posts.
- **resource server**: The **server managing authenticated requests** after the application has secured an `access token` on behalf of the `resource owner`, e.g., **https://socialmedia.com**.
- **client application**: The **application seeking authorization** from the `resource owner`, such as **https://example.com**.
- **authorization server**: The **server that issues `access tokens`** to the `client application` following the successful authentication of the `resource owner` and securing authorization, e.g., **https://socialmedia.com**.
- **client_id**: A public, unique identifier for the application.
- **client_secret:** A confidential key, known solely to the application and the authorization server, used for generating `access_tokens`.
- **response_type**: A value specifying **the type of token requested**, like `code`.
- **scope**: The **level of access** the `client application` is requesting from the `resource owner`.
- **redirect_uri**: The **URL to which the user is redirected after authorization**. This typically must align with the pre-registered redirect URL.
- **state**: A parameter to **maintain data across the user's redirection to and from the authorization server**. Its uniqueness is critical for serving as a **CSRF protection mechanism**.
- **grant_type**: A parameter indicating **the grant type and the type of token to be returned**.

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- redirect_uri bypass → steal code/token → ATO
- Missing state param → OAuth CSRF (account linking) → ATO
- Referrer/open-redirect leak of code → ATO
- PKCE downgrade / code reuse

## Hunter2 wiring
- **Run:** `tools/h1_oauth_tester.py · /auth-hunt`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
