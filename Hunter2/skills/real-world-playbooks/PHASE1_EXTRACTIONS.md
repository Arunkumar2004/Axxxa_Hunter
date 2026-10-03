# Phase 1 Structured Report Extractions

This file converts the 50 public references in `PHASE1_PRIORITY_LEDGER.md` into
compact, reusable method records. It intentionally stores methodology and safe proof
conditions, not raw authenticated traffic, credentials, private data, or destructive
payloads.

Method cross-check sources downloaded to `D:\bughunting\Axxx_Hunter\.phase1-research\sources\`
include OWASP WSTG, PayloadsAllTheThings, HowToHunt, and AllAboutBugBounty. The
Az0x7 checklist is recorded in the source plan; its Windows checkout contains an
invalid filename, so the public repository reference is retained without copying its
unsafe/raw content into Hunter2.

Each row is:

```text
report | precondition | method | safe proof | impact | reject unless
```

## IDOR / BOLA / BFLA

| Report | Preconditions | Method | Safe proof | Impact | Reject unless |
|---|---|---|---|---|---|
| 415081 | Authenticated business user; user-management object | Swap a controlled object reference across two accounts | Account B reads or reversibly edits Account A's test object | Unauthorized user administration | Ownership is not proven |
| 2207248 | Authenticated GraphQL billing access | Query a second controlled account's billing object | Foreign test invoice body is returned | Billing disclosure | Object is public or same-owner |
| 1658418 | User can access moderation API | Compare controlled public/restricted test records | Restricted test record is returned to low-privilege account | Private moderation disclosure | Only status/length differs |
| 1966006 | User/profile identifier is reachable | Replace identifier with another controlled test identity | Foreign test profile data is returned | PII disclosure | Identifier ownership is unknown |
| 2122671 | Two authenticated test accounts; GraphQL object ID | Swap a controlled certification ID | Account B can affect only Account A's test certification | Unauthorized deletion | No cross-account delta |
| 1392630 | Support-ticket API with two test users | Replay ticket request using the other test user's reference | Foreign test ticket is returned | Private support disclosure | Ticket is intentionally shared |
| 1969141 | Campaign-management endpoint; two authorized test programs | Swap controlled campaign ID | Only a disposable test campaign is changed | Unauthorized deletion | Change is not reversible or controlled |
| 2487889 | Search/report endpoint with organization scope | Compare two authorized test organizations | Only controlled private test metadata is returned | Cross-tenant disclosure | Data is public or scope is unknown |
| 876300 | Two owned sites sharing auth/session boundaries | Compare cookie/session trust across controlled sites | Only the attacker's test account is accessed | Cross-site ATO chain | Victim account is touched |
| 1527906 | Ads/catalog API with two controlled accounts | Swap product/catalog object reference | Only a test catalog object changes | Unauthorized modification | No cross-account delta |

## Authentication / Account Takeover

| Report | Preconditions | Method | Safe proof | Impact | Reject unless |
|---|---|---|---|---|---|
| 2293343 | Owned reset flow and test account | Compare token binding, expiry, and account association | Attacker controls only the attacker's test account after reset | Reset authorization failure | No account-state transition |
| 745324 | Session token appears in a controlled test context | Check token scope, rotation, and revocation | Only owned session is reproduced after controlled logout test | Session compromise | Token is synthetic or expired |
| 2443228 | Recovery flow with two owned accounts | Test state transitions and identity binding | Recovery completes for the attacker's own controlled account without victim action | Recovery bypass | Requires victim interaction or data |
| 976603 | SSO/organization test tenant | Check lockout and SSO state handling within limits | Availability or auth state changes only in test tenant | Auth/availability chain | Load or real-user impact is required |
| 173551 | Owned reset flow and controlled mailbox | Inspect token placement, audience, and expiry | Controlled reset token can only reset the attacker's account | Token disclosure/binding flaw | No usable controlled token |
| 136885 | Two owned accounts and normal login flow | Test account-linking and session transitions | Attacker gains access only to an owned test account | Account takeover | Victim account is touched |
| 394329 | Owned billing/account workflow | Compare billing identity and session binding | Controlled account role/state changes reproducibly | ATO via billing flow | Payment or victim data is required |
| 862589 | Authorized test deployment with management endpoint | Check authentication and exposure without changing state | Read-only test metadata proves missing auth | Auth bypass exposure | Endpoint is out of scope |
| 1923672 | Owned SAML/OAuth integration and test provider | Test RelayState and code binding | Controlled authorization code remains bound to the test session | OAuth-to-ATO chain | No code/session impact |
| 397497 | Owned OAuth client and redirect URI | Test state, redirect, and code binding | Authorization code remains bound to the controlled session | OAuth-to-ATO chain candidate | No code/session impact |

## SSRF

| Report | Preconditions | Method | Safe proof | Impact | Reject unless |
|---|---|---|---|---|---|
| 2262382 | Server-side report/fetch feature | Supply a controlled callback URL | Correlated callback includes request timing and unique marker | Blind SSRF | Callback is unrelated or DNS-only without correlation |
| 398799 | OAuth callback makes server-side token request | Use a unique controlled callback host | Correlated request proves blind server-side fetch | Blind SSRF | No target-request correlation |
| 826361 | Remote attachment/import URL | Use an owned callback and controlled test file | Target fetches the callback during import | Server-side fetch | Client fetched it instead |
| 1960765 | Preview/link service | Use unique OOB marker and compare baseline | Controlled callback proves server-side request | Blind SSRF | No target-request correlation |
| 1409727 | Document import service | Use controlled URL and inert response | Returned marker proves fetch path | SSRF/data-read candidate | No response or callback evidence |
| 1547877 | Connector/import service with internal reachability | Stop at controlled callback or marker endpoint | Callback proves reachability without exploitation | SSRF-to-internal chain candidate | Exploitation of internal service is required |
| 776017 | Authorized managed Kubernetes service | Use controlled callback only | Unique callback confirms server-side request | Blind/internal SSRF | Metadata or credentials are accessed |
| 374737 | Error-reporting service fetches source URLs | Use unique controlled callback URL | Correlated callback proves server-side request | Blind SSRF | No callback correlation |
| 2429894 | Application performs domain lookup | Use unique controlled hostname | Correlated lookup proves server-side resolution | DNS/SSRF behavior | No correlation to the request |
| 746024 | XML/fetch endpoint | Controlled URL and inert response | Marker proves server-side fetch | SSRF | Parser error alone is the only signal |

## Command Injection / RCE

| Report | Preconditions | Method | Safe proof | Impact | Reject unless |
|---|---|---|---|---|---|
| 1609965 | Archive import and reachable processing path | Identify parser/extraction boundary | Controlled inert marker or OOB callback proves execution path | Code execution chain | Error or parser banner only |
| 925585 | Build system resolves attacker-controlled dependency name | Verify package namespace and isolated test build | Controlled test package callback in authorized build | Supply-chain execution | No build execution proof |
| 591295 | Pre-auth VPN processing sink in scope | Fingerprint safely and use vendor-safe marker | Controlled callback or inert execution proof | Pre-auth RCE | Version-only evidence |
| 1154542 | Image metadata processing feature | Use benign controlled test file | Callback/marker confirms processing execution | Parser-to-RCE candidate | File is not processed server-side |
| 1125425 | Wiki/template renderer and controlled page | Test harmless expression behavior | Inert marker proves evaluation without file access | Template execution | Reflection only |
| 181879 | Script/type conversion boundary | Supply bounded type-confusion test values | Controlled marker proves execution | Code-execution candidate | Crash only |
| 658013 | Search/flag parser with controlled repository | Test argument-boundary handling safely | Owned test artifact changes in isolated scope | Injection-to-RCE candidate | No state/effect change |
| 3782701 | GraphQL filter reaches server-side evaluator | Use harmless controlled predicate | Unique marker confirms evaluator execution | GraphQL-to-RCE candidate | Query error only |
| 733072 | Traversal reaches a controlled file/write sink | Use isolated test path only | Owned marker file or OOB proof, cleaned up immediately | Traversal-to-RCE candidate | Reads arbitrary sensitive files |
| 125980 | Flask/Jinja template renders controlled profile field | Use inert arithmetic/marker expression | Rendered marker proves template evaluation | SSTI/RCE candidate | Reflection only |

## Business Logic / Race Conditions

| Report | Preconditions | Method | Safe proof | Impact | Reject unless |
|---|---|---|---|---|---|
| 689314 | Project-copy workflow with two owned projects | Compare intended access and copy boundaries | Only controlled private test artifact is copied | Cross-project disclosure | Artifact is public |
| 1478633 | Rule/transform workflow with test tenant | Compare parser interpretation at each stage | Harmless test rule produces unexpected controlled result | Workflow authorization flaw | No state difference |
| 1628209 | Admin support/PDF workflow in scope | Use controlled callback and test document | Callback proves workflow reaches controlled sink | SSRF/business chain | Real internal data is required |
| 1520931 | File operation with controlled test path | Compare check/use timing with isolated files | Test file state changes only in owned workspace | TOCTOU candidate | Destructive shared path is needed |
| 1330529 | OTP/listing workflow with owned test listing | Repeat/reorder only controlled state transitions | Owned listing changes state without required rule | Workflow bypass | Real seller/customer is touched |
| 484745 | Parser/state boundary in authorized test software | Use vendor-safe malformed test input | Controlled test process/marker proves effect | Parser-to-RCE chain | Crash alone |
| 2301565 | Webhook workflow and owned callback | Replay controlled webhook state | Callback and state transition are reproducible | SSRF/workflow chain | Third-party data is required |
| 364843 | Shopping/quantity workflow with test product | Compare server-side total for bounded negative/zero quantity | Only a disposable test order changes | Price manipulation | Real payment or inventory is touched |
| 3255473 | Signup workflow with owned test email | Omit the OTP verification field in a test registration | Controlled test account is created without ownership proof | Verification bypass and impersonation risk | Real email or account is used |
| 429026 | Race-prone payment/retest workflow with test value | One baseline then one bounded concurrent wave | Persistent duplicate effect on two read-only surfaces | Duplicate payment/state effect | Transient response count only |

## Common Rejection Rules

- Scanner signature, banner, stack trace, or timing difference alone is not proof.
- Authenticated findings require identity, ownership, and cross-session evidence.
- SSRF DNS-only callbacks remain `CONFIRMED_BLIND` or `CHAIN REQUIRED` unless impact is
  demonstrated safely.
- RCE requires a controlled callback or inert execution marker; never use real secrets,
  destructive writes, reverse shells, or victim data.
- Business-logic and race findings require persistent controlled impact and cleanup.
- A report must include endpoint, request, response, reproduction, impact, and scope.
