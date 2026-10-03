# Phase 1 External Case Studies

These 20 cases supplement the 50 HackerOne records. They are public technical case
studies, vendor-advisory cases, or research cases fetched from sources other than the
HackerOne dataset. They are counted as cases only when they describe a concrete
vulnerability or exploit path, not merely a generic checklist.

## Authentication / ATO

1. **OAuth dynamic client registration SSRF** - PortSwigger, hidden OAuth vectors.
   Condition: registration accepts URL references; proof: controlled callback; route:
   `oauth` + `ssrf` -> `h1_oauth_tester.py`/OOB -> validation.
2. **OAuth redirect URI session poisoning** - PortSwigger, hidden OAuth vectors.
   Condition: authorization state stored across steps; proof: controlled client and
   redirect binding; route: `oauth`/`auth-session` -> browser/proxy -> validation.
3. **OpenID WebFinger user enumeration** - PortSwigger, hidden OAuth vectors.
   Condition: discovery endpoint exposes response differences; proof: owned test
   identities only; route: `openid` -> auth agent -> evidence.
4. **MITREid redirect URI binding bypass (CVE-2021-27582)** - PortSwigger research.
   Condition: model binding accepts unvalidated confirmation parameters; proof:
   controlled OAuth client; route: `oauth` -> `h1_oauth_tester.py` -> validation.

## SSRF

5. **MITREid client logo SSRF (CVE-2021-26715)** - PortSwigger research.
   Condition: server fetches registered client logo; proof: unique OOB marker; route:
   `ssrf` -> `oob_listener.py` -> blind SSRF validation.
6. **Second-order OAuth registration SSRF** - PortSwigger research.
   Condition: URL stored at registration and fetched later; proof: callback correlated
   to the owned client; route: `ssrf`/`oauth` -> OOB -> evidence.
7. **HTTP/2 scheme-to-route SSRF primitive** - PortSwigger HTTP/2 research.
   Condition: HTTP/2 pseudo-header used in backend URL construction; proof: controlled
   endpoint only; route: `ssrf`/`request-smuggling` -> safe protocol probe.
8. **OAST-confirmed blind backend fetch** - PortSwigger asynchronous research.
   Condition: queued/background processing has a URL sink; proof: unique callback and
   request correlation; route: `ssrf`/`oob_listener.py` -> validation.

## Command Injection / RCE

9. **Asynchronous shell command injection** - PortSwigger asynchronous research.
   Condition: background job or logging path executes attacker-controlled data; proof:
   controlled OOB callback; route: `command-injection` -> OOB -> no-destructive proof.
10. **Blind SQL/command callback detection** - PortSwigger asynchronous research.
    Condition: no in-band response but backend executes a sink; proof: unique callback;
    route: injection playbook -> OOB -> reject uncorrelated callbacks.
11. **Server-side prototype pollution to RCE** - PortSwigger SSPP research.
    Condition: unsafe merge plus reachable Node process sink; proof: safe marker/OOB,
    never destructive execution; route: `prototype-pollution`/`rce` -> validation.
12. **Prototype pollution import-flag RCE primitive** - PortSwigger Node research.
    Condition: controlled `NODE_OPTIONS`/child-process sink; proof: inert test process
    or callback in a lab/owned target; route: `rce` -> `novel-vuln-reasoner` -> proof.

## Business Logic / Race Conditions

13. **Logic flaw from excessive client-side trust** - PortSwigger Business Logic
    Academy. Condition: server trusts a client-controlled rule/value; proof: owned
    test transaction with before/after state; route: `business-logic-hunter`.
14. **Unconventional input transaction flaw** - PortSwigger Business Logic Academy.
    Condition: negative/zero/overflow or unexpected state value; proof: disposable
    test object and persistent state delta; route: business-logic validation.
15. **Workflow assumption bypass** - PortSwigger Business Logic Academy. Condition:
    step order or actor assumption is not enforced server-side; proof: owned workflow
    state transition; route: `business-logic-hunter` -> report.
16. **OAuth authorization race/session state flaw** - PortSwigger OAuth research.
    Condition: concurrent flows share mutable session state; proof: controlled accounts
    and bounded requests; route: `race-hunter`/`auth-session`.

## IDOR / BOLA / BFLA

17. **Hidden internal route reached through HTTP/2 desync** - PortSwigger HTTP/2
    research. Condition: frontend/backend disagreement exposes an internal route;
    proof: staging or explicitly authorized target with harmless endpoint; route:
    `request-smuggling` + `api-security` -> validation.
18. **Cross-user response queue confusion** - PortSwigger HTTP/2 research. Condition:
    response queue desynchronization; proof: controlled two-session test, never live
    victim traffic; route: `request-smuggling`/`api-hunter`.
19. **Cache-poisoned route or tenant selection** - PortSwigger cache research.
    Condition: unkeyed routing input changes selected tenant/resource; proof: isolated
    cache key and disposable response; route: `web-cache`/`api-security`.
20. **Cross-tenant route poisoning** - PortSwigger cache research. Condition: cache or
    proxy ignores tenant-bound input; proof: two owned tenants and harmless marker;
    route: `web-cache`/`api-hunter` -> validation.

## External Source Families Used

- PortSwigger Research and Web Security Academy
- Vendor/CVE references embedded in the research cases, including Apache, Netty, and
  MITREid advisories
- OWASP and public methodology repositories for method cross-checking
- HackerOne public reports for the original 50-case evidence set

These cases add technique diversity. The Hunter2 playbooks must still apply safe proof,
scope checks, rejection rules, and evidence requirements before reporting anything.
