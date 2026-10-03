# Phase 1 External Research Cross-Checks

These sources are not counted as the 50 concrete HackerOne case records. They are
separate public methodology and research inputs used to cross-check the extracted
methods and safe validation rules.

## PortSwigger Research and Academy

### Business Logic

Source: <https://portswigger.net/web-security/logic-flaws>

Extracted method: model intended server-side rules, then test unusual but well-formed
requests, state transitions, and client/server trust boundaries. Automated scanners
usually miss these because the requests are syntactically valid.

Hunter2 mapping: `business-logic-hunter` -> workflow model, controlled replay,
`h1_race.py` where a state transition is race-sensitive -> persistence and cleanup
proof -> validation/report.

### OAuth and OpenID

Source: <https://portswigger.net/research/hidden-oauth-attack-vectors>

Extracted method: enumerate standard and hidden discovery/registration endpoints,
check second-order URL fetches, redirect/session binding, and user enumeration. Test
only with controlled clients and accounts.

Hunter2 mapping: `auth-session`, `oauth`, `account-takeover` -> `h1_oauth_tester.py`
and browser/proxy capture -> controlled token/session evidence -> validation/report.

### HTTP Desynchronization

Source: <https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn>

Extracted method: identify parser disagreement, begin with low-impact timing/detection
probes, and do not move to socket poisoning on live shared traffic without explicit
authorization and a safe staging target.

Hunter2 mapping: `request-smuggling` -> `novel-vuln-reasoner` and scanner review ->
safe detection evidence -> no collateral-impact validation -> report.

### Server-Side Prototype Pollution

Source: <https://portswigger.net/research/server-side-prototype-pollution>

Extracted method: prefer non-destructive behavioral probes such as harmless response,
status, or header changes; avoid probes that can crash or permanently alter a shared
Node process.

Hunter2 mapping: `prototype-pollution` -> `prototype_pollution_scanner.py` -> safe
behavioral evidence -> reject DoS-only or uncorrelated differences -> report.

## OWASP and Methodology Repositories

Downloaded or referenced under:

```text
D:\bughunting\Axxx_Hunter\.phase1-research\sources\
```

- OWASP WSTG: testing structure and evidence discipline
- PayloadsAllTheThings: payload categories and parser-specific variants
- HowToHunt: attacker workflow and reconnaissance reasoning
- AllAboutBugBounty: practical class checklists and chaining patterns
- Az0x7 vulnerability checklist: ordered test-flow references; Windows checkout was
  blocked by one invalid filename, so the public repository remains the source link

## Source Discipline

- Never copy credentials, cookies, attachments, or private target data.
- Never treat a report title or scanner signature as proof.
- Every method promoted into Hunter2 must have a condition, safe proof, impact limit,
  rejection rule, and source link.
