# Real-World Playbook - SAML / SSO

**Class:** `saml-sso` · **Coverage-matrix tier:** 1 · **Hunter2:** `/auth-hunt` · `vuln_scanner.sh` · **Skill:** auth-attacks

**Route:** `auth-attacks` -> `api-hunter`/primary `hunter` -> `/auth-hunt`, browser and
proxy replay -> signed-assertion and identity-binding proof -> validator/report-writer.

## Conditions

- SAML login or ACS endpoint is reachable.
- A controlled IdP/test tenant and controlled service-provider account are available.
- The assertion audience, recipient, destination, signature, replay, and RelayState are
  observable.

## Safe method

- Compare a valid assertion with a single controlled mutation at a time.
- Check signature coverage, audience/recipient binding, time windows, replay, and
  account linking.
- Use only owned test identities and revoke test sessions after validation.

## Proof and rejection

- Confirm only when the controlled account identity or authorization decision changes.
- Reject parser errors, unsigned metadata, or a redirect without token/account impact.
- Never use a real user's assertion or retain credentials from a public report.

## Test flow / checklist — do these in order
*(public methodology — OWASP WSTG SAML / HackTricks SAML+XSW / PayloadsAllTheThings; run each, mark result in the coverage matrix)*

[ ] Capture a valid SAML login flow end to end (AuthnRequest → IdP → SAMLResponse → ACS) with a proxy
[ ] Decode/inflate the SAMLResponse and map signed elements: assertion signature vs response signature coverage
[ ] Test signature stripping — remove the `<Signature>` and see if the SP accepts an unsigned assertion
[ ] Test XML Signature Wrapping (XSW): wrap the original signed assertion and inject an attacker-controlled unsigned one
[ ] Test signature-exclusion / comment injection (comment or NUL in NameID) to alter the parsed identity
[ ] Tamper the `NameID`/attributes to another owned test identity and check whether the SP binds the new identity
[ ] Check audience, recipient, destination, and `NotOnOrAfter` validation — try mismatched/expired values
[ ] Test assertion replay — resend a used SAMLResponse and check for one-time-use enforcement
[ ] Test RelayState for open redirect / injection and IdP-initiated flow abuse
[ ] Check account-linking — can a SAML assertion link/hijack an existing local account by email?
[ ] Use only owned test identities/tenants and revoke test sessions after validation

## What gets this rejected (kill before you write)
*(from `skills/triage-validation/SKILL.md` — one wrong answer = kill it and move on)*

- SAML metadata exposed (public by IdP design) with no private key/signing cert extracted — disclosure only.
- Parser errors or unsigned metadata without an identity or authorization change.
- A RelayState redirect without token or account-takeover impact.
- Findings using a real user's assertion or credentials pulled from a public report.
- "Signature not validated" claimed from reading config with no working forged-assertion PoC.
- An IdP/SP that is a third-party service outside scope.
- **Conditionally valid (only WITH a chain):** signature stripping/XSW/comment injection → assertion forgery logging you in as another user (ATO); RelayState open redirect → SSO token/code theft.

## Sources

OWASP WSTG SAML guidance, PortSwigger OAuth/OIDC research, and `auth-session.md`/
`openid.md` references.
