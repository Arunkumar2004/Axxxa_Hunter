# Real-World Playbook - Secrets and API-Key Exposure

**Class:** `secrets-leak` · **Coverage-matrix tier:** 3 · **Hunter2:** `/secrets-hunt` · `tools/sourcemap_extract.py` · `tools/secrets_hunter.sh` · **Skill:** web2-recon

**Route:** `web2-recon`/`cloud-security` -> `recon-agent`/`cloud-hunter` ->
`secrets_hunter.sh`, `sourcemap_extract.py`, git/source review -> scope/permission
verification -> validator/report-writer.

## Conditions

- A secret, token, private key, source map, debug response, repository, or artifact is reachable.

## Safe method

- Classify the value, scope, audience, expiry, and permission without using it against
  unrelated data.
- Verify with a harmless identity or provider introspection endpoint when authorized.
- Redact values immediately and request revocation through the program.

## Proof and rejection

- A string resembling a key is not proof; confirm format plus scoped validity.
- Reject expired, test-only, public, or unprivileged tokens as standalone findings.
- Never paste secrets into reports or commit them to Hunter2.

## Test flow / checklist — do these in order
*(public methodology — HowToHunt / HackTricks / TruffleHog+gitleaks method / PayloadsAllTheThings; run each, mark result in the coverage matrix)*

[ ] Pull and scan JS bundles, source maps (`.map`), and inline scripts for keys/tokens/endpoints
[ ] Extract source via `sourcemap_extract.py` to recover original files and comments
[ ] Search exposed git (`/.git/`), backups (`.bak`/`.old`/`.zip`), and config files (`.env`, `web.config`, `application.properties`)
[ ] Grep responses/HTML/headers for high-entropy strings and known key formats (AWS `AKIA`, Google `AIza`, Slack, Stripe, JWTs, private keys)
[ ] Search the org's public repos, gists, and commit history for committed secrets
[ ] Classify each hit: provider, scope, audience, expiry, and privilege level
[ ] Verify validity harmlessly via a provider introspection/whoami endpoint when authorized (never against unrelated data)
[ ] Determine blast radius — what does the key access, and is that asset in scope?
[ ] Redact the value immediately; never paste it into the report or commit it to Hunter2
[ ] Report the leak location plus scoped-validity proof and request revocation through the program

## What gets this rejected (kill before you write)
*(from `skills/triage-validation/SKILL.md` — one wrong answer = kill it and move on)*

- A string that resembles a key but is expired, revoked, test-only, public/publishable, or unprivileged.
- A high-entropy value with no confirmed provider/format or scoped validity.
- Client-side "secrets" meant to be public (publishable API keys, OAuth `client_id`, reCAPTCHA site keys).
- OAuth `client_secret` in a mobile app (known, expected).
- Secrets for third-party assets the company does not own / out of scope.
- Pasting real secrets into a report or committing them anywhere.
- **Conditionally valid (only WITH a chain):** leaked key → authenticated API abuse / data access; source-map or JS leak → API keys or OAuth secrets enabling account or infra access.
