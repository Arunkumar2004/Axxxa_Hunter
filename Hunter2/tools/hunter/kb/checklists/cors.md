# CORS Misconfiguration (cors)

A cross-origin policy that lets an attacker page read a victim's credentialed
responses. It only pays when it exposes sensitive, authenticated data.

## Checklist
- Find authenticated, data-returning endpoints (profile, settings, API-key, messages) — CORS pays only when it exposes credentialed, sensitive responses.
- Send `Origin: https://evil.com` and read `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC) in the response.
- Reflected-origin + credentials: ACAO echoes your arbitrary Origin AND ACAC is `true` -> an attacker page can read the victim's credentialed response (critical).
- `null` origin: send `Origin: null` (sandboxed iframe, `data:` document) and check whether ACAO becomes `null` with credentials.
- Suffix/prefix trust: test `https://target.com.evil.com`, `https://evil-target.com`, `https://eviltarget.com`, and `https://nottarget.com` to find weak substring matching.
- Subdomain trust chain: if any `*.target.com` is reflected and you can get XSS/takeover on a subdomain, the CORS trust becomes exploitable.
- Scheme/port handling: an `http://` origin accepted for an `https://` site, or non-standard ports, indicating a loose matcher.
- Pre-flight behaviour: inspect the `OPTIONS` response for over-permissive `Access-Control-Allow-Methods`/`-Headers` and whether it gates anything.
- Verify exploitability: build a minimal cross-origin `fetch(..., {credentials:'include'})` PoC that reads a concrete piece of the victim's data.
- Distinguish wildcard-without-credentials (`ACAO: *`, no ACAC): browsers forbid credentialed reads, so low impact unless the data is already public.
- Confirm the endpoint actually returns sensitive data to the victim's session, not a generic/public payload.

## Bypasses
- Arbitrary-origin reflection: the server copies whatever `Origin` you send into ACAO.
- `null` origin via a sandboxed iframe or a `data:`/`about:blank` document.
- Weak regex/substring matching: `target.com.evil.com`, `eviltarget.com`, `nottarget.com`, or an unescaped `.` in the allow regex.
- Trusted-subdomain pivot: exploit CORS by first getting script execution on an allowlisted `*.target.com`.
- Scheme/port confusion where `http`/alternate ports are mistakenly trusted.
- Pre-flight bypass on simple requests (GET/POST with simple headers) that skip `OPTIONS` entirely.

## Kill rules
- ACAO reflects an origin but ACAC is absent/false AND the endpoint needs credentials — the browser blocks the read, so no data leaks.
- `Access-Control-Allow-Origin: *` on public, non-credentialed data — working as intended.
- The endpoint returns nothing sensitive / only the same data an anonymous user already gets.
- Reflection happens only for the site's own origins (no attacker origin accepted).
- You cannot produce a working cross-origin read PoC (pre-flight or SameSite cookies block it).
- Cookies are `SameSite=Strict`/`Lax` so the credentialed cross-site request carries no session.
