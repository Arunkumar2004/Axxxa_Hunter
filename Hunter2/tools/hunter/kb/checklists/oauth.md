# OAuth 2.0 / OIDC Flaws (oauth)

Flaws in the authorisation flow — redirect_uri validation, state, PKCE, code
handling, account linking — that let you steal a victim's code/token or take over
an account. Prove a real takeover/impersonation, not just an odd redirect.

## Checklist
- Map the flow: client_id, response_type (code/token/id_token), scopes, `redirect_uri`, `state`, `nonce`, PKCE usage, and which endpoints issue/exchange the code.
- `redirect_uri` validation: test unregistered URIs, path/subdomain additions (`/callback/../evil`, `cb.target.com.evil.com`), an open redirect on an allowlisted host, and suffix/prefix matching gaps.
- Redirect-URI-to-code-theft: if a loose `redirect_uri` or a chained open redirect sends the `code`/token to your host, you capture the victim's authorisation (ATO).
- `state` parameter: missing/not-validated `state` = OAuth CSRF (force-link an attacker account or complete a flow in the victim's session).
- PKCE enforcement: start a flow without `code_challenge`; if the server still issues/accepts a code, authorisation-code interception is possible.
- Code reuse/expiry: replay an authorisation code twice, after expiry, or across clients; codes must be single-use and short-lived.
- Implicit/token leakage: tokens in the URL fragment leaking via Referer, history, or an open redirect; `response_mode` manipulation.
- Scope abuse: request extra scopes, or downgrade/confuse scopes; check whether consent is re-prompted for elevated scopes.
- Account linking / pre-account-takeover: link your OAuth identity to a victim's email, or register before the victim so their SSO lands in your account; email-not-verified trust.
- `id_token` validation (OIDC): signature, `aud`, `iss`, `nonce`, and `alg` (reuse the jwt checklist on the id_token).
- Cross-client/mix-up: use a code/token issued for one client with another, or an IdP mix-up attack.
- Confirm a concrete ATO/impersonation or token theft in the victim's session, not just a quirky redirect.

## Bypasses
- `redirect_uri` tricks: an open redirect on a trusted host, path traversal, an added subdomain/suffix, `@`/`#`/backslash parser confusion, double-encoding.
- Missing/weak `state` to mount OAuth CSRF/forced-login.
- Dropping `code_challenge` (PKCE downgrade) and reusing authorisation codes.
- Referer/fragment leakage of tokens via an injected third-party resource or redirect.
- Email-verification gaps for account linking / pre-takeover.
- id_token `alg`/`aud`/`iss` confusion (see the jwt bypasses).

## Kill rules
- `redirect_uri` is strictly matched and every variant is rejected — no code/token exfiltration.
- `state` is validated (the flow fails on mismatch) — no OAuth CSRF.
- The authorisation code is single-use and short-lived; replay is refused.
- You can redirect somewhere odd but no `code`/token or victim session is actually captured.
- Account linking requires verified email and re-auth — no pre-takeover.
- The IdP/client/host is third-party or out of scope.
