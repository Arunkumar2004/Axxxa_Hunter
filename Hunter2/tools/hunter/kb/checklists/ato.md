# Account Takeover (ato)

Usually the outcome of chaining a primitive below. Prove you can control a
victim's account, ideally without their interaction; rank by the interaction
required (no-interaction is critical).

## Checklist
- Password-reset poisoning: request a reset with `Host`/`X-Forwarded-Host: attacker.com` and check whether the emailed link points to your host, leaking the token (link to host-header).
- Reset-token weaknesses: predictable/short tokens, no expiry, reuse, not invalidated after use, or multiple valid tokens — brute or reuse to reset a victim's password.
- Reset-token leakage: the token in a URL leaking via Referer to third-party scripts/analytics, in the response body, or in a redirect.
- Email/phone change without re-auth: change the account email to yours without current password/MFA, then reset — direct ATO.
- Unverified email / pre-account-takeover: register a victim's email before they do (or via SSO) so their later login lands in your account; or link OAuth identities across unverified emails.
- IDOR on account fields: set another user's email/password/phone via a cross-account write (link to idor-bola) — the highest-value IDOR.
- OAuth/SSO ATO: a loose `redirect_uri`/missing `state`/PKCE to capture a victim's code (link to oauth), or id_token confusion.
- JWT/session forgery: forge or reuse a token to impersonate (link to jwt and auth-session); a session not invalidated on password change.
- MFA bypass to complete the takeover without the second factor (link to mfa).
- Response/logic manipulation in the reset or login flow (client-side success, step skip).
- Credential-stuffing/brute enablement: missing rate-limit/lockout turning weak-password guessing into ATO (respect scope, avoid real users).
- Prove the takeover end-to-end on an account you control as the "victim", capture before/after, and rank by interaction required.

## Bypasses
- Host/`X-Forwarded-Host` poisoning of the reset link to capture the token.
- Reset-token brute/reuse where tokens are short, long-lived, or not single-use.
- Referer/response/redirect leakage of the token to an attacker-observable channel.
- Email-change or MFA-disable without re-auth to pivot into a reset.
- Pre-registration / OAuth account-linking on unverified emails.
- Cross-account write (IDOR) to the email/password field, and token forgery (JWT/session).

## Kill rules
- The reset link always uses a canonical domain and the token never reaches the attacker — no poisoning.
- Reset tokens are high-entropy, single-use, short-lived, and invalidated on use — not brute/reusable.
- Email/sensitive changes require current password or MFA — no silent pivot.
- The IDOR on account fields only edits your own account (no victim write).
- You can demonstrate control only of your own account, not a victim's.
- The takeover requires credentials/secrets you were legitimately given, or the account/host is out of scope.
