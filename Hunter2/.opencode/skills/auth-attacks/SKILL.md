---
name: auth-attacks
description: Use when hunting authentication/authorization bugs - login, register, password reset, OAuth/OIDC/SSO/SAML, MFA/2FA, session management, JWT, account takeover chains, or when the user says "auth", "login", "reset", "OAuth", "SAML", "2FA", "MFA", "session", "JWT", "account takeover". Covers the highest-value auth attack classes with test checklists.
---

# Authentication & Authorization Attacks

Auth bugs are the highest-value class on most programs. Most real bugs: password reset, OAuth flows, MFA bypass, session handling, JWT.

## 1. Password Reset Flow (gold mine)

- **Token in URL/email**: `?token=...` — is it returned in response? Referer leak? Predictable (timestamp, incremental, `md5(email)`, short 6-digit)?
- **Response/status oracle**: does reset send `200` for valid and `404` for invalid email → enumeration.
- **Token reuse**: use the same token to reset 2 accounts (race or re-use before invalidation).
- **Token fixation**: request reset for victim, but token issued to attacker session (Host header poisoning — reset link generated with attacker-controlled host: `Host: attacker.com` → email link goes to attacker).
- **User param tampering**: reset by `email=victim@x.com` but change `user_id` to your account → password reset for victim while link goes to you.
- **Unverified email change**: change email field in reset request to attacker's email.
- **No rate limit** on token brute-force (6-digit = 1M; test carefully).

## 2. OAuth / OIDC / SSO / SAML

- **state CSRF**: login CSRF / account linking via missing `state`.
- **redirect_uri**: `https://app.com/callback` → `https://app.com.evil.com`, `//evil.com`, path-based `https://app.com/callback?redirect=...` — open redirect → token leak.
- **scope escalation**: request `scope=admin`, modify scope in request.
- **code exchange**: replay authorization code, use code from another client, `code` in query → referrer leak.
- **IdP confusion**: signature not verified (`alg:none`), `aud` not checked, `iss` confusion (craft IdP token with same secret), `kid` traversal.
- **SAML**: XML signature wrapping (Wrapping/XSW), `alg`/`digest` substitution, `assertion` not signed but response signed, `InResponseTo` missing (CSRF), duplicate assertion IDs.

## 3. MFA / 2FA

- **Response manipulation**: `{"otp":"123456","2fa":true}` → set `"2fa":false`; change `success:false` to `true`; intercept and strip the 2FA step.
- **Skip endpoint**: `POST /2fa/verify` → try `/login` directly with password, mobile app API may skip OTP entirely.
- **Backup codes**: reuse, unlimited tries, predictable.
- **OTP brute-force**: 4-6 digits, no rate limit → brute (report, don't actually crack).
- **OTP reuse**: verify OTP, then re-verify same OTP for another account (race).
- **Session persistence**: after 2FA, old session still valid (no session invalidation on MFA enable).

## 4. Session Management

- **Session fixation**: pre-login session ID survives login; set `PHPSESSID=attacker` then victim logs in.
- **No rotation**: session ID unchanged after login/role change.
- **Logout not server-side**: logout just clears client cookie → old session still works.
- **Session in URL/Referer**: `?sid=` leaks.
- **Cookie flags**: `Secure`/`HttpOnly`/`SameSite` missing; `SameSite=None` without `Secure`.
- **Role change in session**: change `role` claim in JWT/cookie → admin (test with own account only).

## 5. JWT (see also jwt-scan)

- `alg:none`, `HS256` with public key, weak secret (`jwt_scanner.py --crack`), `kid` path traversal (`kid=../../../../dev/null`), `jku`/`x5u` remote key, `crit` header injection, claim tampering (`role`).
- Algorithm confusion: RS256→HS256 with the server's RSA public key as HMAC secret.

## 6. Account Takeover Chains (the combo bugs)

- Open redirect → OAuth token leak → ATO.
- Host header injection → password reset link poisoning → ATO.
- CORS misconfig + stored XSS → token theft → ATO.
- IDOR on user profile (email/phone) → change victim's email → ATO.
- Rate-limit bypass + username enum → credential stuffing.
- Report the **chain**, not the parts.

## Tools

```
python tools/jwt_scanner.py <token>            # JWT attacks
python tools/h1_oauth_tester.py                # OAuth flow tests
python tools/cors_scanner.py <url>             # CORS misconfig
bash   tools/bypass_403.sh <url>               # auth bypass on protected endpoints
python tools/auth_session.py                   # auth-session management
python tools/validate.py "<finding>"
```

## Validation

- ATO = CONFIRMED only if you can prove full account control (reset + login) on **your own or approved** account.
- MFA bypass = CONFIRMED only if you actually get in without OTP (own account).
- Token/OTP brute = POSSIBLE → report with evidence of no rate limit (don't actually brute).
- Never test against accounts you don't own; never lock out users.

## References

- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OAuth 2.0 Security Best Practices (RFC 9700): https://datatracker.ietf.org/doc/html/rfc9700
- HackTricks OAuth/SAML: https://book.hacktricks.wiki/en/pentesting-web/oauth-2-0-oauth-1-0a
- jwt_tool: https://github.com/ticarpi/jwt_tool
