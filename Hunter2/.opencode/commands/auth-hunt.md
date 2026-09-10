---
description: Auth/account-takeover hunt - password reset, OAuth/OIDC/SAML, MFA bypass, JWT, session bugs, ATO chains. Usage: auth-hunt <base-url> [--flow reset|oauth|mfa|jwt|session]
---

# /auth-hunt

Hunt authentication and account takeover bugs.

## Run This

```bash
# JWT analysis (alg:none, confusion, crack):
python tools/jwt_scanner.py <token> --crack wordlists/common.txt

# OAuth flow tests (state, redirect_uri, scope, code reuse):
python tools/h1_oauth_tester.py <base-url> --client-id <id> --redirect-uri <uri>

# CORS (part of many ATO chains):
python tools/cors_scanner.py <base-url>

# Password reset flow: check token in URL/response, predictability, reuse, user_id tampering, Host header poisoning (manual, own accounts)
# MFA: response manipulation (2fa:false), skip endpoint, OTP brute rate limit (report only)
# Session: fixation, no rotation, no server-side logout, cookie flags
```

## Workflow

1. Map auth flow (register → login → reset → MFA → session).
2. Reset flow: token leakage (URL/Referer), enumeration oracle, reuse, Host header poisoning, user_id tamper.
3. OAuth: `state` missing, `redirect_uri` open redirect, scope escalation, code replay.
4. JWT: `jwt_scanner.py` full suite.
5. MFA: response manipulation, skip, OTP brute-force rate limit (report, don't brute).
6. Chain: open redirect + OAuth → ATO; Host header + reset → ATO; CORS + XSS → ATO. **Report the chain.**

## Rules

- Only test on accounts you own; never lock out real users.
- ATO = CONFIRMED only with full account control proof on your own account.
- No credential stuffing/spraying here — use `spray` command with human go/no-go.

## Output

`findings/<target>/auth-<date>.md`; validate each; lead board route `auth`.
