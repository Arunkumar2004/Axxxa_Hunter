# Authentication and Session Management (auth-session)

Weaknesses in how sessions are issued, carried, and invalidated, and in the login
flow itself. A missing cookie flag alone is low; prove a session compromise or
auth bypass.

## Checklist
- Session cookie hygiene: check `HttpOnly`, `Secure`, `SameSite`, domain/scope, path, and lifetime; a session cookie missing `HttpOnly`/`Secure` is weak (chain with XSS/MitM).
- Logout invalidation: after logout, replay a captured session token/JWT — if it still works, logout is cosmetic.
- Session fixation: set/know a session before login, authenticate, and check whether the same identifier is retained (attacker can pre-seed it).
- Concurrent/stale sessions: does changing the password invalidate other sessions? Are old tokens revoked?
- Predictable/weak identifiers: analyse session ids/tokens for low entropy, sequential, or time-based patterns.
- Credential handling: login rate-limiting and lockout, username enumeration via differential responses/timing on login and reset, and password-policy weaknesses.
- "Remember me"/persistent tokens: entropy, storage, revocation, and whether they bypass MFA.
- Cookie-scope and subdomain issues: a session cookie scoped to `.target.com` exposed to a vulnerable subdomain (chain with takeover/XSS).
- Re-authentication for sensitive actions: is current-password/MFA required to change email/password/MFA (overlaps with ato)?
- Token transport: session tokens in URLs (referrer leak), in localStorage (XSS-exposed), or reflected in responses.
- Multi-factor and step-up coverage of the session (link to the mfa checklist).
- Confirm a concrete session compromise or auth bypass (reuse after logout, fixation leading to victim-session access), not just a missing flag.

## Bypasses
- Reuse a token after logout/expiry where server-side revocation is absent.
- Pre-seed a known session id (fixation) that survives authentication.
- Exploit a `.target.com`-scoped cookie via a subdomain XSS/takeover to read or set it.
- Username enumeration via a differential error/timing to build a target list.
- Race the login/reset rate-limiter (link to race-condition) to brute credentials/OTP.
- Downgrade to a flow (legacy endpoint, mobile API) that issues weaker/longer-lived sessions.

## Kill rules
- A missing cookie flag (`HttpOnly`/`Secure`/`SameSite`) with no demonstrated exploitation path — low/informational on its own.
- Logout actually invalidates the token server-side and the replay fails.
- Session ids are high-entropy and random; the "pattern" is not predictable.
- Username enumeration where the site intentionally reveals existence (public usernames) and rate-limits.
- The weakness affects only the attacker's own session with no victim impact.
- The auth system/host is out of scope.
