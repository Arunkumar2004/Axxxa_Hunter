# MFA / 2FA Bypass (mfa)

Defeating the second factor — brute force, reuse, workflow skip, response
tampering, device-trust abuse. Keep OTP/SMS volume minimal to avoid spamming real
users, and only probe code-entry with authorisation.

## Checklist
- Map the MFA flow: what pre-MFA state exists (a half-authenticated cookie/token), which endpoints are gated, and how the code is delivered (TOTP, SMS, email, push, backup codes).
- No rate-limit on code entry: attempt several OTP values and check for lockout/throttling (keep attempts minimal and only with authorisation) — unlimited tries means brute-forceable.
- Code reuse / non-expiry: a used OTP still accepted, a code valid long after issue, or the same code across sessions.
- Workflow skip: after the password step, go straight to the post-MFA endpoint/dashboard with the pre-MFA cookie — is MFA actually enforced server-side?
- Response manipulation: flip `{"success":false}`->`true` or `401`->`200` on the verify response to see whether the check is client-side only.
- Race on verification: submit the same OTP concurrently to bypass a single-use/rate check (link to race-condition).
- Backup-code weakness: short/low-entropy backup codes, no rate-limit, reuse after exhaustion, or predictable generation.
- "Remember this device" trust: capture the trust token and present it from another IP/UA — is device trust bound to anything?
- Enrolment/downgrade flaws: disable MFA or enrol a new factor without re-auth/old-factor confirmation; downgrade from TOTP to weaker SMS/email.
- Delivery abuse: OTP sent to an attacker-changeable phone/email, or the code leaked in the response/next-step payload.
- Direct object/endpoint: a verify-OTP endpoint that accepts another user's identifier (MFA on behalf of a victim).
- Confirm it yields access/ATO without the legitimate second factor; keep OTP/SMS volume minimal to avoid spamming real users.

## Bypasses
- Missing server-side enforcement: use the pre-MFA session directly against gated endpoints (workflow skip).
- Client-side-only verification defeated by response manipulation.
- No/weak rate-limit enabling OTP or backup-code brute force (and racing to beat the counter).
- OTP reuse/non-expiry and cross-session acceptance.
- "Remember device" token reuse across IP/UA, and MFA-skipping "remember me" cookies.
- Enrol/disable a factor without re-auth; downgrade to a weaker channel.

## Kill rules
- The code field is rate-limited/locks out and brute force is infeasible — no bypass.
- MFA is enforced server-side; the pre-MFA cookie is rejected on gated endpoints.
- The manipulated response does not actually grant access (the server re-checks) — client display only.
- OTPs are single-use and expire; replay/reuse is refused.
- "Remember device" is bound to a validated context and cannot be transplanted.
- The only effect is OTP spam/DoS on an excluding program, or the flow/host is out of scope.
