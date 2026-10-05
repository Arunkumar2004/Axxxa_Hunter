# Clickjacking / UI Redressing (clickjacking)

Framing a target page so a victim's click lands on a sensitive control. Pays only
when a framable page has a real single-click sensitive action and the session is
carried in the framed context.

## Checklist
- Identify sensitive single-click state-changing actions: delete account, change email/password, transfer, OAuth "Approve", disable MFA, confirm purchase.
- Check framing defences on those pages: `X-Frame-Options` (DENY/SAMEORIGIN) and CSP `frame-ancestors`; absence or `ALLOWALL`/wildcard means framable.
- Build a framing PoC: embed the target in an `<iframe>` and confirm it renders (not blank/blocked) in a current browser.
- Overlay/opacity attack: position a decoy UI under a transparent (`opacity:0`) iframe so the victim's click lands on the sensitive control.
- Verify the action completes: the framed click must actually perform the sensitive operation (not merely focus), using the victim's logged-in session.
- Cookie context: confirm the session cookie is sent in the framed cross-site context (`SameSite=None`/absent) — otherwise the frame is unauthenticated.
- Drag-and-drop / multi-step variants and "fill then submit" where several aligned clicks are needed.
- Mobile/touch considerations: a tap-target overlay works similarly; test viewport sizes.
- Distinguish framable-but-harmless pages (no sensitive single-click action) from genuinely exploitable ones.
- Produce a concrete PoC HTML that performs the action, and note whether a confirmation dialog or re-auth neutralises it.

## Bypasses
- Missing/weak headers: no `X-Frame-Options`, no CSP `frame-ancestors`, or `ALLOW-FROM`/wildcard misconfigurations.
- `frame-ancestors` that lists an attacker-controllable or overly broad origin.
- Nested/double framing and sandboxed iframes to defeat some frame-busting JS.
- Partial overlay so only the sensitive button is exposed through a transparent region.
- `SameSite=None`/absent cookies that keep the framed session authenticated.

## Kill rules
- The page sets `X-Frame-Options: DENY/SAMEORIGIN` or CSP `frame-ancestors 'self'`/'none' — not framable.
- The framable page has no sensitive single-click action (pure content/marketing) — no impact.
- The sensitive action requires a confirmation step, re-auth, or CSRF token that framing cannot satisfy.
- Session cookies are `SameSite=Strict`/`Lax`, so the framed cross-site action is unauthenticated.
- Only a theoretical frame with no demonstrated state change.
- The program explicitly rates clickjacking on that page as out of scope/informational.
