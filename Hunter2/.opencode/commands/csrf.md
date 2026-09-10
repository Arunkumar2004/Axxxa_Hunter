---
description: Scan a page for CSRF - extracts state-changing forms and checks for anti-CSRF tokens and SameSite cookie protection. Usage: /csrf <url> [--cookie "session=..."] | /csrf -l urls.txt
---

# /csrf

Find state-changing forms an attacker page can forge in the victim browser.
Parses HTML forms, checks for anti-CSRF tokens, and inspects Set-Cookie
`SameSite` (the browser-side defence).

## Usage

```
/csrf https://target.com/account
/csrf https://target.com/account --cookie "session=abcd"
/csrf -l recon/target.com/urls/authed.txt --json
```

Run directly:

```bash
tools/csrf_scanner.py https://target.com/account --cookie "session=..."
```

## Severity

- **HIGH** - state-changing form, no anti-CSRF token, no SameSite protection.
- **MEDIUM** - no token but SameSite=Lax (bypassable via top-level GET->POST / method-override).
- **LOW** - token present but static/predictable, or GET-based state change.
- **INFO** - token + SameSite; confirm the server rejects a removed/altered token.

## Confirm the bug

A flagged form is a candidate. Confirm by replaying the request cross-site with
the token removed/altered and a live session - if the state change still
succeeds, it is a real CSRF. Pass `--cookie` to analyse authenticated pages.

## Chain

CSRF on an email/password change -> account takeover. CSRF on a role field ->
privilege escalation.
