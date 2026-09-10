---
description: Open a real browser to a target login page; you log in manually (email/password/OTP/MFA typed into the actual site, never into chat) and the tool auto-detects success and captures the session cookie/token into .private/<target>.json (AuthSession format). Usage: /login-capture <login-url> [--name target]
---

# /login-capture

Get the hunt behind the login wall. Opens a real browser; you authenticate
manually on the actual site; the tool detects login success and writes the
captured session to `.private/<target>.json`, which every other tool loads via
`--auth-file`.

## Usage

```bash
tools/login_capture.py https://target.com/login
tools/login_capture.py https://target.com/login --name acme --out .private/
```

Then hunt authenticated:

```bash
tools/hunt.py target.com --auth-file .private/target.com.json
```

## How it works

1. Launches headed Chromium at the login URL.
2. You log in by hand — credentials, OTP, MFA, SSO all go into the browser, never
   into this tool or the chat.
3. Auto-detects success (URL leaves the login path + a session cookie appears, or
   a JWT/token shows up in localStorage). Press Enter to confirm manually anytime.
4. Captures cookies + SPA bearer token, writes `.private/<target>.json` (chmod 600
   on POSIX; the dir is gitignored).

## Security

Passwords are entered into the target site only. This tool reads the resulting
session material (the point of the capture) — it never records keystrokes or
credentials. Requires Playwright (`pip install playwright && playwright install
chromium`); if absent it prints how to paste a cookie manually.

## Hunt integration

When a hunt hits a login wall (auth-required responses on the primary surface),
pause, run `/login-capture <login-url>`, then resume with
`--auth-file .private/<target>.json`. Most paying bugs live behind auth.
