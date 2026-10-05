# Open Redirect (open-redirect)

A redirect parameter that sends users to an arbitrary external origin. Low on its
own on many programs; valuable chained into OAuth token theft or phishing.

## Checklist
- Find redirect parameters: `redirect`, `url`, `next`, `return`, `returnUrl`, `dest`, `destination`, `continue`, `goto`, `rurl`, `callback`, `checkout_url`, and post-login/logout `returnTo`.
- Baseline: set the param to your external domain and follow the response; a 3xx `Location` (or JS/meta redirect) to your domain confirms it.
- Distinguish header redirect (`Location:`) from client-side (`window.location`, `<meta http-equiv=refresh>`) — both count, test both.
- Absolute URL acceptance: `https://evil.com`, protocol-relative `//evil.com`, and `https:/evil.com` / `https:evil.com`.
- Allowlist/prefix bypasses: `https://target.com.evil.com`, `https://evil.com/target.com`, `https://target.com@evil.com`, `https://target.com%2f@evil.com`.
- Parser confusion: backslashes `https:\\evil.com`, `/\evil.com`, `//\evil.com`, whitespace/control chars, and `#`/`?` fragment tricks `https://target.com#@evil.com`.
- Encoding: single and double URL-encoding of `/`, `:` and the whole URL (`%2f%2fevil.com`, `%252f%252fevil.com`).
- Dangerous schemes where the sink allows them: `javascript:alert(1)` (redirect-to-XSS), `data:text/html,...`.
- Chaining: use the redirect as the `redirect_uri` in an OAuth flow to steal the code/token, or build a phishing link that starts on the trusted domain.
- Confirm the final navigation truly lands on the attacker origin (not an interstitial warning that blocks it), and note whether a warning page neutralises it.

## Bypasses
- Protocol-relative and scheme tricks: `//evil.com`, `https:/evil.com`, `\/\/evil.com`, `https:\\evil.com`.
- Allowlist defeat via `@` userinfo, subdomain (`target.com.evil.com`), path prefix (`evil.com/target.com`), and `target.com@evil.com`.
- Encoding layers: URL-encoded and double-encoded separators, and CR/LF/whitespace injection in the value.
- Fragment/`?` abuse: `https://target.com#@evil.com`, `https://target.com?x=.evil.com`.
- IDN/unicode homoglyph domains and full-width characters to look like the target.
- Backslash normalisation that browsers turn into `/` after a server-side check.

## Kill rules
- The redirect only ever goes to same-site/relative paths; external URLs are rejected or stripped to a path.
- An interstitial "you are leaving" warning requires user action and the program treats that as safe.
- The value is reflected but navigation never occurs (no `Location`, no client redirect).
- Only `javascript:`/`data:` is reached but the context neutralises it (and that is really XSS — triage there).
- A bare open redirect with no chain on a program that explicitly rates it informational.
- The parameter/host is out of scope.
