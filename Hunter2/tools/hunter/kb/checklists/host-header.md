# Host Header Injection (host-header)

The app trusting an attacker-controlled Host (or forwarded-host) when building
links, redirects, or cache keys. Highest impact is password-reset poisoning.

## Checklist
- Identify flows that build absolute URLs from the request Host: password-reset/verification emails, absolute redirects, canonical/`<base>` tags, and cache keys.
- Change `Host:` to an attacker domain and observe whether it is reflected into links, redirects, or email contents.
- Password-reset poisoning (high impact): request a reset for a victim with `Host: attacker.com` (or `X-Forwarded-Host: attacker.com`) and check whether the reset link points to your domain, leaking the token.
- Use `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `Forwarded`, and duplicate `Host` headers when the raw Host is validated but a forwarded variant is trusted.
- Absolute-redirect abuse: a login/redirect that uses the Host to build `Location` -> open redirect / credential theft.
- Web-cache poisoning via Host/forwarded-host reflected into a cached response (link to cache-poisoning).
- Routing/virtual-host confusion: a spoofed Host that reaches an internal vhost or a different tenant.
- SSRF/authentication bypass where an internal service trusts the Host for routing or access decisions.
- Confirm the token/link actually reaches the attacker-controlled host (use a collaborator and verify the inbound request carries the secret).
- Bound it: trigger resets only for accounts you control; never harvest real users' reset tokens.

## Bypasses
- Forwarded-host family: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `Forwarded: host=`, `X-Original-Host`.
- Duplicate `Host` headers (two values) so validation reads one and URL-building reads the other.
- Host with port or userinfo (`victim.com:@attacker.com`, `victim.com.attacker.com`) to pass a prefix check.
- Absolute URL in the request line while keeping a benign `Host` header.
- Line-wrapping or `\n` in the Host on tolerant stacks, and a trailing-dot FQDN.

## Kill rules
- The Host is reflected but into a non-security context (a logged value, non-clickable text) with no token/redirect/cache effect.
- Reset emails use a hard-coded/canonical domain regardless of Host — no poisoning.
- The spoofed Host is validated and rejected (400/invalid host) on every variant including forwarded headers.
- Only your own reset link changes and no secret reaches the attacker host.
- The redirect built from Host is to a same-site path only / safely encoded.
- The host or host-routing target is out of scope.
