# CRLF Injection / HTTP Response Splitting (crlf)

Injecting carriage-return/line-feed into a value reflected in response headers,
letting you add headers, set cookies, or split the response. Prove impact beyond
a single injected header.

## Checklist
- Find inputs reflected into response headers: redirect `Location`, `Set-Cookie`, custom headers, caching headers, and anything echoed into the response header block.
- Inject encoded CRLF: `%0d%0a`, `%0D%0A`, and single `%0a`/`%0d`; also `%E5%98%8A%E5%98%8D` (unicode that normalises to CR/LF on some stacks).
- Confirm a new header lands: inject `%0d%0aX-Injected: hunter` and verify it appears as a distinct response header.
- Set-Cookie injection: `%0d%0aSet-Cookie: session=attacker` to fix or overwrite a cookie (session-fixation chain).
- Open-redirect/location abuse: break the `Location` header to add your own, or split into a body.
- Response splitting to reflected XSS: `%0d%0a%0d%0a<html>...<script>...` to craft a second response body where the stack allows a full split.
- Cache-poisoning chain: a CRLF-injected header that gets cached affects other users (link to the cache-poisoning checklist).
- Header injection into back-end requests: CRLF in a value the server forwards (SSRF/host contexts, log injection).
- Test query, path and body reflection points, plus headers the app copies (`Referer`, `User-Agent`, `X-Forwarded-*`).
- Confirm impact beyond a reflected header: cookie set, redirect hijack, XSS, or cache poison — a lone injected header is usually low on its own.

## Bypasses
- Encoding variants: `%0d%0a`, `%0a`, `%0d`, double-encoded `%250d%250a`, and mixed-case hex.
- Unicode/overlong CR-LF (`%E5%98%8A`/`%E5%98%8D`) that normalises to `\r`/`\n` after a transform.
- Inject only `%0a` where the server tolerates LF-only line endings.
- Place the payload in a header the app reflects (`Referer`, `X-Forwarded-Host`) rather than the obvious redirect param.
- Combine with a path/param the front-end rewrites so the CRLF survives to the origin.

## Kill rules
- The CR/LF is stripped, URL-encoded in output, or rejected — no real header break.
- An extra header is injected but it has no security effect (no cookie, no redirect, no cache, no body split).
- A modern server collapses the split and prevents a second response — no XSS via splitting.
- The reflection is into the body only (that is XSS, triage there), not into headers.
- Only your own response is affected with no cache or cross-user path.
- The endpoint/host is out of scope.
