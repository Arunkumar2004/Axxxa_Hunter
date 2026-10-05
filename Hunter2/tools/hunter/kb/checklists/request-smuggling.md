# HTTP Request Smuggling / Desync (request-smuggling)

Front-end and back-end disagreeing on where one request ends, letting you queue
a prefix onto the next user's request. Needs a proxy chain and a reproducible
request-capture or routing effect.

## Checklist
- Confirm a front-end/back-end chain exists (CDN, load balancer, reverse proxy) — desync needs two servers disagreeing on request boundaries.
- CL.TE probe: send both `Content-Length` and `Transfer-Encoding: chunked`, crafted so the front-end uses CL and the back-end uses TE, leaving a prefix queued.
- TE.CL probe: the mirror case where the front-end honours TE and the back-end honours CL.
- TE.TE obfuscation: make one server ignore `Transfer-Encoding` via `Transfer-Encoding: xchunked`, a leading space, `chunked\r\n` duplication, or casing tricks.
- Timing-based detection: a CL.TE probe that leaves the back-end waiting for more body shows a measurable delay — the safe first signal.
- HTTP/2 desync: h2.CL / h2.TE where H2-to-H1 downgrade rewrites a request using an attacker-set length; test header injection and CRLF in h2 pseudo-headers.
- Confirm with the standard differential: issue the smuggled prefix, then a normal request, and show the next request is affected (e.g. a `404`/`405` landing on an unexpected victim request).
- Impact: capture another user's request (steal headers/cookies), bypass front-end access controls to a restricted path, or chain to cache poisoning for mass effect.
- Byte tuning: adjust CL/chunk-size counts carefully so the boundary splits exactly where intended.
- Client-side desync and browser-powered variants on HTTP/2 where applicable.
- Automate probes with PortSwigger's HTTP Request Smuggler methodology, but verify every hit by hand before claiming it.
- Operate carefully: smuggling can affect other live users — keep probes minimal, avoid poisoning shared state beyond a controlled proof, and stay in scope.

## Bypasses
- `Transfer-Encoding` obfuscation: leading space/tab, ` chunked`, duplicate TE headers, uppercase `CHUNKED`, `TE : chunked`, trailing `\r\n` tricks.
- Split the header across an HTTP/2-to-H/1 downgrade so the front-end never sees the TE the back-end honours.
- CL.0 and `Connection: keep-alive` tricks against servers that mishandle bodyless requests.
- Line-folding and bare `\n` (LF-only) line endings that one parser accepts and the other rejects.
- Vary byte counts and chunk-size terminators to hit parser-specific edge cases.

## Kill rules
- A one-off timing blip with no reproducible request-capture or routing effect — jitter, not desync.
- The front-end and back-end are the same server / no proxy chain — no two parsers to disagree.
- The probe only affects your own subsequent request, not another user's and not a protected resource.
- The smuggled prefix is normalised/rejected consistently — no actual boundary disagreement.
- The target explicitly excludes DoS and your only effect is connection disruption.
- The chain is a third-party CDN out of scope, or documented behaviour with no security impact.
