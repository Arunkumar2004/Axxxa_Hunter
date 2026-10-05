# Web Cache Poisoning and Deception (cache-poisoning)

Getting a shared cache to store an attacker-influenced or another user's private
response, then served to others. Prove persistence and cross-user blast radius.

## Checklist
- Identify a cache in front of the app: `X-Cache`, `Age`, `CF-Cache-Status`, `Via`, `X-Served-By` headers, and cacheable 200 responses.
- Find unkeyed inputs: headers/params that influence the response but are not part of the cache key (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `X-Forwarded-For`, custom headers).
- Reflect-and-store test: send an unkeyed header with a canary value, confirm it is reflected in the body, then confirm a subsequent clean request (same key) returns the poisoned body (cache HIT).
- Use Param Miner-style header/parameter discovery to enumerate unkeyed inputs quickly, then verify by hand.
- Poison targets: reflected `X-Forwarded-Host` into an absolute resource URL or redirect (loads attacker JS), into an open redirect, or into a `<meta>`/`<link>`.
- Cache deception: request a victim's private page with a static-looking suffix (`/account/settings/foo.css`, `/account;.css`, `/account%2f..%2fx.css`) so the cache stores the private response under a path the attacker can then fetch.
- Fat-GET / method and parameter cloaking: a body on a GET, or a duplicate/extra parameter the cache ignores but the origin honours.
- Cache-key normalisation gaps: case, trailing slash, path params, double slashes, and encoded characters that collapse to the same key but different origin behaviour.
- DoS-via-cache (report cautiously): poison an unkeyed header to force an error page to be cached for all users.
- Confirm persistence and blast radius: show the poisoned entry served to a different client, and the TTL/`Age`, to prove other users are affected.
- Clean up: use a unique path/param for the proof so you do not persistently poison a production page beyond the demonstration.

## Bypasses
- Unkeyed header variety: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL`, `X-Host`, `Forwarded`.
- Cache-key confusion: differing case, trailing slash, `;`-params, double slashes, and encoded path segments that normalise to a cached key.
- Deception suffixes: `.css`/`.js`/`.png` appended, `%2f`/`%2e%2e` path confusion, `;`-delimiter, and path-parameter tricks.
- Fat GET (GET with a body) and parameter cloaking (duplicate keys) where cache and origin disagree on what is significant.
- Header value tricks (CRLF, port, scheme) that change the origin response while the key stays constant.

## Kill rules
- The reflected value is never actually cached (always MISS / `Cache-Control: private`) — reflection, not poisoning.
- Only your own requests see the poison (keyed on your cookie/session) — no cross-user effect.
- The unkeyed input reflects into a non-executed, non-security context (plain text, encoded) with no redirect/script.
- The cache stores it but TTL is effectively zero / immediately revalidated — no real window.
- The deception path is served with `Cache-Control: no-store` or a correct `Vary` — private data not cached.
- The affected cache/host is third-party/out of scope, or the only effect is DoS on an excluding program.
