# IDOR / BOLA — Broken Object-Level Authorisation (idor-bola)

Accessing or modifying another user's object by supplying its identifier when
the server fails to check ownership. Impact is proven by cross-account data, not
by a 200 status.

## Checklist
- Enumerate object-referencing inputs across the surface: path ids (`/api/orders/1024`), query ids (`?invoice=2024-55`), JSON body fields (`{"user_id":...}`), headers/cookies (`X-Account-Id`), and base64/UUID handles; prefer endpoints that read or mutate data.
- Establish two accounts you control, A (attacker) and B (victim), and where roles exist a low-priv and a high-priv identity; act as B to capture B's real object ids.
- Baseline as A: record status, body length and a content fingerprint for A's own object, so classification is by response diff rather than status code alone.
- Cross-account READ: replay A's request with A's token but B's id; returning B's data (not A's, not a generic error) is the finding — confirm the record is genuinely B's.
- Cross-account WRITE / tamper (BOLA write): repeat the id swap on `PUT`/`PATCH`/`POST`, change a field, re-read the object as B to confirm the change landed, then auto-revert to the captured original.
- Method swap / BFLA overlap: if `GET` is authorised but `DELETE`/`PUT`/`PATCH` is unchecked, try the state-changing verbs on B's id.
- ID mutation sweep: numeric +/-1, zero-pad, int<->string, negative/zero, very large values; UUID nibble-flip, or an id harvested from an invite/listing endpoint.
- Encoded-id decode: base64/hex/md5-wrapped ids — decode, change the inner value, re-encode (`GET /user/dmljdGlt` -> decode -> victim).
- Parameter pollution: duplicate the id (`?id=A&id=B`, JSON `{"id":A,"id":B}`) and swap order, since back-ends differ on which value wins.
- Wrapper mutation: send the id as an array `{"id":[B]}` or nested object `{"id":{"id":B}}` to dodge a shallow equality check.
- Add the id where it is normally implicit: an endpoint that reads "my" object from the token may honour an added `?user_id=B`.
- Alternate representations: append `.json`/`.xml`/`.csv`, change `Content-Type`, or hit an older API version (`/v1` vs `/v3`) that lacks the check.
- Sibling / indirect objects: export, print, share-link, thumbnail, attachment and download endpoints often skip the check the primary read enforces.
- GraphQL `node(id:)` and batched queries that resolve an opaque global id straight to the object, bypassing per-field authorisation.
- Predictable-id recon: create several objects, infer the allocation pattern (sequential, timestamp, short random), then target B's range.
- Anon-access guard: re-run the winning request with NO auth header; if it still returns the data it is missing authentication (a different, usually lower bug), not a cross-account IDOR.

## Bypasses
- Case and path tricks on function-level gates: `/Admin/`, `/ADMIN/`, trailing slash, `%2e` segments, `..;/`, matrix parameters.
- Encode the id or the traversal: URL-encode, double URL-encode, path segment `..%2f` to reach a sibling object route.
- Content-type switch (`application/xml` <-> `application/json`) to reach a parser that skips the authorisation filter.
- Wrap or retype the id (array, nested object, string vs int) to slip past a type-narrow ownership check.
- HTTP parameter pollution and JSON duplicate keys so the gate reads one value and the data layer reads another.
- Downgrade the API version or swap the HTTP method to reach a handler written before the control existed.
- Append a file extension (`/user/23.json`) or hit a cache/CDN variant that serves an unchecked route.

## Kill rules
- The id in the response resolves to your own account (attacker == victim) — own-data only, no cross-account proof.
- Only a 200 came back with no actual other-user data in the body — status alone is not a finding.
- It works solely with no auth header: that is broken/missing authentication, report it as that, not as IDOR.
- The object is public by design (a published profile, a shared-by-link resource) — no authorisation was ever expected.
- The extra fields exposed are non-sensitive; over-fetching without sensitive data is not impact.
- It only reproduces under one identity, or the diff does not hold with a fresh/relogged session — fails the cross-identity re-check.
- The actor is an admin/support role acting on a user by design — an expected privileged capability, not a bug.
