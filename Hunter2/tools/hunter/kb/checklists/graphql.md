# GraphQL Abuse (graphql)

Resolver-level authorisation gaps, object-id lookups, batching, and injection
through arguments. Confirm concrete impact, not merely that introspection is on.

## Checklist
- Locate the endpoint (`/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`) and whether GET and POST (and batched arrays) are accepted.
- Introspection: run the full `__schema` query; if enabled it maps every type, query and mutation (informational alone, but the map for everything else).
- If introspection is disabled, use field suggestions ("Did you mean...") and known-type probing to reconstruct the schema.
- Authorisation per resolver: enumerate queries/mutations reachable without auth or with a low-priv token that should be restricted (missing resolver-level checks).
- BOLA via `node(id:)` / global-id lookups: base64 a `Type:id` and fetch another user's object, bypassing per-object checks.
- BFLA via privileged mutations (`deleteUser`, `setRole`, `adminUpdate`) callable by a non-admin.
- Mass assignment / over-fetching: request sensitive fields (`email`, `phone`, `passwordHash`, `ssn`) the UI hides, and input objects that accept privileged fields.
- Batching/alias abuse: send many operations or aliased fields in one request to bypass rate limits (credential stuffing, OTP brute) or amplify cost.
- DoS by query depth/complexity: deeply nested/circular queries and alias multiplication — report cautiously where DoS is excluded.
- Injection through arguments: SQL/NoSQL/command/SSRF payloads inside GraphQL arguments reach the same back-end sinks — pivot to those checklists.
- CSRF on GraphQL over GET or `application/x-www-form-urlencoded` POST that skips a token.
- Confirm concrete impact (cross-user data, a privileged mutation effect, auth bypass), not merely that introspection is on.

## Bypasses
- Introspection re-enable tricks and field-suggestion inference when `__schema` is blocked.
- Method/content-type switch: GET query, `x-www-form-urlencoded`, or a batched array to dodge CSRF/rate controls.
- Alias and batch multiplication to brute-force or exceed limits under one HTTP request.
- Global-id (`node`) resolution to reach objects the typed queries would gate.
- Argument-level injection to reach SQL/NoSQL/SSRF sinks behind resolvers.
- Persisted-query/APQ manipulation where the hash is trusted.

## Kill rules
- Introspection enabled with no demonstrated auth bypass, IDOR, injection, or privileged mutation — informational alone.
- A `node()` query returns only your own objects (no cross-user data).
- Over-fetched fields are non-sensitive / already public.
- Batching is possible but the endpoint is non-critical and rate-limited elsewhere.
- The only outcome is query-complexity DoS on a program that excludes DoS.
- The endpoint/schema is third-party or out of scope.
