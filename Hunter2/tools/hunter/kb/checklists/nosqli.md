# NoSQL Injection (nosqli)

Operator or JavaScript injection into a document-store query (MongoDB and
friends). Prove an auth bypass or a concrete cross-document read, not that an
operator was merely accepted.

## Checklist
- Spot NoSQL back-ends (Mongo, CouchDB, Firebase, Redis-backed) via tech fingerprint, `_id` object ids, or JSON APIs that accept operators.
- Authentication bypass with operator injection in JSON: `{"user":"admin","pass":{"$ne":null}}`, `{"$gt":""}`, `{"$ne":"x"}` to make the password clause always true.
- Form/urlencoded operator smuggling: `user[$ne]=&pass[$ne]=` where the framework parses bracket syntax into a nested object.
- Boolean inference via `$regex`: `{"pass":{"$regex":"^a"}}` then walk the prefix character-by-character where the response differs on match.
- `$where` / JavaScript injection: `{"$where":"this.pass=='x'||'1'=='1'"}` and server-side JS sinks that evaluate attacker strings.
- Time-based blind through `$where`: `{"$where":"sleep(5000)"}` or a heavy regex to confirm server-side evaluation when there is no content oracle.
- Operator injection where a scalar is expected: `$in`, `$nin`, `$gt`, `$lt`, `$exists`, `$regex` placed into a normal field.
- Type juggling: send a number where a string is expected, an array where a scalar is expected, or `null` to flip comparison semantics.
- Projection/field leakage: abuse operators so the query returns documents or fields outside your scope (other tenants' records).
- Blind extraction loop: automate the `$regex` prefix oracle to dump a password/token hash one character at a time, confirming each step reproduces.
- Aggregation/pipeline endpoints: test `$lookup`/`$group`/`$expr` injection where user input shapes the pipeline.
- Confirm impact: show an auth bypass logging you in, or a concrete cross-document read — accepted operator is not the same as exploited.

## Bypasses
- Bracket-to-object parsing: `param[$ne]=1` / `param[$regex]=.*` in query or form bodies that frameworks (Express/qs, PHP) auto-nest.
- JSON content-type switch to deliver `$`-operators the urlencoded parser would flatten.
- Encoded operator keys (unicode escapes, `$` for `$`) to slip past a naive `$`-blacklist.
- Nested or duplicated keys and arrays to confuse a shallow sanitiser that only checks top-level values.
- `$regex` with anchors and `$options:"s"` to build a character oracle when equality is filtered.
- Swap `$where` for aggregation `$expr`/`$function` on versions where JS evaluation is reachable.

## Kill rules
- An operator was accepted but produced no auth bypass and no out-of-scope data — accepted is not exploited.
- The `$ne`/`$gt` bypass logs you into your own account only, with no access to another user's data.
- The response differs for reasons unrelated to the injection (generic validation error) — no real oracle.
- Input is cast/validated to a scalar server-side and your operators are stringified harmlessly.
- The time delay is not dose-dependent or reproducible — jitter, not a `$where` sleep.
- The target datastore/endpoint is out of scope or a documented public search.
