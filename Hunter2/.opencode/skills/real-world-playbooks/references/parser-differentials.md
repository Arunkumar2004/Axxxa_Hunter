# Real-World Playbook - Parser Differential and Type Confusion

**Class:** `parser-differentials` · **Coverage-matrix tier:** 2 · **Hunter2:** `novel-vuln-reasoner` agent · `tools/deser_probe.py` (guided-manual — no dedicated scanner) · **Skill:** — (closest: web2-vuln-classes)

**Route:** `novel-vuln-reasoner` -> relevant parser/tool (`deser_probe.py`, multipart,
CRLF, GraphQL, HTTP/2 tooling) -> controlled differential evidence -> validator/report-writer.

## Conditions

- Multiple parsers, proxies, content types, serializers, or protocol versions process input.

## Safe method

- Send one bounded ambiguity at a time and compare normalized interpretations.
- Record front-end/backend, client/server, or parser A/parser B differences.
- Use a harmless marker or owned test object to demonstrate the security boundary.

## Proof and rejection

- A different error is only a lead; confirm a security-sensitive interpretation difference.
- Reject crashes, generic 500s, timing noise, and malformed input without impact.

## Test flow / checklist — do these in order
*(public methodology — PortSwigger request-smuggling/parser research / HackTricks / PayloadsAllTheThings; run each, mark result in the coverage matrix)*

[ ] Map every layer that re-parses input: front-end proxy vs backend, CDN/WAF vs origin, client vs server, serializer A vs B
[ ] Identify multi-parser inputs: `Content-Length`/`Transfer-Encoding`, JSON vs form, XML vs JSON, multipart boundaries, URL/host parsing
[ ] Send one bounded ambiguity at a time (e.g. a CL.TE / TE.CL desync marker) and compare how each layer interprets it
[ ] Test content-type confusion — same body parsed as JSON by one component and XML/form by another
[ ] Test JSON parser quirks: duplicate keys, comments, trailing data, and integer/float/type coercion across services
[ ] Test URL/host parser differentials (userinfo `@`, backslashes, unicode) that route differently front vs back
[ ] Test multipart/upload boundary and filename parsing differences across the pipeline
[ ] Test serialization/type confusion where a value is one type to the validator and another to the sink
[ ] Record the exact normalized interpretation of each parser side-by-side, using a harmless marker or owned object
[ ] Escalate a confirmed differential to a concrete security effect (auth/routing/validation bypass, cache poisoning, smuggling)

## What gets this rejected (kill before you write)
*(from `skills/triage-validation/SKILL.md` — one wrong answer = kill it and move on)*

- A different error message or generic 500 between parsers — that is a lead, not a finding.
- Crashes, timeouts, or timing noise with no security-sensitive interpretation difference.
- Malformed input the server rejects everywhere (no divergence).
- A differential with no reachable security boundary crossed (no bypass, no smuggling, no confusion into a sink).
- Theoretical desync with no demonstrated request-routing or response impact.
- **Conditionally valid (only WITH a chain):** parser differential → request smuggling (queue poisoning / auth bypass), web cache poisoning/deception, WAF/validation bypass into an injection sink, or access-control bypass via divergent routing.
