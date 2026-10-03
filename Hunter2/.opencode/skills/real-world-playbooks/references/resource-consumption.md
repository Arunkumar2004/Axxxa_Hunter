# Real-World Playbook - Resource Consumption

**Class:** `resource-consumption` · **Coverage-matrix tier:** 2 (API4) / 3 (LLM10) · **Hunter2:** `api-security` review (non-DoS checks only) · `/llm-hunt` (guided-manual) · **Skill:** api-security, llm-security

**Route:** `api-security`/`llm-security` -> `api-hunter`/`llm-hunter` -> bounded single,
small-batch, or static complexity checks -> validator/report-writer.

## Conditions

- Rate-limited action, GraphQL complexity, regex/parser, upload, export, or model-cost path exists.

## Safe method

- Establish a baseline with one request, then use the smallest bounded test increment.
- Prefer static complexity analysis, server timing with wide margins, and test accounts.
- Stop at first measurable controlled impact; never load-test production.

## Proof and rejection

- Require persistence, a documented quota bypass, or measurable controlled cost/availability
  impact.
- Reject response latency alone, generic 429 behavior, and unbounded-volume claims.

## Test flow / checklist — do these in order
*(public methodology — OWASP API Security API4 / WSTG / GraphQL cost analysis; NON-DoS only — run each, mark result in the coverage matrix)*

[ ] Identify cost/limit surfaces: rate-limited actions, GraphQL depth/complexity, regex/parser inputs, uploads, exports, model-cost paths
[ ] Establish a baseline with a single request; record timing and any quota headers
[ ] Check for missing/weak rate limits on sensitive endpoints (OTP, login, reset, payment) with small bounded bursts only
[ ] Test pagination/`limit` params for oversized page sizes returning huge result sets
[ ] Analyze GraphQL query depth, aliasing, and batching statically for complexity amplification (analyze, don't flood)
[ ] Check upload/export endpoints for missing size caps with one bounded oversized-but-safe test payload
[ ] Test regex/parser inputs for ReDoS with a single crafted string measured against a wide timing margin
[ ] Check whether a documented quota/plan limit can be bypassed (test account, per-plan enforcement)
[ ] For LLM cost paths, bound token/iteration tests tightly and stop at first measurable controlled impact
[ ] Confirm impact = persistence, a real quota bypass, or a measurable controlled cost/availability effect — never load-test production

## What gets this rejected (kill before you write)
*(from `skills/triage-validation/SKILL.md` — one wrong answer = kill it and move on)*

- Response latency alone with no persistent or quota impact.
- Generic `429` / rate-limit-present behavior, or missing rate limit on search/contact/non-sensitive forms.
- Rate limit "missing" behind Cloudflare/WAF that actually throttles.
- MFA/OTP rate limit without proving a code can actually be brute-forced.
- Unbounded-volume / theoretical DoS claims with no controlled measurement.
- Anything that degrades the live production service — do not run it.
- **Conditionally valid (only WITH a chain):** missing rate limit → OTP/reset-token brute force that succeeds; complexity/ReDoS → measurable controlled resource exhaustion, or a documented quota bypass with real cost.
