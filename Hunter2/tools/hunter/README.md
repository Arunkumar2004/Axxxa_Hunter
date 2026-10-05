# Hunter Engine — build spec (read this fully before writing code)

We are turning Hunter2 into an **expert-level hunting engine**: one driver that
understands a target, picks the attacks that fit, tests each class **deeply (many
techniques + bypasses)**, adapts to responses, chains findings, kills weak ones,
and reports. It **drives the existing tools in `tools/`** — it does not replace
or delete any of them.

## The human-expert loop (what the engine does)

1. **Understand** — build a Target Model: tech stack, roles/accounts, valuable
   objects (orders, coupons, products, PII), auth shape, trust boundaries.
2. **Select** — from the model, decide which classes the surface actually
   exposes (match class to surface; say why a class is N/A).
3. **Go deep** — run the depth kit for each applicable class: every technique +
   bypass, adapting to what the server returns. Park-and-return, never abandon.
4. **Chain** — combine all findings (incl. low/info) into A→B→C.
5. **Validate & kill** — 7-question gate; kill false positives.
6. **Report** — one merged, deduped report.

A **coverage ledger** (state machine) tracks every class as
`PENDING / IN_PROGRESS / FOUND / TESTED_DEEP / N/A(reason) / BLOCKED(reason)`.
No silent skips; no "queued" forever.

## The contract (import from here, nothing else shared)

`from tools.hunter.contract import HuntContext, Finding, Resp, Account, register, ...`

- A kit is an object with `name: str`, `classes: tuple`, `applicable(ctx)->bool`,
  `run(ctx)->list[Finding]`. At import, call `register(MyKit())`.
- **Every request goes through `ctx.fetch(method, url, headers=None, body=None)`**
  which returns a `Resp` or `None`. NEVER call the network directly in a kit —
  this is what makes everything unit-testable offline.
- Build `Finding` objects per the dataclass. Put statuses/lengths/short redacted
  snippets in `evidence`; never put raw tokens or full bodies anywhere.

## Hard rules (all agents)

- **Create ONLY the files listed for you. Do NOT edit or delete any existing
  file.** If you need a change to an existing tool, write it in your final
  report for the orchestrator to apply — do not touch it yourself.
- **Reuse, don't re-implement.** Import the existing tool modules named in your
  section and drive them. Writing a parallel re-implementation is a failure.
- **Safety:** state-changing requests (POST/PUT/PATCH/DELETE) run **only** when
  `ctx.allow_write` is True, and must **capture the original value first and
  auto-revert** after; DELETE only on an object the kit itself created. All
  fetches must be SSRF-safe (the default fetch wraps `tools/safe_http`).
- **Adapt like a human:** on 403 → try the bypass techniques; on WAF/soft-block
  → encode; on a login/OTP/captcha wall → stop and record `BLOCKED` (never guess
  creds). Classify with response *diffing*, not status codes alone.
- British English, no emoji, LF line endings, Windows-safe stdout (UTF-8).
- Python 3.13, standard library + `requests` only unless a reused tool adds one.

## File ownership map

| Agent | Owns (create these only) |
|---|---|
| engine-core | `tools/hunter/engine.py`, `tools/hunter/ledger.py`, `tools/hunter/target_model.py`, `tests/hunter/test_engine.py`, `tests/hunter/test_ledger.py`, `tests/hunter/test_target_model.py` |
| kit-access | `tools/hunter/kits/access_control.py`, `tests/hunter/test_kit_access.py` |
| kit-injection | `tools/hunter/kits/injection.py`, `tests/hunter/test_kit_injection.py` |
| kit-auth | `tools/hunter/kits/auth.py`, `tests/hunter/test_kit_auth.py` |
| kit-ssrf | `tools/hunter/kits/ssrf_infra.py`, `tests/hunter/test_kit_ssrf.py` |
| kit-logic | `tools/hunter/kits/logic_race.py`, `tests/hunter/test_kit_logic.py` |
| kit-client | `tools/hunter/kits/client_side.py`, `tests/hunter/test_kit_client.py` |
| harness | `tools/hunter/net.py` (default SSRF-safe fetch), `tools/hunter/chain.py`, `tools/hunter/validate_gate.py`, `tests/hunter/mock_target.py`, `tests/hunter/test_mock_target.py`, `tests/hunter/test_chain.py`, `tests/hunter/test_validate_gate.py` |
| knowledge | `tools/hunter/kb/__init__.py`, `tools/hunter/kb/loader.py`, `tools/hunter/kb/checklists/*.md`, `tests/hunter/test_kb.py` |

The engine discovers kits by scanning `tools/hunter/kits/*.py` and importing each
(every kit self-registers). No shared `__init__` list to edit.

## Testing bar (every agent)

- Unit-test your own code with an **inline fake `fetch`** (a small function
  returning `Resp(...)`), covering: a true-positive, a true-negative
  (false-positive guard), and the safety/revert path if you do writes.
- Run `python -m pytest tests/hunter/test_<yours>.py -q` until green. Report the
  exact pass count. "Looks fine" is not acceptable — paste the result.

## Per-class technique matrices ("all ways" — build these into each kit)

**kit-access (IDOR/BOLA/BFLA)** — reuse `tools/two_account_idor.py` (read axis,
`_similar`, `test_endpoint`) and `tools/chain_engine.sibling_endpoints`; also
look at `tools/h1_mutation_idor.py` for the write-battery pattern:
cross-account **read**; cross-account **write/tamper** (PATCH/PUT then owner-read
to confirm, then auto-revert); **BFLA** method-swap (GET→PUT/POST/DELETE/PATCH);
**ID mutation** (numeric ±1/zero-pad/int↔str, URL-encoded, base64/wrapped
`{"id":x}`/array, UUID nibble-flip); **sibling** endpoints; anon-access
false-positive guard.

**kit-injection (SQLi/NoSQLi/SSTI/XSS/cmdi/XXE/LDAP)** — reuse
`tools/nosqli_scanner.py`, `tools/xxe_scanner.py`, `tools/waf_encoder.py`,
`tools/dom_xss_harness.py`: SQLi error/boolean/time-based + UNION shape;
NoSQLi operator-injection + `$where` time blind; SSTI polyglot `${{7*7}}`
family with engine fingerprint; XSS reflected/stored/DOM across HTML/attr/JS/URL
contexts + WAF-encoded + known-sink; command-injection `;|&&$()` + time blind;
XXE internal-entity → file read → OOB; LDAP `*)(` filters. Reflection/diff-based,
canary-tagged; mark blind ones for OOB.

**kit-auth (JWT/session/OAuth/SAML/MFA/reset/ATO)** — reuse
`tools/jwt_scanner.py` and `tools/h1_oauth_tester.py`: JWT alg:none, RS256→HS256
confusion, weak-secret crack (offline), `kid`/`jku` abuse, claim tamper; session
fixation / logout-invalidation / cookie flags; OAuth `redirect_uri` / `state` /
code-reuse; password-reset token predictability/leak/reuse; MFA
bypass/brute/backup-code; ATO chaining hypotheses. **Never send OTP/reset spam
without `allow_write`; stop at a wall.**

**kit-ssrf (SSRF + smuggling + cache + redirect + host-header + CRLF)** — reuse
`tools/oob_listener.py`, `tools/crlf_scanner.py`, `tools/safe_http.py`: SSRF
param probing with bypasses (decimal/octal/hex/IPv6, `[::]`, DNS-rebind shape,
redirect-chain, `@`-confusion, metadata `169.254.169.254`/`metadata.google`),
blind via OOB; open-redirect; host-header injection / password-reset poisoning;
CRLF/response-splitting; request-smuggling CL.TE/TE.CL shape; cache
poisoning/deception (unkeyed header/`.css` path confusion). **SSRF targets only
via `ctx.fetch` which blocks internal hops — report param reachability, don't
actually pivot into internal infra.**

**kit-logic (business logic + race)** — reuse `tools/h1_race.py`: parameter
tampering (price/qty/negative/overflow), step-skip / forced-browsing of a
workflow, coupon/discount reuse & stacking, quantity/limit bypass, state
machine order abuse; race conditions (parallel submit → double-spend / limit
bypass) **only under `allow_write`** with the smallest safe N and revert.

**kit-client (CORS/CSRF/clickjacking/proto-pollution/postMessage/open-redirect/
websocket)** — reuse `tools/cors_scanner.py`, `tools/csrf_scanner.py`,
`tools/prototype_pollution_scanner.py`, `tools/hpp_postmessage_scanner.py`,
`tools/websocket_scanner.py`: CORS origin-reflection/null/credentialed/
suffix-prefix; CSRF token/SameSite on state-changing forms; clickjacking
(X-Frame/CSP frame-ancestors); client/server prototype pollution; postMessage
missing-origin; CSWSH; DOM open-redirect.

## Cross-cutting: the SPA baseline

`tools/spa_baseline.py` fingerprints an SPA catch-all shell. The engine probes it
and sets `ctx.baseline`. Kits should treat `ctx.baseline.is_catchall(resp.status,
resp.body)` responses as noise (not a live endpoint / not a finding).
