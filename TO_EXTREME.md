# Hunter2 — Existing → EXTREME Upgrade Plan

> **How to use this file in a NEW session:**
> 1. Open a new session in this repo and say: **"read TO_EXTREME.md"** — the agent
>    will load full context from this file alone.
> 2. Then say **"start 1"**, **"start 2"**, or **"start 3"** to execute that phase.
>    "start 1" = Phase 1, and so on. Each phase is self-contained and must pass its
>    acceptance criteria before it is called done.
> 3. This file is the single source of truth for the upgrade. It does NOT need any
>    other doc to be understood.

---

## PROGRESS TRACKER  (last updated: 2026-09-29)

Full test suite at last update: **821 passed, 10 skipped** (was 779 before this work).

**PHASE 1 = COMPLETE ✅** (all 4 steps built, wired live, docs mirrored to Claude Code
+ OpenCode, tests green).
**PHASE 2 = COMPLETE ✅** (chain engine + learning memory built, wired, tests green).
**PHASE 3 = COMPLETE ✅** (all 54 playbooks leveled + synced to both mirrors; 843 tests
passing). **ALL OF LEVEL 1 (Phases 1–3) IS DONE.** Only optional Level 2 remains.

### ✅ DONE — Phase 3: all 54 playbooks leveled to one depth
- Tool/command mapping: **54/54** (was 44)
- Test-flow checklist: **54/54** (was 23)
- Rejection rules ("What gets this rejected"): **54/54** (was 11)
- 10 thin playbooks (cicd, cloud-storage, kubernetes, llm-agentic, saml-sso,
  secrets-leak, security-misconfiguration, parser-differentials, resource-consumption,
  api-inventory-consumption) brought to full mature format.
- Re-synced to `.claude/skills/` and `.opencode/skills/` mirrors (54 files each).

### ✅ DONE — Phase 2 fully wired
- `tools/chain_engine.py` (+ test, 14) — sibling rule + A→B table → ranked next-tests.
  Wired: `run_two_account_idor` auto-chains every POSSIBLE_IDOR hit → `findings/<t>/chains.json`.
- `tools/hunt_memory.py` (+ test, 8) — records worked/rejected/dead_end/inconclusive to
  `memory/hunt_outcomes.jsonl` (rotation-capped, no secrets). Wired: `hunt_target` logs
  prior wins/dead-ends at hunt start via `summarize_for_hunt()`.
- Note: `test_pattern_db.py::test_save_10k_completes_under_5s` can flake under load
  (timing test); passes in isolation — not a regression.

### ✅ DONE — Phase 1 fully wired
- `playbook_router` now AUTO-fires in `/hunt` → writes `findings/<target>/PLAYBOOKS.md`
  (27 class playbooks indexed) via `run_playbook_context()`.
- `rejection_gate` now AUTO-fires in `/validate` as a pre-check before the 4 gates.
- `two_account_idor` wired via `--two-account` / `--two-account-unsafe`.
- Docs updated: `commands/hunt.md`, `commands/validate.md`, and `.opencode/` mirrors.

### ✅ DONE — earlier this session
- **Windows portability fix** — `tools/hunt.py` + `tools/zero_day_fuzzer.py` guarded
  for POSIX-only `os.setsid`/`os.killpg` and the bash-style env-var prefix. Recon was
  silently skipping on Windows; it now runs. (Prerequisite for everything.)
- **Extended class scanners wired into `/hunt`** — `run_extended_scans()` in `hunt.py`
  (CORS/CRLF/XXE/CSRF/prototype-pollution/HPP/WebSocket).
- **Recon freshness diff** — `tools/recon_diff.py` (+ test), wired as
  `run_recon_freshness()`. Flags new assets to `recon/<target>/fresh/`.
- **Phase 1 · Step #1** — `tools/playbook_router.py` (+ `tests/test_playbook_router.py`,
  12 tests). Resolves any class/alias → the right `references/<class>.md`, extracts
  checklist + rejection rules. **CLI works; NOT yet auto-invoked inside the hunt loop.**
- **Phase 1 · Step #2** — `tools/two_account_idor.py` (+ test, 8 tests). Two-account
  IDOR/BOLA cross-tenant replay. **WIRED into `hunt.py`** as `run_two_account_idor()`
  with `--two-account` / `--two-account-unsafe` flags; reads `ACCOUNT_A_*`/`ACCOUNT_B_*`
  from `.env`; SAFE methods by default; never logs tokens.
- **Phase 1 · Step #4** — `tools/rejection_gate.py` (+ test, 15 tests). Non-interactive
  always-rejected checker. **CLI works; NOT yet wired into the `/validate` flow.**
- **Dukaan recon** — 372 subdomains, real API surface mapped (paused; needs 2 accounts).

### ⏳ TODO — finish Phase 1 (small, ~20 min)
- Auto-invoke `playbook_router` inside the hunt loop so the matching playbook loads
  automatically per lead (today it is CLI-only).
- Wire `rejection_gate` into the `/validate` flow (auto-check findings).
- Update `commands/hunt.md` + `commands/validate.md`; mirror all to `.opencode/`.

### ⏳ TODO — Phase 2 (~1.5–2 hrs)
- Step #3 auto-chain engine (`tools/chain_engine.py`): sibling rule + A→B.
- Step #7 learning memory (`tools/hunt_memory.py`): record/load per-target + per-class
  outcomes so hunts compound.

### ⏳ TODO — Phase 3 (~1.5–2 hrs) — LEVEL THE PLAYBOOKS (uses existing sources, no new reports)
Audit of the 54 playbooks (2026-09-28):
- Report links + bounty signal: 54/54 ✅
- Payloads: 44/54 · Tool/command mapping: 44/54
- **Test-flow checklist: only 23/54** — add to the 31 missing
- **Rejection rules: only 11/54** — add to the 43 missing
- Step #5 backfill Business Logic + Race with real cases.
- Step #6 fold Phase-1 research inline + level every playbook to one depth.
- Note: reports are HackerOne-heavy; broaden PortSwigger/vendor where thin.

### Level 2 / God-Eye — see Section 9
- **L2.2 Attack-surface graph = FULL DONE ✅** — `tools/surface_graph.py` (+ 11 tests).
  v1: host→family→endpoint→param map; flags IDOR/action candidates, sibling clusters,
  version anomalies. v2 (full): `--probe` live auth-probing (anon/A/B via injectable
  fetch) → real `missing_auth` + `cross_account` anomalies + role reachability. Wired
  into `hunt.py`. Writes `findings/<t>/SURFACE_GRAPH.md`.
- **L2.1 Feedback loop = DONE ✅** — `tools/feedback_loop.py` (+ 13 tests), wired into
  `hunt.py`. Records PAID/REJECTED/DUPLICATE/INFORMATIVE; `advise_for_hunt()` boosts
  paid techniques, avoids rejected ones next hunt.
- **L2.3 Hypothesis engine** — NOT built (the deep multi-day piece; deferred by operator).

Full suite: **867 passed, 10 skipped.**

### 🔒 BLOCKED (needs the operator, not code)
- Dukaan high-value hunt: needs the operator's **two own test accounts** in `.env`
  (`ACCOUNT_A_TOKEN`/`_COOKIE`, `ACCOUNT_B_TOKEN`/`_COOKIE`) to run `--two-account`.

---

## 0. What this project is (context for a cold reader)

**Hunter2** is an AI-driven bug-bounty hunting toolkit living at
`D:\bughunting\Axxx_Hunter\Hunter2\`. It has:

- ~90 Python/bash tools in `tools/` (recon, scanners, validators, memory)
- 54 per-class real-world playbooks in `skills/real-world-playbooks/references/`
- 40+ skills, 15+ hunting agents (`agents/`), 58 slash commands (`commands/`)
- A memory system (`memory/`), lead board, audit log, pattern DB
- Runs under BOTH **Claude Code** (`commands/`, `CLAUDE.md`) and **OpenCode**
  (`.opencode/`, `AGENTS.md`) — the two share the same Python engine (`tools/hunt.py`)

The master entry point is `tools/hunt.py` (invoked by `/hunt`). Both agents call it,
so engine changes benefit both automatically.

**Python note:** on this Windows machine the interpreter is `py` (not `python`/
`python3`). Bash (Git Bash) is available; PowerShell is the default shell.

---

## 1. Why this upgrade exists (the problem)

Real hunts on live programs (tested via both Claude Code and OpenCode) found **zero
bugs**. Root causes discovered this session:

1. **The tool was scanner-heavy but reasoning-light.** It ran signatures (which find
   duplicates) instead of thinking/testing like a hunter (which finds real bugs).
2. **It has huge knowledge but doesn't USE it automatically** — the 54 playbooks are
   never auto-opened during a hunt; the agent guesses instead.
3. **No authenticated two-account testing** — so the money classes (IDOR, payment,
   privilege escalation) were structurally out of reach.
4. **[FIXED this session] Windows portability bugs** — `tools/hunt.py` passed env vars
   as a bash-style prefix (`TARGET_TYPE=... bash`) which cmd.exe can't parse, and used
   POSIX-only `os.setsid`/`os.killpg`. Result: **recon silently skipped on Windows**
   (reported "OK" but did nothing). Fixed with platform guards in `tools/hunt.py` and
   `tools/zero_day_fuzzer.py`. This was a big part of the zero-findings problem.

**Already shipped this session (do not redo):**
- Extended class scanners wired into `/hunt` (CORS/CRLF/XXE/CSRF/prototype-pollution/
  HPP/WebSocket) → `run_extended_scans()` in `tools/hunt.py`
- Recon freshness diff → `tools/recon_diff.py` (+ `tools/test_recon_diff.py`), wired
  into the hunt loop as `run_recon_freshness()`
- Blind XXE auto-uses OOB when `BBHUNT_OOB_DOMAIN` is set
- Windows portability fixes (above)
- Test suite green: **779 passed, 10 skipped**

---

## 2. The goal

Turn Hunter2 from a scanner that finds duplicates into a **real, compounding hunter**
that thinks, tests, chains, validates, and learns — at expert level.

**Explicit decision by the operator:**
- ❌ **DO NOT build new scanners** (the ~40 knowledge-only classes stay scanner-less).
  Scanners find duplicates; the money bugs are found by guided manual reasoning.
- ❌ **DO NOT bulk-add more reports** past what exists (~70 real cases + 54 playbooks).
  Diminishing returns; quality of wiring beats quantity of reports.
- ✅ **DO wire BEHAVIOR** — make the tool act on its knowledge, test with two accounts,
  chain bugs, validate hard, and learn across hunts.

---

## 3. The upgrade = 7 pieces (the "6 steps" + learning memory)

| # | Upgrade | Applies to | In phase |
|---|---|---|---|
| 1 | **Auto-load playbook per lead** — agent opens `references/<class>.md` automatically and follows its checklist + rejection rules | ALL 54 classes | Phase 1 |
| 2 | **Two-account IDOR/BOLA harness** — replay account A's requests with account B's tokens/IDs to prove cross-tenant access | Access-control classes only (IDOR/BOLA/BFLA/privesc/auth/payment) | Phase 1 |
| 4 | **Rejection-gate in `/validate`** — auto-kill invalid findings (public keys, self-XSS, theoretical, out-of-scope) before a report is written | ALL classes | Phase 1 |
| 3 | **Auto-chain** — after any confirmed bug, auto-run the Sibling Rule (`/export`,`/delete`,`/share`,`/v1/`) + the A→B table | ALL classes | Phase 2 |
| 7 | **Learning memory (NEW — the god-level piece)** — every hunt writes what worked / got rejected / dead ends; next hunt auto-loads it so the tool compounds and gets smarter over time | ALL classes | Phase 2 |
| 5 | **Backfill weak groups** — add real disclosed cases to Business Logic + Race (currently ~2 each, need ~14) | Business Logic + Race | Phase 3 |
| 6 | **Fold Phase-1 research into playbooks + level all** — merge the 70-case research into the priority `references/*.md` and bring every playbook to one consistent depth | Priority classes → then all | Phase 3 |

**Coverage summary:**
- **Steps 1, 3, 4, 7 = universal** (every bug class gets: right playbook + chaining +
  validation + learning memory).
- **Steps 2, 5, 6 = targeted** (only the classes where they matter).

---

## 4. THE THREE PHASES (execution spec)

### PHASE 1 — Act on knowledge (the core engine) — ~2 hrs
**Goal:** the tool starts using its playbooks + hunts the money classes with two accounts.

**Tasks:**
- **1.1 Auto-load playbook per lead (Step #1).**
  - When a lead/finding is classified to a vuln class, the hunt loop must locate
    `skills/real-world-playbooks/references/<class>.md` and inject its checklist +
    rejection rules into the agent's working context.
  - Add a resolver `tools/playbook_router.py` mapping class → playbook file (fuzzy match
    on the 54 filenames). Wire it into `tools/hunt.py` (and expose for agents/commands).
  - Handle "no playbook found" gracefully (log + continue).
- **1.2 Two-account IDOR/BOLA harness (Step #2).**
  - Reuse `tools/credential_store.py` (already exists, `.env`-based). Read TWO account
    contexts: `ACCOUNT_A_*` and `ACCOUNT_B_*` (tokens/cookies).
  - New `tools/two_account_idor.py`: given a list of endpoints (from recon/JS), replay
    account A's request with account B's auth (and vice-versa), diff responses, flag
    when B's data is returned to A. Detection-only, safe methods by default (GET/HEAD);
    state-changing methods require explicit opt-in.
  - Wire an optional phase into `tools/hunt.py` (`--two-account`, off unless creds set).
  - Never print raw token values; use the credential store's masking.
- **1.4 Rejection-gate in validate (Step #4).**
  - Extend `tools/validate.py` to check each finding against the always-rejected list
    (public keys like `rzp_live_*`/`rzp_test_*` publishable IDs, self-XSS, missing
    headers w/o impact, theoretical/no-impact, out-of-scope) sourced from the
    `security-arsenal` / `triage-validation` skills.
  - Output a clear `REJECTED (reason)` vs `PASSES GATE` verdict.

**Phase 1 acceptance:**
- `playbook_router` resolves all 54 class names; unit test proves mapping + fallback.
- `two_account_idor.py` runs against a fixture (two fake auth contexts) and correctly
  flags a simulated cross-account leak; unit test included; no token values leak to logs.
- `validate.py` rejects each item on the always-rejected list; unit test included.
- Full suite: no new failures. Works invoked via `py` on Windows.
- `commands/hunt.md` + `.opencode/commands/hunt.md` + `commands/validate.md` updated.

---

### PHASE 2 — Learn & chain (the god-level piece) — ~1.5–2 hrs
**Goal:** the tool finds bug B after bug A, and gets smarter every hunt.

**Tasks:**
- **2.3 Auto-chain (Step #3).**
  - New `tools/chain_engine.py`: given a confirmed finding, generate sibling endpoints
    (`/export`,`/delete`,`/share`,`/archive`,`/v1/`…) and the A→B follow-ups from the
    A→B table in `commands/hunt.md`. Return a ranked next-test list.
  - Wire so that on any confirmed finding, the chain list is produced and (if safe)
    auto-queued to the lead board.
- **2.7 Learning memory (Step #7 — NEW).**
  - Use `memory/` (pattern DB + journal + rotation, all already present). On session end,
    auto-write: target, endpoints tested, classes tried, what worked, what was rejected
    and WHY, dead ends. On hunt start, auto-load the prior entries for that target/class
    so the agent skips dead ends and repeats winning techniques.
  - Add `tools/hunt_memory.py` helpers: `record_outcome(...)`, `load_target_memory(...)`,
    `load_class_memory(...)`. Wire into `tools/hunt.py` start + end.
  - Bounded by existing 10 MB JSONL rotation (`memory/rotation.py`). No credentials/raw
    target data stored — only technique/outcome metadata.

**Phase 2 acceptance:**
- `chain_engine.py` unit-tested: a confirmed IDOR yields correct sibling + A→B tests.
- `hunt_memory.py` unit-tested: write→read round-trip; second hunt loads first hunt's
  outcomes; rotation respected; no secrets written.
- Full suite: no new failures. Claude Code + OpenCode parity (docs mirrored).

---

### PHASE 3 — Level the knowledge (polish) — ~1.5–2 hrs
**Goal:** all classes at equal, expert knowledge depth.

**Tasks:**
- **3.5 Backfill weak groups (Step #5).**
  - Add real disclosed cases (source URL + type each) to bring Business Logic and Race
    to ~14 solid cases; update their `references/*.md` and the Phase-1 ledgers.
- **3.6 Fold Phase-1 research into playbooks + level all (Step #6).**
  - Merge the 70-case research (`skills/real-world-playbooks/PHASE1_*.md`) into the
    priority `references/*.md` so the agent reads the case knowledge inline.
  - Bring every playbook to one consistent structure: sources → test-flow checklist →
    real payloads → methodology → rejection rules → chain opportunities → Hunter2
    routing (skill/agent/tool/validator/report).
  - Improve source diversity: reduce HackerOne-only weighting by adding
    PortSwigger/vendor/CVE/advisory cases where thin.

**Phase 3 acceptance:**
- Business Logic + Race each have ≥14 cases with source URL + type.
- Every priority playbook contains inline case knowledge + rejection rules + routing.
- ≥4 source families represented across the case set (not HackerOne-only).
- Full suite: no new failures. Docs mirrored to `.opencode/`.

---

## 5. Global rules (apply to every phase)

1. **Authorized targets only.** All live testing stays scope-gated (`/scope` first).
   Public research teaches method; it is not permission to test.
2. **No secrets in the repo or logs** — no credentials, cookies, tokens, raw target
   data, or large attachments. Use `credential_store.py` masking.
3. **Two accounts are the operator's own** — the tool never creates accounts or logs in;
   the operator supplies `ACCOUNT_A_*`/`ACCOUNT_B_*` via `.env`.
4. **Detection-only by default** — safe HTTP methods unless the operator opts in.
   Respect `SafeMethodPolicy` / `AutopilotGuard`.
5. **A phase is "done" only when its acceptance criteria + the full test suite pass** —
   not because docs were added (roadmap rule).
6. **Claude Code ↔ OpenCode parity** — mirror any command/skill doc change into
   `.opencode/`.
7. **Windows-safe** — use `py`; guard POSIX-only calls; no bash-style env prefixes in
   `subprocess(shell=True)`.
8. **Do NOT build new scanners** and **do NOT bulk-add reports** (operator decision).

---

## 6. What becomes powerful after this upgrade

**Full power (playbook + two-account/chain/validate/learn):**
- IDOR / BOLA / BFLA ← biggest jump
- Authentication / Account Takeover (OAuth, JWT, SAML, session, MFA)
- Privilege Escalation / mass assignment
- Business Logic + Payment Manipulation
- Race Conditions
- SSRF (with OOB confirm)

**Universal lift (auto-playbook + chain + validate + learning memory) — every other
class:** XSS, SQLi, CSRF, CORS, CRLF, NoSQLi, XXE, prototype pollution, WebSocket, HPP,
SSTI, deserialization, request smuggling, cache poisoning, file upload, open redirect,
path traversal/LFI, GraphQL, subdomain takeover, cloud storage, k8s, CI/CD, LLM/agentic,
secrets leak, info disclosure, and the rest of the coverage matrix.

**Not changed (Chunk C skipped by decision):** the ~40 knowledge-only classes still have
no dedicated auto-scanner — the agent tests them manually, now with expert playbook
guidance + chaining + validation + memory.

---

## 7. Time

| Phase | Work | Time |
|---|---|---|
| 1 | Act on knowledge (auto-playbook + two-account + rejection-gate) | ~2 hrs |
| 2 | Learn & chain (auto-chain + learning memory) | ~1.5–2 hrs |
| 3 | Level the knowledge (backfill + fold/level playbooks) | ~1.5–2 hrs |
| **All** | **Existing → EXTREME** | **~5–6 hrs** |

---

## 8. Start commands

- **"start 1"** → execute Phase 1 (tasks 1.1, 1.2, 1.4), run tests, report.
- **"start 2"** → execute Phase 2 (tasks 2.3, 2.7), run tests, report.
- **"start 3"** → execute Phase 3 (tasks 3.5, 3.6), run tests, report.
- **"start all"** → run Phases 1–3 in order, stopping only if a phase's tests fail.
- **"start L2"** → execute the optional Level 2 / God-Eye section below (weeks-long).

Each phase: build → run `py -m pytest -q` → confirm no new failures → mirror docs to
`.opencode/` → report what changed and what's next. Never mark a phase done on a failing
suite.

---

## 9. OPTIONAL — Level 2 / God-Eye (the last ~10%, weeks-long)

> **This is separate from the fast 7 (Phases 1–3).** Do Phases 1–3 first — they deliver
> ~90% of real-world hunting power in hours. Level 2 is the roadmap's architecture tier:
> it adds the last ~10% (compounding, connected reasoning) but costs **~1.5–2 weeks**,
> not hours. Only start it after Phases 1–3 are done and you want to push toward the
> realistic ceiling. **Space cost is tiny** (code + bounded JSON/SQLite, <~50 MB, capped
> by the existing 10 MB rotation). **Time is the real cost.**

**Honest ceiling note:** even with Level 2, the tool is a *strong, compounding hunter
that you drive* (~90–95/100), not an autonomous human hacker. The money bugs (logic,
payment, IDOR) still need a human to confirm intent. Full autonomy is marketing, not
reality — do not expect zero-human auto-hacking.

### L2.1 — Real submission feedback loop — ~0.5–1 day
**Goal:** learn from real triage outcomes (the truest signal).
- New `tools/feedback_loop.py`: record each real submission's outcome — `PAID` (amount),
  `REJECTED` (reason), `DUPLICATE`, `INFORMATIVE` — against the finding's class,
  endpoint pattern, and technique.
- On hunt start, load these outcomes so the agent repeats paid techniques and avoids
  patterns that got rejected/duped. Reuse `memory/` + rotation; store outcome metadata
  only (no report bodies, no target PII).
- **Acceptance:** write→read round-trip test; a rejected technique is de-prioritized and
  a paid technique is boosted in the next hunt's plan; no secrets stored.

### L2.2 — Attack-surface graph — ~3–6 days
**Goal:** see the target as connected surfaces, not isolated URLs (where chains live).
- New `tools/surface_graph.py` (+ a store, e.g. SQLite under `memory/`): nodes =
  assets/hosts/endpoints/params/roles/workflows; edges = reachability, auth-requirement,
  ownership, data-flow. Ingest from existing recon output, lead board, JS-extracted
  endpoints, and authenticated sessions.
- Add coverage status per node (`TESTED|FOUND|N/A|BLOCKED|PENDING`) and surface related
  leads + candidate chains.
- **Acceptance:** graph builds from a recon fixture; querying "endpoints reachable by
  role X" and "unkeyed/auth-less endpoints" returns correct sets; coverage rolls up;
  unit-tested; bounded storage.

### L2.3 — Hypothesis engine — ~4–8 days
**Goal:** reason about broken security assumptions, not just run signatures.
- New `tools/hypothesis_engine.py`: for each observation (from the surface graph),
  generate a hypothesis {affected asset, assumed control, expected attacker capability,
  priority, confidence, required accounts, applicable methods, status, next action,
  evidence}. Flow: `observation → hypothesis → methods → test → evidence →
  validated/rejected`.
- Route hypotheses to the right specialist agent + playbook (reuse Phase 1's
  `playbook_router`) and record results back onto the graph + memory + feedback loop.
- **Acceptance:** from a sample surface graph it produces prioritized, deduped
  hypotheses with correct method/agent routing; a validated/rejected result updates
  graph + memory; unit-tested; Claude Code ↔ OpenCode parity.

### Level 2 summary

| Piece | Time | Space |
|---|---|---|
| L2.1 Feedback loop | ~0.5–1 day | negligible |
| L2.2 Surface graph | ~3–6 days | small (SQLite/JSON, capped) |
| L2.3 Hypothesis engine | ~4–8 days | small |
| **All Level 2** | **~1.5–2 weeks** | **<~50 MB total** |

Same global rules (Section 5) apply. A Level 2 piece is done only when its acceptance
criteria + the full suite pass and docs are mirrored to `.opencode/`.
