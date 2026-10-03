---
name: race-conditions
description: Use when the user targets money/limits/verification flows - coupons, wallet, balance, quantity, OTP, signup, email verification, password reset - or when the user says "race", "TOCTOU", "double spend", "concurrency". Full race condition methodology: candidate identification, concurrency vectors (pipelining/parallel/GraphQL aliasing), winning strategies, confirmation rules.
---

# Race Conditions (TOCTOU)

Races = the same state change executed multiple times concurrently. Often pays Critical (payment, wallets, coupons, verification).

## Step 1: Find a candidate (30 sec each)

An endpoint is a race candidate if a **single** request flips a state flag, and a **second** manual request fails with something like `already used`, `coupon already applied`, `limit reached`, `email already verified`.

Candidates by class:
- **Coupon/discount**: apply+redeem, redeem after order, multi-coupon.
- **Wallet/money**: top-up, cashback, refund, transfer A→B while B→A, negative price.
- **Quantity**: add item qty=N to cart twice, stock decrement, reservation.
- **Verification**: email/phone OTP verify (reuse one OTP for N accounts), account verification.
- **Limits**: free trial, invites, API quota, license, rate-limit bypass.
- **Signup flows**: username takeover via registration race (register same username twice).

## Step 2: Choose the concurrency vector

1. **HTTP/1.1 pipelining** (single connection, N requests queued) — defeats per-connection locks and many app-level mutexes. Use `h1_race.py --pipeline`.
2. **Parallel connections** (N threads, identical requests) — defeats per-request serialization. `h1_race.py --parallel --threads 30`.
3. **GraphQL aliasing** — N mutations in ONE HTTP request → the server processes them in parallel; bypasses per-request limits entirely (and rate limits). Use `graphql_audit.sh` alias generator.
4. **WebSocket** — N frames on one socket.
5. **HTTP/2 multiplexing** — N streams on one connection.

## Step 3: Win the race

- Send N=10-50 identical requests (keep modest; respect program limits).
- If all succeed → CONFIRMED (N successes for 1 resource).
- If none succeed → try:
  - Delays: 0ms, 1ms, 5ms, 15ms, 50ms offsets between requests (`--delay`).
  - Randomize order; repeat 3-5 waves.
  - Larger N (up to 100, only if program tolerates).
- Single connection pipelining often wins where parallel fails (server locks per-IP/per-conn).

## Step 4: Confirm persistence

After the wave, verify the side effect **twice from independent surfaces**:
- Coupon: check balance in `/wallet` and in `/orders`.
- Verification: log in with each "verified" account.
- Quantity: check stock in two endpoints.
If the effect reverted → not valid; kill it.

## Tools

```
python tools/h1_race.py --url <url> --method POST --body '{"id":1}' --mode parallel --threads 30
python tools/h1_race.py --url <url> --mode pipeline --count 20
bash   tools/graphql_audit.sh <url>          # alias batching
python tools/validate.py "<finding>"
```

## Safety

- **Never** race real money/payments without explicit human approval and tiny reversible values.
- Keep concurrency ≤30 by default; check program rate limits first.
- Log all requests via `memory/audit_log.py`.
- For OTP/verification races: use your own test accounts only.

## Confirmation Rules

- Valid: single request fails, concurrent requests succeed >1 times, effect persists.
- Invalid: app returns success once and errors the rest (proper locking) — kill it.
- Impact must be usable: N coupons redeemed, N accounts verified with 1 OTP, wallet doubled.

## References

- Race condition hunting (PortSwigger): https://portswigger.net/web-security/race-conditions
- James Kettle "Smashing the state machine": https://portswigger.net/research/smashing-the-state-machine
- Tips on GraphQL alias racing: https://blog.assetnote.io/
