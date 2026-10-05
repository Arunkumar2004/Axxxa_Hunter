# Race Conditions / TOCTOU (race-condition)

A check-then-act window where concurrent requests interleave to exceed a limit or
double-spend. Only valid under write authorisation, with the smallest safe N and
an auto-revert; the effect must not reproduce sequentially.

## Checklist
- Find limited/consumable actions with a check-then-act gap: coupon/gift-card redemption, balance/credit spend, stock purchase, vote/like, invite acceptance, withdrawal, rate-limited actions.
- Baseline the single-request behaviour and the intended limit (one use, one per account, N in stock) so you can show the limit was exceeded.
- Prepare parallel requests: identical state-changing request x N, dispatched as simultaneously as possible, under `allow_write` only.
- Single-packet attack (HTTP/2): batch many requests in one TCP packet to minimise jitter; or Turbo Intruder-style last-byte sync on HTTP/1.1.
- Double-spend proof: redeem the same one-use credit/coupon concurrently and show the balance went negative or the code applied more than once.
- Limit-overrun proof: acquire more than the per-user/stock cap by racing (buy 2 of a 1-item limit, over-withdraw).
- Rate-limit/OTP bypass by racing before the counter increments (overlaps with MFA/auth — keep OTP attempts minimal and only with authorisation).
- State-confusion races: concurrent requests that interleave a multi-step state machine into an invalid state (apply+cancel, upgrade+refund).
- Use the smallest safe N that demonstrates the effect, capture before/after state, and auto-revert (refund/return) anything consumed.
- Confirm it is a true race (reproduces only under concurrency, not sequentially) and is reproducible across attempts.

## Bypasses
- Single-packet attack over HTTP/2 to neutralise network jitter between requests.
- Last-byte synchronisation (Turbo Intruder) on HTTP/1.1 so all requests complete the final byte together.
- Connection warming/pre-flight to remove TLS/handshake variance before the burst.
- Multiple sessions/tokens for the same account to dodge per-connection serialisation.
- Vary N and timing to hit the narrow window; retry bursts since races are probabilistic.

## Kill rules
- The effect also reproduces with sequential requests — it is a logic flaw, triage as business-logic.
- The back-end uses an atomic/locked operation and the extra requests are rejected or coalesced — no overrun.
- You could not revert a consumed resource and the proof is just your own duplicated benign action with no limit crossed.
- The duplicated outcome has no security/economic impact (an idempotent result).
- It is only achievable with write access you were not granted / without `allow_write`.
- The limited resource/host is out of scope, or the only outcome is DoS on an excluding program.
