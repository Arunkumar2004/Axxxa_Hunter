# Business Logic Flaws (business-logic)

Abusing the intended workflow and its invariants — price, quantity, balance,
limits, order of steps — rather than a memory-safety or injection bug. Proven by
outcome (you paid less, got free goods, exceeded a limit), not by status code.

## Checklist
- Model the intended workflow and its invariants: who may do what, in what order, with what limits, and what should stay server-enforced (price, balance, role, quantity, status).
- Parameter tampering on value fields: negative/zero/overflow `amount`, `quantity`, `price`, `discount`; send `-100`, `0`, `0.001`, `99999999`, scientific notation.
- Client-trusted values: change a price/total/currency/tax the client sends that the server should recompute (`price=1`, `currency=USD->local`).
- Step-skip / forced browsing: jump straight to a later workflow endpoint (confirm, activate, settle) bypassing payment/verification steps.
- Coupon/discount abuse: reuse a single-use code, stack multiple codes, apply to ineligible items, or re-apply after removal.
- Quantity/limit bypass: exceed per-user caps, buy more than stock, split into parallel orders, or reset a counter.
- State-machine abuse: cancel-after-ship, refund-more-than-paid, re-use a consumed token, or move an order backwards into a privileged state.
- Replay and idempotency: replay a signed/confirmed request, or omit the idempotency key to double an action.
- Identity/ownership assumptions in logic: use another user's coupon, cart, or saved instrument where the check is implicit.
- Currency/rounding and unit confusion: pay in a cheaper currency, exploit integer vs decimal, or round-down to zero.
- Trial/subscription abuse: re-trigger free trials, downgrade-then-use premium, or cancel-and-keep entitlement.
- Verify the economic/authorisation impact concretely and quantify it — this class is proven by outcome, not by a 200.

## Bypasses
- Negative/zero/overflow and type-juggled values where the server trusts the client number.
- Reorder or omit workflow steps (hit the final endpoint directly; drop the payment/verify call).
- Parallel/duplicate submission to defeat per-request limits (overlaps with race conditions).
- Parameter addition/removal (drop a `signature`, add a `discount`, override a `total`).
- Replay previously valid/confirmed requests, or strip the idempotency key.
- Mix currencies/units, or apply a coupon/credit belonging to another context.

## Kill rules
- The server re-validates and rejects the tampered value (price recomputed, negative refused) — no effect landed.
- The discount or free item did not actually change what you were charged on verification.
- The skipped step is re-checked later and the order/account ends in a correct state.
- The behaviour is an intended feature (a legitimate free tier, a documented refund policy).
- Impact is purely theoretical with no demonstrated money/goods/limit change.
- It requires privileges or insider access you were legitimately granted.
