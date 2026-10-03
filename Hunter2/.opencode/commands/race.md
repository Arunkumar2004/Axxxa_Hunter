---
description: Race condition tester - concurrent requests on a state-changing endpoint. Usage: race <url> --method POST --body '{"id":1}' [--mode parallel|pipeline] [--threads 30]
---

# /race

Race a single endpoint with concurrent identical requests (TOCTOU).

## Run This

```bash
# Parallel connections (default 30 threads):
python tools/h1_race.py --url https://target.com/api/coupon/redeem --method POST --body '{"code":"SAVE10"}' --mode parallel --threads 30

# HTTP/1.1 pipelining (single connection - beats per-conn locks):
python tools/h1_race.py --url https://target.com/api/coupon/redeem --method POST --body '{"code":"SAVE10"}' --mode pipeline --count 20

# With auth headers:
python tools/h1_race.py --url <url> --method POST --body '<json>' --headers '{"Cookie":"..."}'

# GraphQL aliasing batch (N mutations, one request):
bash tools/graphql_audit.sh <url> --batch-mutation 'redeemCoupon(code:"SAVE10")' --count 20
```

## Workflow

1. Confirm candidate: run the endpoint once → success; run again → fails ("already used")? → race candidate.
2. Wave: 10-50 concurrent identical requests.
3. A concurrent success count alone is not proof. Compare against a single-request
   baseline and stop after one bounded wave if the controlled state changes.
4. Confirm persistence from two independent read-only surfaces and capture before/after
   state. Report only when the effect survives and the test account can be cleaned up.
5. `python tools/validate.py "<finding>"` → report.

## Rules

- No real money/payments without explicit human approval + tiny reversible values.
- ≤30 requests default; respect program rate limits.
- Log via `memory/audit_log.py`.

## Output

`findings/<target>/race-<date>.md`: method, concurrency vector, wave results (success/attempts), persisted impact.
