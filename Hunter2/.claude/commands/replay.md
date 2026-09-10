---
description: Re-verify a saved finding by replaying its exact request - reports VULNERABLE (still live), FIXED (patched), or CHANGED (re-triage). Regression-check one finding or a whole folder. Usage: /replay finding.json | /replay findings/target/ --dir
---

# /replay

Re-issue the request that proved a finding and decide whether the bug is still
there. Use before submitting (re-confirm), after a program patches (prove the
fix), or to regression-check every finding at once.

## Usage

```bash
tools/finding_replay.py finding.json
tools/finding_replay.py findings/target/ --dir --json
tools/finding_replay.py finding.json --auth-file .private/target.json
```

## Finding format (canonical replayable finding)

```json
{
  "id": "idor-orders-001", "severity": "HIGH",
  "request": {"method":"GET","url":"https://api.t.com/orders/1337","headers":{"Authorization":"Bearer ..."}},
  "match": {"status":200, "contains":["victim@"], "absent":["Forbidden"]}
}
```

`match` is what "still vulnerable" looks like. All `contains` must be present and
no `absent` may appear.

## Verdicts

- **VULNERABLE** - every condition still holds (bug is live).
- **FIXED** - no condition holds (patched / access denied).
- **CHANGED** - partial match; re-triage manually.
- **ERROR** - request could not be sent.

`--auth-file` overlays a fresh session so a replay does not fail just because the
finding stored an expired token.
