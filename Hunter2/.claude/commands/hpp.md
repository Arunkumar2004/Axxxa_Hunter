---
description: Scan for HTTP Parameter Pollution (duplicate-param behaviour differential) + postMessage listeners missing origin checks. Usage: /hpp <url?param=x> [--postmessage-only] [--cookie "s=..."]
---

# /hpp

Two cross-context input bugs: server-side HTTP Parameter Pollution and
client-side postMessage listeners with no origin validation.

## Usage

```
/hpp https://target.com/search?q=x
/hpp https://target.com/app.js --postmessage-only
/hpp -l recon/target.com/urls/with_params.txt --cookie "s=..." --json
```

Run directly:

```bash
tools/hpp_postmessage_scanner.py "https://target.com/search?q=x" --cookie "s=..."
```

## What it tests

- **HPP** - sends a parameter twice (`?x=A&x=B` and `?x=B&x=A`) and diffs the
  responses. Position-dependent handling (first-wins vs last-wins) is a
  WAF/validation-bypass primitive (filter reads one copy, sink uses the other).
- **postMessage** - fetches JS and flags `addEventListener("message", ...)` /
  `onmessage` handlers that consume `event.data` without checking `event.origin`,
  especially into a dangerous sink (`innerHTML`, `eval`, `location`).

## Severity

- **HIGH** - message listener -> dangerous sink with no origin check.
- **MEDIUM** - HPP positional divergence, or a listener with no origin check.
- **LOW** - duplicating a param changed the response cosmetically.

## Chain

HPP -> bypass a WAF or server-side validation to smuggle the real payload (SQLi,
auth params). postMessage-injection -> DOM XSS / token theft from any origin.
