---
description: Scan for prototype pollution - static client-side gadget/source detection in JS + active server-side __proto__ reflection probing. Usage: /proto-pollution <js-or-endpoint> [--active] [--cookie "s=..."]
---

# /proto-pollution

Find prototype pollution primitives client-side (shipped JS) and server-side
(Node/Express endpoints).

## Usage

```
/proto-pollution https://target.com/app.js
/proto-pollution https://target.com/api/profile --active
/proto-pollution -l recon/target.com/urls/js.txt --json
```

Run directly:

```bash
tools/prototype_pollution_scanner.py https://target.com/api/x --active --cookie "s=..."
```

## What it does

- **Static** - flags pollution sources (`location.search`, `URLSearchParams`,
  `qs.parse`, `JSON.parse`) + sinks/gadgets (`$.extend(true)`, `lodash.merge`,
  deep-merge helpers, `Object.assign` on request data, for-in copy loops).
- **Active** (`--active`) - sends a `__proto__` JSON body and a
  `?__proto__[canary]=canary` query, then checks for the canary reflected in a
  response object (server-side PP) or a 500 from prototype traversal.
  Non-destructive: only a random canary key is ever set.

## Severity

- **HIGH** - server reflects the injected prototype property.
- **MEDIUM** - client-side source+sink both present, or a consistent proto-only 500.
- **LOW** - a pollution source without an obvious sink.

## Chain

Server-side PP -> RCE (gadget in later child_process/template calls) or
auth-bypass. Client-side PP -> DOM XSS via a gadget.
