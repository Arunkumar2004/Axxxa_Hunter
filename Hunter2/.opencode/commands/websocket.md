---
description: Scan a WebSocket for Cross-Site WebSocket Hijacking (CSWSH) - replays the handshake with a forged Origin while authenticated. Usage: /websocket wss://target/ws --cookie "session=..."
---

# /websocket

Detect Cross-Site WebSocket Hijacking: a ws(s):// endpoint that authenticates
via cookies but does not validate the handshake `Origin` can be driven by an
attacker page as the victim.

## Usage

```
/websocket wss://target.com/socket --cookie "session=abcd"
/websocket ws://target.com/ws --origin https://evil.example --json
/websocket -l recon/target.com/urls/ws.txt --cookie "s=..."
```

Run directly:

```bash
tools/websocket_scanner.py wss://target.com/socket --cookie "session=..."
```

## How it works

Performs the raw WS handshake twice - once with a forged cross-site Origin, once
with the site own Origin - and compares. Sends your cookie so the
authenticated-socket condition is realistic.

## Severity

- **HIGH** - forged-Origin handshake succeeds (101) while authenticated (CSWSH).
- **MEDIUM** - any Origin accepted with no cookie.
- **LOW** - forged rejected but same-origin accepted (Origin validated).

## Confirm the bug

On HIGH, build a PoC page that opens the socket from an attacker origin and reads
the first authenticated message - that message content is the proof.

## Chain

CSWSH -> read live chat/notifications/PII, or send actions as the victim ->
account takeover / data exfil.
