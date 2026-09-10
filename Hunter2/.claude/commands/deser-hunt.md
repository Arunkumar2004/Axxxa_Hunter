---
description: Insecure deserialization detection + safe confirmation. Usage: deser-hunt <url> [--cookie NAME] [--param name=value]
---

# /deser-hunt

Detect and safely confirm insecure deserialization.

## Run This

```bash
# Format detection + reflection probes on a URL:
python tools/deser_probe.py <url>

# Scan a specific cookie (Java rO0AB / PHP a:3:{ / .NET ViewState):
python tools/deser_probe.py <url> --cookie CUSTOMER

# Blind OOB confirmation (DNS/HTTP callback - interactsh):
python tools/oob_listener.py --start
python tools/deser_probe.py <url> --oob <callback-domain> --gadget dns

# PHP PHAR via file param:
python tools/deser_probe.py <url> --param "file=phar://uploads/x.phar" --oob <callback-domain>
```

## Workflow

1. Find serialized blobs (cookies/params): base64 decode (offline) → identify Java/PHP/.NET/Python/Node magic.
2. Reflection probe: benign object → canary in response (e.g., `__toString` echo).
3. OOB: DNS callback gadget (URLDNS/phpggc phar) → hit = CONFIRMED blind.
4. Time-based: `sleep(5)` gadget → delayed response = CONFIRMED.
5. RCE: ONLY with explicit human approval.

## Rules

- Never fire RCE payloads without explicit human approval.
- OOB callbacks only to your own interactsh endpoint.
- Redact any secrets/creds from evidence.

## Output

`findings/<target>/deser-<date>.md`: blob location, format, gadget (used/proposed), callback evidence.
