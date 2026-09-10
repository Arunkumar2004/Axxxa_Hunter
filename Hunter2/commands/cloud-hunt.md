---
description: Cloud asset hunt - public bucket enum, metadata SSRF, exposed services, cloud takeover. Usage: cloud-hunt <domain> [--buckets name1,name2]
---

# /cloud-hunt

Hunt misconfigured cloud assets for a domain or company.

## Run This

```bash
# Bucket enumeration (S3/GCS/Azure) for a domain:
python tools/cloud_bucket_enum.py <domain>

# Explicit bucket name candidates:
python tools/cloud_bucket_enum.py <domain> --names media,static,assets,prod,backup

# Exposed services (Redis, Docker, k8s, DBs, ES):
python tools/port_scanner.py <host-or-ip> --top-ports 1000

# Subdomain takeover candidates:
bash tools/takeover_scanner.sh --recon recon/<domain>/

# Public bucket search by keyword:
bash tools/cloud_recon.sh --keyword <company-name>
```

## Workflow

1. Enumerate buckets → anonymous listing (`200` + objects) = public read (High).
2. Test public write with a canary object name (remove it after; report if `204`).
3. Port scan → probe non-web services (Redis PING, Docker `/version`, ES `/_cat`, k8s `/version`).
4. Takeover scanner → verify dangling CNAME → claimable bucket (only claim with human approval).
5. If any SSRF found → metadata chain (`cloud-security` skill), confirm via `oob_listener.py`.

## Rules

- Scope check first — cloud assets are in scope only when the program says so.
- Never output raw cloud credentials — hash/redact.
- No destructive writes without human approval.

## Output

`findings/<domain>/cloud-<date>.md`; feed leads via `lead_board.py`.
