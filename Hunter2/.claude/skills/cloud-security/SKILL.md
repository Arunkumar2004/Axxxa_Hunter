---
name: cloud-security
description: Use when the target is cloud-hosted (AWS/GCP/Azure), when recon finds S3/GCS/blob links, CDNs, cloud subdomains, or when the user says "bucket", "cloud", "S3", "metadata", "takeover", "cloud storage". Covers bucket enumeration/takeover, metadata SSRF chains, exposed cloud services, and cloud subdomain takeover with evidence rules.
---

# Cloud Security (External/No-Key Testing)

Most cloud bugs are checkable with zero credentials: public buckets, dangling DNS, exposed services, metadata SSRF.

## 1. Bucket Enumeration (S3 / GCS / Azure)

Name candidates from: target domain, `company`, `company-assets`, `company-prod`, `company-backup`, `media.company`, subdomain names, JS bundle strings.

```
python tools/cloud_bucket_enum.py <domain>    # checks S3+GCS+Azure via DNS
```

Manual checks:
- S3: `https://<bucket>.s3.amazonaws.com/?list-type=2` → `200` + XML keys = **public read** (CRITICAL if sensitive).
- GCS: `https://storage.googleapis.com/<bucket>/?prefix=` → `200` + JSON objects.
- Azure: `https://<name>.blob.core.windows.net/<container>?restype=container&comp=list` → `200` + XML.
- Write test: `PUT` an empty object → `204` = **public write** (reportable; do not leave test objects — use a random name and delete it or use a canary `POSSIBLE` write and note).

Takeover signals: `NoSuchBucket` / `NoSuchObject` / `ResourceNotFound` + DNS A record exists (dangling). Only claim a bucket with explicit human approval.

## 2. Cloud Metadata SSRF

Any SSRF endpoint → try cloud metadata (see `ssrf` skill for SSRF methodology):

| Cloud | URL | Header |
|---|---|---|
| AWS IMDSv2 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | first `PUT /latest/api/token` for token |
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | — |
| GCP | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `Metadata: true` |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | — |

**Never output the actual credentials** — report the exposure path with a hash/redacted value. Use `oob_listener.py` for blind SSRF confirmation.

## 3. Exposed Cloud Services

Run `python tools/port_scanner.py <target>` then probe findings:
- Redis `6379`: `echo PING | nc` → `PONG` = unauth (CRITICAL).
- Docker API `2375`: `curl http://host:2375/version` → RCE vector.
- Kubernetes `6443`: `curl -k https://host:6443/version` (unauth API) or `https://host:6443/api` anonymous.
- Elasticsearch `9200`: `curl http://host:9200/_cat/indices`.
- MongoDB `27017`, PostgreSQL `5432`, MySQL `3306`: banner + no-auth.
- S3/cloud consoles on 443: default creds, directory listing.

## 4. Cloud Subdomain Takeover

- `python tools/takeover_scanner.sh --recon recon/<target>/` (dnsReaper/subjack).
- Dangling CNAME → takeover: S3 (`NoSuchBucket`), GCS (`NoSuchObject`), Azure (`ResourceNotFound`), CloudFront (`NoSuchBucket` / `ERROR: The request could not be satisfied`), Heroku (`No such app`), Shopify (`Sorry, this shop is currently unavailable`), Fastly (`Fastly error: unknown domain`), Elastic Beanstalk (`NXDOMAIN` on CNAME).
- Verify the claimability (name available in the provider) — do not claim without human approval.

## 5. Cloud Config & Credential Leaks

- `bash tools/secrets_hunter.sh --js-bundle recon/<target>/` — AWS keys (`AKIA[0-9A-Z]{16}`), GCP (`AIza...`), Azure, `.env`, `aws_credentials`, `google-credentials.json`, presigned URLs.
- `cloud-recon` for public buckets by keyword: `bash tools/cloud_recon.sh --keyword <company>`.
- Presigned URLs: check expiry + scope (`x-amz-expires` huge = finding if object sensitive).

## Evidence & Safety

- Save raw listing/response as PoC; never fetch objects without human approval (respect program rules).
- Redact credentials; hash them (sha256 first 12) in findings.
- Cloud assets are in scope ONLY if the program says so — always `scope_checker.py` first.
- Report impact tiers: public read (High), public write (High), takeover (High), unauth service (Critical), metadata SSRF (Critical).

## References

- OWASP Cloud-Native Security Top 10: https://owasp.org/www-project-cloud-native-application-security-top-10/
- S3 bucket takeover guide: https://rhinosecuritylabs.com/aws/s3-ransomware-part-2-prevention-and-defense/
- AWS IMDS docs: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- GCP metadata docs: https://cloud.google.com/compute/docs/metadata/overview
- Azure IMDS docs: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
