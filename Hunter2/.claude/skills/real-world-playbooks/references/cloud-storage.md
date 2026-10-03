# Real-World Playbook - Public Cloud Storage

**Class:** `cloud-storage` · **Coverage-matrix tier:** 3 · **Hunter2:** `/cloud-hunt` · `cloud_bucket_enum.py` · `cloud_recon.sh` · **Skill:** cloud-security

**Route:** `cloud-security` -> `cloud-hunter` -> `/cloud-hunt`, `cloud_bucket_enum.py`,
`cloud_recon.sh` -> anonymous read/write/takeover proof -> validator/report-writer.

## Conditions

- A bucket, blob container, object URL, CDN origin, or cloud hostname is in scope.

## Safe method

- Test anonymous listing/read with a harmless known object or public metadata.
- Test write only with explicit authorization and a tiny disposable marker, then delete it.
- Check CORS, signed URL scope/expiry, tenant prefixes, and dangling ownership.

## Proof and rejection

- Public URL visibility alone is not a vulnerability; prove unauthorized access to a
  non-public test object or a controlled write/takeover condition.
- Redact object contents, credentials, and customer data.
- Reject CDN cache evidence without origin/storage ownership proof.

## Test flow / checklist — do these in order
*(public methodology — HackTricks cloud / AWS-GCP-Azure docs / PayloadsAllTheThings; run each, mark result in the coverage matrix)*

[ ] Enumerate storage names from JS bundles, HTML, DNS, CDN origins, and error messages (S3 buckets, GCS buckets, Azure blob containers)
[ ] Permute likely names: `<company>`, `<company>-dev/-prod/-backup/-assets/-logs`, plus region suffixes
[ ] Test anonymous listing (`?list-type=2`, `s3 ls`, GCS/Azure list APIs) using a harmless known object or public metadata only
[ ] Test anonymous read of a *non-public* test object to prove access production intends to deny
[ ] Test anonymous/any-authenticated write ONLY with explicit authorization, using a tiny disposable marker, then delete it
[ ] Check bucket/object ACLs, bucket policy, and `AllUsers` / `AuthenticatedUsers` grants
[ ] Check CORS config for wildcard origin + credentials allowing cross-site read
[ ] Inspect signed-URL scope and expiry: overly long TTL, predictable/replayable URLs, missing object scoping
[ ] Check tenant/prefix isolation — can one tenant read another's prefix?
[ ] Check for dangling storage (deleted bucket still referenced) enabling takeover; confirm ownership before claiming
[ ] Redact any object contents, credentials, or customer data pulled during proof

## What gets this rejected (kill before you write)
*(from `skills/triage-validation/SKILL.md` — one wrong answer = kill it and move on)*

- A public object URL being visible/reachable — that is intended; you must prove access to a non-public object or a write/takeover condition.
- Bucket-name enumeration alone with no read/write/list access.
- CDN cache evidence without proving origin/storage ownership.
- CORS wildcard on a bucket without a credentialed cross-origin exfil PoC.
- Objects that are intentionally public assets (images, static-site content).
- Storage owned by a third party the company merely links to (out of scope).
- **Conditionally valid (only WITH a chain):** bucket listing → JS/config containing API keys or secrets; anonymous read → PII/customer data; dangling bucket → subdomain/asset takeover.

## Sources

OWASP cloud guidance, AWS/GCP/Azure security documentation, `cloud-security` skill,
and `cloud_bucket_enum.py`.
