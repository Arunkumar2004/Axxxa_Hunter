# Real-World Playbook - Security Misconfiguration

**Class:** `security-misconfiguration` · **Coverage-matrix tier:** 2 · **Hunter2:** recon + `/scan-cves` · `/portscan` · **Skill:** web2-recon

**Route:** `web2-recon`/`cloud-security` -> `recon-agent`/`cloud-hunter` -> recon,
`scan-cves`, `portscan`, admin/framework playbooks -> impact validation -> report-writer.

## Conditions

- Debug/admin panel, default access, unsafe header, exposed service, staging host,
  directory listing, old component, or permissive cloud setting is reachable.

## Safe method

- Verify access using read-only requests and owned credentials where required.
- Fingerprint versions only to select a relevant advisory; do not report banners alone.
- Check authorization, data exposure, state-changing methods, and safe remediation evidence.

## Proof and rejection

- Confirm only with unauthorized sensitive access, a reachable exploitable condition, or
  a demonstrated security-control bypass.
- Reject missing headers, banners, default pages, and version disclosure without impact.

## Test flow / checklist — do these in order
*(public methodology — OWASP WSTG config testing / HackTricks / HowToHunt; run each, mark result in the coverage matrix)*

[ ] Fingerprint stack/versions (headers, error pages, banners) only to select a relevant advisory
[ ] Look for exposed admin/debug panels, actuator/console endpoints, framework default pages, and default credentials
[ ] Check for directory listing, backup/temp files, and exposed config (`.env`, `.git`, `phpinfo`, Swagger)
[ ] Test verbose errors / stack traces revealing paths, versions, or internal IPs (impact still requires more)
[ ] Review security headers and CORS/cookie flags — note as supporting context, not standalone
[ ] Enumerate exposed non-web services (Redis, Docker API, DB, Elasticsearch, RDP/SMB) via port scan
[ ] Check for exposed staging/dev hosts that are reachable and in scope
[ ] Test HTTP methods (`PUT`, `DELETE`, `TRACE`, `OPTIONS`) and dangerous method handling
[ ] Match a fingerprinted version to a KEV/advisory and confirm the CVE is actually exploitable on the live service
[ ] Prove impact: unauthorized sensitive access, a reachable exploitable condition, or a demonstrated control bypass — using read-only requests and owned creds

## What gets this rejected (kill before you write)
*(from `skills/triage-validation/SKILL.md` — one wrong answer = kill it and move on)*

- Missing security headers (CSP/HSTS/X-Frame-Options) alone.
- Version/banner disclosure without a working CVE exploit against the live service.
- Default pages, directory listing of non-sensitive content, or a verbose error alone.
- Internal IP in an error message.
- Nuclei `info`-severity matches (detection, not exploitation).
- SSL weak ciphers, missing SPF/DKIM/DMARC, autocomplete-on-password.
- Exposed staging/dev host that is out of scope.
- **Conditionally valid (only WITH a chain):** default creds / exposed panel → authenticated admin access; exposed service → data read or RCE; fingerprinted version → a confirmed, exploited CVE with real impact.
