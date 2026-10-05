# SSRF — Server-Side Request Forgery (ssrf)

Coercing the server into making requests you choose — ideally into internal
services or cloud metadata. Report reachability and data returned; do not pivot
deeper into internal infrastructure than needed to prove impact.

## Checklist
- Find request-issuing parameters: `url`, `uri`, `next`, `redirect`, `dest`, `image`, `img`, `src`, `webhook`, `callback`, `feed`, `proxy`, `fetch`, `load`, plus JSON fields and SVG `<image href>`.
- Spot indirect fetchers: link previews, PDF/thumbnail/screenshot generators, from-URL importers, webhooks, avatar-by-URL, SSO/OIDC metadata URLs, and XML/XXE paths.
- Baseline with a collaborator URL you control; confirm the server (not your browser) makes the request by checking the source IP and headers at your listener.
- DNS-only vs full-response: determine whether you merely get a callback or the response body is reflected back — full-read SSRF is far higher impact.
- Loopback/internal targets: `http://127.0.0.1/`, `http://localhost/`, `http://[::1]/`, and private ranges (`10.`, `172.16-31.`, `192.168.`, `169.254.`).
- Cloud metadata: AWS `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, GCP `http://metadata.google.internal/computeMetadata/v1/` (with `Metadata-Flavor: Google`), Azure IMDS and equivalents.
- Internal port/service sweep via the SSRF: common ports (6379 Redis, 9200 Elasticsearch, 2375 Docker, 8080 admin) to prove internal reachability.
- Scheme abuse where the client allows it: `file://` (local read), `gopher://` (craft Redis/SMTP/HTTP payloads), `dict://`, `ftp://`, `ldap://`.
- Redirect-based SSRF: your external URL 302s to an internal/metadata target; test whether the fetcher follows cross-host and cross-scheme redirects.
- DNS rebinding: a hostname resolving external on first check then internal on fetch (TOCTOU) to defeat a resolve-time allowlist.
- Blind SSRF escalation: use OOB (interactsh/collaborator) to confirm, then try to reach a service that reflects data or accepts a gopher-crafted request.
- Protocol/parser confusion in the URL to point validation at one host and the fetch at another (`@`, `#`, backslash, embedded credentials).
- Header/host-injection variants: `Host`, `X-Forwarded-Host` that steer a server-side fetch; and SSRF via XXE/SVG/HTML-to-PDF.
- Bound it responsibly: demonstrate reachability/credential exposure but do not pivot deeper into internal infrastructure than needed, and stay in scope.

## Bypasses
- Decimal/dword IP: `http://2130706433/` = `127.0.0.1`, `http://3232235521/` = `192.168.0.1`, `http://2852039166/` = `169.254.169.254`.
- Octal IP: `http://0177.0.0.1/`, and mixed `http://0177.0.0.0x1/`.
- Hex IP: `http://0x7f000001/` or dotted hex `http://0x7f.0x0.0x0.0x1/`.
- Short/abbreviated forms: `http://127.1`, `http://0/`, `http://127.0.1`.
- IPv6 forms: `http://[::1]/`, `http://[::ffff:127.0.0.1]/`, `http://[0:0:0:0:0:ffff:127.0.0.1]/`, and IPv6 of the metadata IP.
- DNS tricks: `127.0.0.1.nip.io`, rebinding services (`make-...-rebind-...rr.1u.ms`), and attacker-controlled CNAME pointing inward.
- URL parser confusion: `http://expected.com@127.0.0.1/`, `http://127.0.0.1#@expected.com/`, backslash `http://127.0.0.1\@expected.com/`, `http:127.0.0.1/`.
- Full-width/unicode host and URL-encoded host (`%6c%6f%63%61%6c%68%6f%73%74`) to dodge string filters.
- Redirect to the internal target from a host that passes the allowlist, and enclosed-alphanumeric bubble text for domains.

## Kill rules
- DNS/HTTP callback only, with no internal service reached and no internal content returned — insufficient on its own.
- The fetch only reaches an external host you control — proves outbound traffic, not SSRF into anything sensitive.
- It is a documented, intended URL fetcher (public webhook/importer) behaving exactly as designed with no internal access.
- The metadata endpoint is blocked/filtered (IMDSv2 enforced, 169.254 unreachable) and no other internal target is reachable.
- The root cause is on a third-party or out-of-scope host.
- You reached an internal host but got no data and no actionable effect (a bare connect with a generic error).
