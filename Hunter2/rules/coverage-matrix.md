# Coverage Matrix — the "miss nothing, A→Z" checklist

This is the **canonical vulnerability-class list** the Lead Commander iterates on every
target. It merges four industry-standard taxonomies:

- **OWASP Web Top 10 (2021)**
- **OWASP API Security Top 10 (2023)**
- **OWASP LLM / GenAI Top 10 (2025)**
- **PortSwigger Web Security Academy** — full topic list (the most complete practical class list)

**How the leader uses it (NON-NEGOTIABLE):**
For each target, every row gets one status:

| Status | Meaning |
|---|---|
| `TESTED` | Class was actually probed on a reachable surface; result recorded (found / not found). |
| `FOUND` | A candidate/finding exists → routed to its skill + lead board. |
| `N/A (reason)` | No reachable surface for this class — **must state why** (e.g. "no XML parser / no file upload / no GraphQL endpoint"). |
| `PENDING` | Not yet reached. A hunt is **not "done"** while any reachable class is `PENDING`. |

**Rule:** silently skipping a class is forbidden. Either test it, or mark `N/A` with a
one-line reason. The leader reports this matrix at the end of every hunt.

---

## Tier 0 — Always test first (highest impact, most reachable)

| Class | Detect on | Hunter2 tool / command | Skill |
|---|---|---|---|
| **Broken Access Control / IDOR / BOLA** (OWASP A01, API1) | any object id, `/user/123`, numeric/UUID refs | `tools/h1_idor_scanner.py`, `tools/h1_mutation_idor.py`, `tools/apispec_idor.py`, `/api-audit` | `api-security`, `auth-attacks` |
| **BFLA — Broken Function-Level Auth** (API5) | admin/privileged endpoints reachable as low-priv | `/api-audit`, `api_security_scanner.py` | `api-security` |
| **BOPLA / Mass assignment** (API3) | JSON bodies with extra fields | `/api-audit`, `api_security_scanner.py` | `api-security` |
| **Authentication flaws** (A07, API2) | login/reset/OAuth/SSO/JWT | `tools/h1_oauth_tester.py`, `tools/jwt_scanner.py`, `/auth-hunt` | `auth-attacks` |
| **SSRF** (A10, API7) | url= / webhook / fetch / preview / import | `/ssrf-chain`, `tools/oob_listener.py` | `ssrf` |
| **Business logic** (A04) | cart/price/coupon/wallet/quota/workflow | `business-logic-hunter` agent, `tools/h1_race.py` | `race-conditions` |
| **Injection — SQLi** (A03) | any param reaching a query | `vuln_scanner.sh` (nuclei/ghauri/sqlmap) | `web2-vuln-classes`, `security-arsenal` |
| **XSS — reflected / stored / DOM** (A03) | reflected params, HTML sinks, DOM sinks | `vuln_scanner.sh` (dalfox+xsstrike), `/domxss`, `tools/dom_xss_harness.py` | `web2-vuln-classes`, `client-side-security` |

## Tier 1 — Test on every reachable surface

| Class | Detect on | Hunter2 tool / command | Skill |
|---|---|---|---|
| **NoSQL injection** | Mongo/JSON auth, `$where` | `/nosqli`, `tools/nosqli_scanner.py` | `web2-vuln-classes` |
| **SSTI — template injection** | reflected values in templated pages | `vuln_scanner.sh` | `web2-vuln-classes` |
| **OS command injection** | params to system calls, blind | `oob_listener.py` (blind), `vuln_scanner.sh` | `web2-vuln-classes` |
| **Path traversal / LFI** | file/path/page params | `vuln_scanner.sh`, manual | `web2-vuln-classes` |
| **File upload** | any upload feature | `fuxploider` (via `vuln_scanner.sh`), `tools/multipart_mutator.py` | `web2-vuln-classes` |
| **XXE** | XML/SOAP/SVG/DOCX parsers | `/xxe`, `tools/xxe_scanner.py` | `web2-vuln-classes` |
| **CSRF** | state-changing forms w/o token/SameSite | `/csrf`, `tools/csrf_scanner.py` | `client-side-security` |
| **CORS misconfig** | `Access-Control-Allow-*` reflection | `/cors`, `tools/cors_scanner.py` | `client-side-security` |
| **CRLF / response splitting / Host-header** | reflected headers, redirects | `/crlf`, `tools/crlf_scanner.py` | `web2-vuln-classes` |
| **Open redirect** | redirect/return/next params | `vuln_scanner.sh`, `/client-side` | `web2-vuln-classes` |
| **JWT attacks** | any JWT | `/jwt-scan`, `tools/jwt_scanner.py` | `auth-attacks` |
| **OAuth / OIDC flaws** | OAuth login, redirect_uri, state, PKCE | `tools/h1_oauth_tester.py`, `/auth-hunt` | `auth-attacks` |
| **SAML / SSO (XSW, sig-wrapping)** | SAML SSO endpoints | `/auth-hunt`, `vuln_scanner.sh` | `auth-attacks` |
| **MFA / 2FA bypass** | OTP/MFA challenge | `/auth-hunt`, `vuln_scanner.sh` | `auth-attacks` |
| **Password reset flaws** | reset-token flow | `/auth-hunt` | `auth-attacks` |
| **GraphQL** (introspection, batching, alias-IDOR, injection) | `/graphql` endpoint | `graphql_audit.sh`, `/graphql-audit` | `graphql-audit` |
| **Prototype pollution** (client + server) | JS merge sinks, `__proto__` params | `/proto-pollution`, `tools/prototype_pollution_scanner.py` | `client-side-security` |
| **WebSocket / CSWSH** | `ws://`/`wss://` | `/websocket`, `tools/websocket_scanner.py` | `client-side-security` |
| **HTTP Parameter Pollution + postMessage** | duplicated params, postMessage listeners | `/hpp`, `tools/hpp_postmessage_scanner.py` | `client-side-security` |
| **Clickjacking / client-side misconfig** | missing frame headers | `/client-side` | `client-side-security` |
| **Information disclosure** | verbose errors, debug, `.git`, backups | recon + `vuln_scanner.sh`, `tools/secrets_hunter.sh` | `web2-recon` |

## Tier 2 — Reasoning / chained / novel

| Class | Detect on | Hunter2 tool / command | Skill |
|---|---|---|---|
| **HTTP request smuggling** (CL.TE/TE.CL) | front-end/back-end desync | `novel-vuln-reasoner`, `vuln_scanner.sh` | `web2-vuln-classes` |
| **Web cache poisoning / deception** | cache headers, keyed/unkeyed inputs | `novel-vuln-reasoner` | `web2-vuln-classes` |
| **Insecure deserialization** (Java/PHP/.NET/Python) | serialized cookies/blobs | `/deser-hunt`, `tools/deser_probe.py` | `deserialization` |
| **Race conditions** (limit-overrun, TOCTOU) | coupon/OTP/wallet/balance | `/race`, `tools/h1_race.py`, `business-logic-hunter` | `race-conditions` |
| **Parser differentials / type confusion** | multi-parser input | `novel-vuln-reasoner` | — |
| **Dependency confusion / supply chain** (A08) | internal pkg names, CI | `sast_scan.py`, `cicd-security` | `cicd-security` |
| **Vulnerable/outdated components** (A06) | version banners, EOL | `/scan-cves` (nuclei), `tools/eol_check.py` | `web2-recon` |
| **Security misconfiguration** (A05, API8) | headers, defaults, exposed panels | recon + `/scan-cves` | `web2-recon` |
| **Improper inventory mgmt** (API9) | old API versions, staging | `/recon-plus`, `/param-discover` | `api-security` |
| **Unsafe consumption of APIs** (API10) | 3rd-party API trust | `api-security` review | `api-security` |
| **Unrestricted resource consumption** (API4) | no rate-limit, large payloads | `api-security` (non-DoS checks only) | `api-security` |
| **Low→Critical exploit chains** | any set of findings | `chain-builder` agent / `/chain` | see `real-world-playbooks` |

## Tier 3 — Infra / cloud / mobile / web3 / LLM (test when surface exists)

| Class | Detect on | Hunter2 tool / command | Skill |
|---|---|---|---|
| **Subdomain / bucket takeover** | dangling CNAME, unclaimed bucket | `/takeover`, `takeover_scanner.sh` (detect-only) | `cloud-security` |
| **Public cloud storage** (S3/GCS/Azure) | bucket links | `/cloud-hunt`, `cloud_bucket_enum.py` | `cloud-security` |
| **Exposed services** (Redis/Docker/DB/RDP/SMB) | non-web ports | `/portscan`, `port_scanner.py` | `cloud-security` |
| **Kubernetes misconfig** | k8s API, kubelet | `/k8s-audit` | `kubernetes-security` |
| **Cloud metadata / IMDS chains** | SSRF → 169.254.169.254 | `/ssrf-chain`, `/cloud-recon` | `cloud-security` |
| **Secret / API-key leaks** | JS bundles, git, responses | `/secrets-hunt`, `tools/sourcemap_extract.py` | `web2-recon` |
| **CI/CD pipeline injection** | GH Actions, runners | `sast_scan.py`, `cicd_scanner.sh` | `cicd-security` |
| **Mobile (APK/IPA) secrets + endpoints** | mobile apps in scope | `/mobile-scan` | `mobile-pentest` |
| **Web3 smart-contract bugs** | contracts/repo | `/web3-audit`, `web3_audit.sh` | `web3-audit`, `meme-coin-audit` |
| **LLM01 Prompt injection** (direct + indirect) | any LLM/chat feature | `/llm-redteam`, `tools/llm_redteam.py` | `llm-security` |
| **LLM02 Sensitive info disclosure** | LLM outputs | `/llm-redteam` | `llm-security` |
| **LLM05 Improper output handling → XSS/SSRF/SQLi sink** | LLM output into a sink | `/llm-redteam --category output-sink` | `llm-security` |
| **LLM06 Excessive agency / tool abuse** | agentic LLM w/ tools | `/llm-redteam`, `/llm-hunt` | `llm-security` |
| **LLM07 System-prompt leakage** | LLM system prompt | `/llm-redteam` | `llm-security` |
| **LLM04 / RAG poisoning** | RAG / retrieval features | `/llm-hunt` | `llm-security` |
| **LLM10 Unbounded consumption** | LLM cost/DoS (non-destructive) | `/llm-hunt` | `llm-security` |

---

## Standard chaining recipes (always run the chaining pass)

Never report a finding in isolation. Ask **"what does this unlock?"** and try:

- IDOR → **ATO** (change email/password of another user)
- SSRF → **cloud metadata** → **IAM creds** → account/infra takeover
- Open redirect → **OAuth token / code theft** → ATO
- XSS → **session/cookie theft** or CSRF-token exfil → ATO
- Subdomain takeover → **OAuth redirect_uri** / cookie scope → ATO
- Source/JS-map leak → **secret/API key** → authenticated API abuse
- Prompt injection → **tool/function call abuse** → IDOR/SSRF via the LLM
- Info leak (userID/email) → **IDOR/BOLA** targeting
- CORS misconfig → **authenticated data exfil**
- Host-header injection → **password-reset poisoning** → ATO

See `skills/real-world-playbooks/` for real disclosed-report chains distilled per class.
