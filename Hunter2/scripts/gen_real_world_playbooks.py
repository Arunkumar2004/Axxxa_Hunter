#!/usr/bin/env python3
"""
Regenerate skills/real-world-playbooks/references/ from two public sources:
  - reddelexc/hackerone-reports   (top disclosed reports per class: technique + bounty + link)
  - Az0x7/vulnerability-Checklist  (ordered hands-on test flow per class)

Fetches live over HTTPS (no local cache kept), then writes one curated playbook per class.
Run any time to refresh as new reports land:

    python scripts/gen_real_world_playbooks.py            # fetch + regenerate
    python scripts/gen_real_world_playbooks.py --offline  # only if raw files exist in _cache

Pure stdlib. Safe to re-run; overwrites reference files deterministically.
"""
import json, os, re, sys, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "skills" / "real-world-playbooks" / "references"
RED_BASE = "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/docs/tops_by_bug_type/"
AZ_TREE = "https://api.github.com/repos/Az0x7/vulnerability-Checklist/git/trees/main?recursive=1"
AZ_BASE = "https://raw.githubusercontent.com/Az0x7/vulnerability-Checklist/main/"

# Extra real-knowledge sources (Phase 1 upgrade): real payloads + real attacker methodology.
# Each maps a class slug -> best-matching file in the repo (via git-trees API + fuzzy match).
PATT_REPO = "swisskyrepo/PayloadsAllTheThings"   # real payloads + bypasses per class
HTH_REPO = "KathanP19/HowToHunt"                  # step-by-step hunting methodology per class
AAB_REPO = "daffainfo/AllAboutBugBounty"          # concise real technique notes per class

# Phase 3 sources
WSTG_REPO = "OWASP/wstg"                           # authoritative OWASP testing methodology (permissive)
HACKTRICKS_REPO = "HackTricks-wiki/hacktricks"     # deep per-topic methodology (NC license -> short excerpt + link only)
RED_TREE = "https://api.github.com/repos/reddelexc/hackerone-reports/git/trees/master?recursive=1"
# payloadbox: one curated repo per class (each is a big real payload list). Detection only.
# payloadbox dropped: its tree API is flaky (404/rate-limit) and its payloads are
# already covered by PayloadsAllTheThings. Left as a dict so it's trivial to re-enable.
PAYLOADBOX: dict[str, str] = {}

# slug -> metadata (curated). red = reddelexc TOP stem; az = Az0x7 file basenames (path.replace('/','__').replace(' ','_'))
CLASSES = {
 "idor-bola": dict(title="IDOR / BOLA (Broken Object-Level Auth)", tier=0,
    red="TOPIDOR", az=["IDOR Vulnerability/idor.md"],
    tool="tools/h1_idor_scanner.py · tools/h1_mutation_idor.py · tools/apispec_idor.py · /api-audit",
    skill="api-security, auth-attacks",
    chain=["IDOR on email/password field → **full ATO** (no interaction)",
           "IDOR read → PII/enumeration → targeted phishing or credential-stuffing list",
           "Write/DELETE IDOR → destroy/modify other users' objects (campaigns, tickets, photos)",
           "IDOR price/quantity field → payment/business-logic abuse",
           "Decode the object id first (base64/md5/seq) — most IDORs hide behind a reversible id"]),
 "account-takeover": dict(title="Account Takeover (ATO)", tier=0,
    red="TOPACCOUNTTAKEOVER", az=["Acount takeover/ATO.md"],
    tool="/auth-hunt · tools/h1_oauth_tester.py · tools/jwt_scanner.py · tools/h1_idor_scanner.py",
    skill="auth-attacks",
    chain=["This IS the top chain sink — route IDOR / open-redirect / XSS / reset-poisoning / OAuth here",
           "Password-reset token leak/predict → set new password → ATO",
           "Email-change IDOR → change victim email → reset → ATO",
           "OAuth code/token theft via open redirect or referrer leak → ATO",
           "Session-fixation / cookie misbinding → ATO"]),
 "ssrf": dict(title="SSRF (Server-Side Request Forgery)", tier=0, red="TOPSSRF", az=[],
    tool="/ssrf-chain · tools/oob_listener.py", skill="ssrf",
    chain=["SSRF → cloud metadata (169.254.169.254 / metadata.google) → **IAM creds** → infra takeover",
           "SSRF → internal admin panels / unauthenticated internal APIs",
           "Blind SSRF → confirm via OOB (interactsh); then escalate to gopher/redis/file schemes",
           "SSRF via URL param, webhook, PDF/image/importer, XXE, or SVG"]),
 "xss": dict(title="XSS (Reflected / Stored / DOM)", tier=0, red="TOPXSS", az=["RXSS/xss.md"],
    tool="vuln_scanner.sh (dalfox+xsstrike) · /domxss · tools/dom_xss_harness.py",
    skill="web2-vuln-classes, client-side-security",
    chain=["Stored XSS in an admin-viewed field → **admin session/ATO**",
           "XSS → CSRF-token exfil → state-changing request → ATO",
           "XSS → read authed API responses (same-origin) → PII/IDOR discovery",
           "DOM XSS via postMessage / location sink — confirm in a real DOM"]),
 "business-logic": dict(title="Business Logic Abuse", tier=0, red="TOPBUSINESSLOGIC", az=["Bussiness Logic/bussiness logic.md"],
    tool="business-logic-hunter agent · tools/h1_race.py", skill="race-conditions",
    chain=["Price/quantity/currency tamper → buy for free / negative totals",
           "Coupon/referral/cashback stacking → infinite credit",
           "Workflow/state-machine skip → reach a step without paying/authorizing",
           "Quota/limit bypass via race (see race-condition playbook)"]),
 "auth-session": dict(title="Authentication & Session Flaws", tier=0, red="TOPAUTH", az=["Authentication/authentication.md"],
    tool="/auth-hunt · tools/jwt_scanner.py · tools/h1_oauth_tester.py", skill="auth-attacks",
    chain=["Weak/session-fixation → hijack → ATO",
           "Auth bypass on one endpoint → pivot to authed-only IDOR/BFLA",
           "Verbose login errors → username enumeration → spray target list"]),
 "api-auth": dict(title="API Auth (BOLA/BFLA/BOPLA/Mass-Assignment)", tier=0, red="TOPAPI",
    az=["Api Authentication /Authentication.md","Api Authorization/Authorization.md","Mass Assignment/Mass.md"],
    tool="/api-audit · tools/api_security_scanner.py · tools/apispec_idor.py", skill="api-security",
    chain=["BFLA: call admin function as low-priv user → privilege escalation",
           "Mass assignment: add role=admin / is_verified=true in JSON body → privesc",
           "BOPLA: read/write a property you shouldn't (returned but hidden in UI)",
           "Old API version (v1 vs v2) missing the auth check → BOLA"]),
 "jwt": dict(title="JWT Attacks", tier=1, red=None, az=[],
    tool="/jwt-scan · tools/jwt_scanner.py", skill="auth-attacks",
    chain=["alg:none forgery → forge any user → ATO",
           "RS256→HS256 confusion (sign with public key as HMAC secret) → forge tokens",
           "Weak HMAC secret crack (offline) → mint admin token",
           "kid header injection / jwk embedding → signature bypass"]),
 "oauth": dict(title="OAuth / OIDC Flaws", tier=1, red="TOPOAUTH", az=[],
    tool="tools/h1_oauth_tester.py · /auth-hunt", skill="auth-attacks",
    chain=["redirect_uri bypass → steal code/token → ATO",
           "Missing state param → OAuth CSRF (account linking) → ATO",
           "Referrer/open-redirect leak of code → ATO", "PKCE downgrade / code reuse"]),
 "openid": dict(title="OpenID Connect", tier=1, red="TOPOPENID", az=[],
    tool="tools/h1_oauth_tester.py · /auth-hunt", skill="auth-attacks",
    chain=["id_token signature not verified → forge identity",
           "iss/aud confusion across providers → login as anyone"]),
 "mfa-2fa": dict(title="MFA / 2FA Bypass", tier=1, red="TOPMFA", az=["2FA Bypass/2FA bypass.md"],
    tool="/auth-hunt · vuln_scanner.sh", skill="auth-attacks",
    chain=["Response-tamper (success:false→true) → skip 2FA",
           "Missing rate-limit on OTP → brute the code",
           "Backup-code / remember-device flaw → bypass",
           "2FA not enforced on one login path (OAuth/legacy/API) → bypass → ATO"]),
 "reset-password": dict(title="Password Reset Flaws", tier=1, red=None, az=["reset password/reset_password_checklist.md"],
    tool="/auth-hunt", skill="auth-attacks",
    chain=["Host-header poisoning → reset link points to attacker → token theft → ATO",
           "Token leak in referrer / predictable token → ATO",
           "Reset without invalidating session / IDOR on userId in reset → ATO"]),
 "csrf": dict(title="CSRF", tier=1, red="TOPCSRF", az=["CSRF/csrf.md"],
    tool="/csrf · tools/csrf_scanner.py", skill="client-side-security",
    chain=["CSRF on email/password change → ATO", "Login CSRF → victim uses attacker account → data capture",
           "SameSite=None + no token → cross-site state change"]),
 "cors": dict(title="CORS Misconfiguration", tier=1, red=None, az=[],
    tool="/cors · tools/cors_scanner.py", skill="client-side-security",
    chain=["ACAO reflects Origin + ACAC:true → exfil authed data cross-site",
           "null origin / suffix-match regex bypass → data theft → chain to ATO"]),
 "sqli": dict(title="SQL Injection", tier=1, red="TOPSQLI", az=[],
    tool="vuln_scanner.sh (nuclei/ghauri/sqlmap)", skill="web2-vuln-classes",
    chain=["Auth-bypass SQLi at login → ATO/admin", "Union/error → dump users+hashes → crack → ATO",
           "Blind boolean/time → confirm via OOB; stacked → RCE where supported"]),
 "nosqli": dict(title="NoSQL Injection", tier=1, red=None, az=["Json Attack/json.md"],
    tool="/nosqli · tools/nosqli_scanner.py", skill="web2-vuln-classes",
    chain=["Operator injection ($ne/$gt) at login → auth bypass → ATO", "$where JS → time-based blind extraction"]),
 "ssti": dict(title="SSTI (Template Injection)", tier=1, red="TOPSSTI", az=[],
    tool="vuln_scanner.sh", skill="web2-vuln-classes",
    chain=["SSTI → **RCE** (Jinja2/Twig/Freemarker gadget)", "Sandboxed SSTI → file read / SSRF at minimum"]),
 "rce": dict(title="Remote Code Execution", tier=1, red="TOPRCE", az=["Rce/Rce.md"],
    tool="oob_listener.py (blind) · vuln_scanner.sh · /deser-hunt", skill="web2-vuln-classes, deserialization",
    chain=["Via: upload, SSTI, deserialization, command injection, or known CVE",
           "Blind RCE → confirm via OOB DNS/HTTP callback → escalate to reverse shell (authorized)"]),
 "command-injection": dict(title="OS Command Injection", tier=1, red=None, az=[],
    tool="oob_listener.py · vuln_scanner.sh", skill="web2-vuln-classes",
    chain=["Blind cmd injection → OOB callback confirm → RCE", "Argument/flag injection into a CLI wrapped by the app"]),
 "file-upload": dict(title="File Upload", tier=1, red="TOPUPLOAD", az=["File Upload/File Upload.md"],
    tool="fuxploider (vuln_scanner.sh) · tools/multipart_mutator.py", skill="web2-vuln-classes",
    chain=["Upload webshell (ext/mime/magic bypass) → RCE", "SVG/HTML upload → stored XSS; polyglot → filter bypass",
           "Path traversal in filename → overwrite files"]),
 "path-traversal-lfi": dict(title="Path Traversal / LFI / File Reading", tier=1, red="TOPFILEREADING", az=[],
    tool="vuln_scanner.sh · manual", skill="web2-vuln-classes",
    chain=["LFI → read secrets/config → creds → authed access", "LFI + log poisoning / PHP wrappers → RCE",
           "Path traversal in download/preview/import param"]),
 "xxe": dict(title="XXE (XML External Entities)", tier=1, red="TOPXXE", az=[],
    tool="/xxe · tools/xxe_scanner.py", skill="web2-vuln-classes",
    chain=["XXE → file read (/etc/passwd, config) → secrets", "XXE → **SSRF** → cloud metadata → creds",
           "Blind XXE → OOB exfil via external DTD", "Hidden XXE in SVG/DOCX/XLSX upload, SOAP, SAML"]),
 "open-redirect": dict(title="Open Redirect", tier=1, red="TOPOPENREDIRECT", az=[],
    tool="vuln_scanner.sh · /client-side", skill="web2-vuln-classes",
    chain=["Open redirect → **OAuth token/code theft** → ATO", "Redirect → phishing on trusted domain",
           "Chain with SSRF filter bypass"]),
 "graphql": dict(title="GraphQL", tier=1, red="TOPGRAPHQL", az=[],
    tool="tools/graphql_audit.sh · /graphql-audit", skill="graphql-audit",
    chain=["Introspection on → map hidden mutations → BFLA/IDOR via aliasing",
           "Batching/alias → brute or DoS; nested query → depth bomb", "Field-level auth gap → read fields the UI hides"]),
 "prototype-pollution": dict(title="Prototype Pollution", tier=1, red=None, az=[],
    tool="/proto-pollution · tools/prototype_pollution_scanner.py", skill="client-side-security",
    chain=["Client PP + gadget → DOM XSS", "Server PP (__proto__ in JSON) → privesc / RCE gadget / DoS"]),
 "websocket-cswsh": dict(title="WebSocket / CSWSH", tier=1, red=None, az=[],
    tool="/websocket · tools/websocket_scanner.py", skill="client-side-security",
    chain=["No Origin check on WS handshake → hijack authed socket → data/actions", "Injection over WS messages"]),
 "hpp": dict(title="HTTP Parameter Pollution + postMessage", tier=1, red=None, az=[],
    tool="/hpp · tools/hpp_postmessage_scanner.py", skill="client-side-security",
    chain=["Param pollution → bypass WAF/validation, alter server parsing",
           "postMessage listener without origin check → DOM XSS / data theft"]),
 "clickjacking": dict(title="Clickjacking / UI Redress", tier=1, red="TOPCLICKJACKING", az=[],
    tool="/client-side", skill="client-side-security",
    chain=["Framing a state-change with no CSRF token → 1-click account change",
           "Only meaningful on sensitive authed actions — prove impact"]),
 "crlf-hostheader": dict(title="CRLF / Response-Splitting / Host-Header", tier=1, red=None, az=[],
    tool="/crlf · tools/crlf_scanner.py", skill="web2-vuln-classes",
    chain=["Host-header → password-reset poisoning → ATO", "CRLF → Set-Cookie injection / cache poisoning",
           "CRLF → reflected XSS via injected header"]),
 "request-smuggling": dict(title="HTTP Request Smuggling", tier=2, red="TOPREQUESTSMUGGLING", az=[],
    tool="novel-vuln-reasoner · vuln_scanner.sh", skill="web2-vuln-classes",
    chain=["CL.TE / TE.CL desync → poison next user's request → cred/session theft",
           "Smuggle → bypass front-end auth/WAF → reach internal path", "Smuggle → cache poisoning at scale"]),
 "web-cache": dict(title="Web Cache Poisoning / Deception", tier=2, red="TOPWEBCACHE", az=[],
    tool="novel-vuln-reasoner", skill="web2-vuln-classes",
    chain=["Unkeyed header reflected + cached → stored XSS to all users",
           "Cache deception (/account/foo.css) → cache victim's private page → info leak"]),
 "deserialization": dict(title="Insecure Deserialization", tier=2, red=None, az=[],
    tool="/deser-hunt · tools/deser_probe.py", skill="deserialization",
    chain=["Java/PHP/.NET/Python gadget chain → **RCE**",
           "Serialized cookie/viewstate/blob → tamper → privesc or RCE"]),
 "race-condition": dict(title="Race Conditions", tier=2, red="TOPRACECONDITION", az=["Rate limit/bypass rate limit.md"],
    tool="/race · tools/h1_race.py · business-logic-hunter", skill="race-conditions",
    chain=["Limit-overrun: redeem coupon/withdraw/transfer N× in parallel → money",
           "OTP/MFA submit race → brute past rate-limit", "TOCTOU on balance/state → double-spend"]),
 "subdomain-takeover": dict(title="Subdomain Takeover", tier=3, red="TOPSUBDOMAINTAKEOVER", az=[],
    tool="/takeover · tools/takeover_scanner.sh (DETECT-ONLY)", skill="cloud-security",
    chain=["Dangling CNAME → claim service → host content on trusted subdomain",
           "Takeover → OAuth redirect_uri / cookie-scope → ATO", "DETECT AND REPORT ONLY — never claim the resource"]),
 "info-disclosure": dict(title="Information Disclosure", tier=1, red="TOPINFODISCLOSURE", az=["exif Vulnerability/exif_geo.md"],
    tool="recon · vuln_scanner.sh · tools/secrets_hunter.sh · tools/sourcemap_extract.py", skill="web2-recon",
    chain=["Leaked userID/email → targeted IDOR/BOLA", "Leaked API key/secret (JS, .git, source map) → authed API abuse",
           "Verbose stack trace → tech stack → targeted CVE / SSTI"]),
 "cookie": dict(title="Cookie Attacks", tier=1, red=None, az=["Cookie  Attack/cookie.md"],
    tool="/auth-hunt · /crlf", skill="auth-attacks",
    chain=["Missing Secure/HttpOnly/SameSite → theft via XSS/MITM",
           "Cookie injection / scoping across subdomains → session issues"]),
 "403-bypass": dict(title="403 / 401 Access-Control Bypass", tier=1, red=None, az=["403 Bypass/403-bypass.md"],
    tool="/bypass-403", skill="web2-vuln-classes",
    chain=["Path/method/header trick reaches a forbidden admin endpoint → BFLA",
           "X-Original-URL / X-Rewrite-URL / case / trailing-slash bypass"]),
 "registration": dict(title="Registration / Signup Flaws", tier=1, red=None, az=["register vulnerability/register.md"],
    tool="/auth-hunt", skill="auth-attacks",
    chain=["Pre-account takeover (register victim email before they do)",
           "Email verification bypass → trusted account", "Duplicate/normalization (unicode, +alias, case) → collision"]),
 "admin-panel": dict(title="Admin Panel Exposure", tier=1, red=None, az=["Admin panal/adminpanal.md"],
    tool="recon · /bypass-403 · /param-discover", skill="web2-recon",
    chain=["Exposed/again-reachable admin → BFLA → full control", "Default creds / no-auth admin API"]),
 "aem": dict(title="AEM Misconfiguration", tier=2, red=None, az=["Aem misconfiguration/aem.md"],
    tool="recon · /scan-cves", skill="web2-recon",
    chain=["Adobe AEM default endpoints (Query Builder, Groovy, DAM) → info leak → RCE"]),
 "jira": dict(title="Jira Misconfiguration", tier=2, red=None, az=["Jire Vulnerability/jire.md"],
    tool="recon · /scan-cves", skill="web2-recon",
    chain=["Unauthed Jira dashboards/pickers/user-enum → info leak → SSRF/CVE"]),
 "framework": dict(title="Framework-Specific (Django / Symfony)", tier=2, red=None,
    az=["Hacking Django/Django.md","Hacking Symfony/Symfony.md"], tool="recon · sast_scan.py", skill="web2-vuln-classes",
    chain=["Debug mode → source/secret leak → SSTI/RCE", "Framework default routes / _profiler / admin"]),
 "mobile": dict(title="Mobile (APK/IPA)", tier=3, red="TOPMOBILE", az=[],
    tool="/mobile-scan", skill="mobile-pentest",
    chain=["Hardcoded secret/endpoint in APK → authed API abuse",
           "Exported activity / deeplink / WebView bridge → injection",
           "SSL-pin bypass → proxy hidden API → IDOR/BOLA"]),
 "dos": dict(title="Denial of Service (report-only class)", tier=3, red="TOPDOS", az=[],
    tool="(analyze only — NEVER run load/DoS)", skill="web2-vuln-classes",
    chain=["Algorithmic complexity / ReDoS / amplification — DESCRIBE, do not exploit",
           "Most programs treat volumetric DoS as out-of-scope; report logic-DoS carefully"]),
}

# slug -> keyword aliases used to fuzzy-match the right file/folder in each extra repo.
ALIASES = {
 "idor-bola": ["insecure direct object", "idor", "broken object level", "bola"],
 "account-takeover": ["account takeover", "ato"],
 "ssrf": ["server side request forgery", "ssrf"],
 "xss": ["xss", "cross site scripting"],
 "business-logic": ["business logic"],
 "auth-session": ["broken authentication", "authentication", "session"],
 "api-auth": ["api key", "mass assignment", "authorization", "graphql"],
 "jwt": ["jwt", "json web token"],
 "oauth": ["oauth"],
 "openid": ["openid", "oidc", "saml"],
 "mfa-2fa": ["2fa", "mfa", "two factor", "otp"],
 "reset-password": ["reset password", "password reset", "forgot password"],
 "csrf": ["csrf", "cross site request forgery"],
 "cors": ["cors"],
 "sqli": ["sql injection", "sqli"],
 "nosqli": ["nosql injection", "nosql"],
 "ssti": ["server side template injection", "ssti", "template injection"],
 "rce": ["remote code execution", "rce", "code execution", "insecure deserialization"],
 "command-injection": ["command injection", "os command", "command execution"],
 "file-upload": ["file upload", "upload insecure files", "upload"],
 "path-traversal-lfi": ["directory traversal", "path traversal", "file inclusion", "lfi"],
 "xxe": ["xxe", "xml external entity"],
 "open-redirect": ["open redirect", "open url redirection", "open url redirect"],
 "graphql": ["graphql"],
 "prototype-pollution": ["prototype pollution"],
 "websocket-cswsh": ["websocket", "cross site websocket"],
 "hpp": ["http parameter pollution", "parameter pollution"],
 "clickjacking": ["clickjacking", "ui redress"],
 "crlf-hostheader": ["crlf", "host header", "http response splitting"],
 "request-smuggling": ["request smuggling", "http smuggling"],
 "web-cache": ["web cache deception", "cache poisoning", "web cache"],
 "deserialization": ["insecure deserialization", "deserialization"],
 "race-condition": ["race condition"],
 "subdomain-takeover": ["subdomain takeover", "domain takeover"],
 "info-disclosure": ["information disclosure", "sensitive data", "exif"],
 "cookie": ["cookie"],
 "403-bypass": ["403", "forbidden bypass", "access control"],
 "registration": ["registration", "sign up", "signup", "register"],
 "admin-panel": ["admin panel", "admin"],
 "framework": ["django", "symfony", "laravel", "spring", "rails"],
 "mobile": ["mobile", "android", "ios"],
 "dos": ["denial of service", "dos"],
}

def fetch(url, timeout=45):
    req = urllib.request.Request(url, headers={"User-Agent": "hunter2-playbook-gen"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")

def _norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())

def fetch_tree_any(repo):
    """Return (blob_paths, branch) for a repo, trying master then main."""
    for br in ("master", "main"):
        try:
            data = json.loads(fetch(f"https://api.github.com/repos/{repo}/git/trees/{br}?recursive=1"))
            paths = [t["path"] for t in data.get("tree", []) if t.get("type") == "blob"]
            if paths:
                return paths, br
        except Exception as e:
            print(f"  WARN tree {repo}@{br}: {e}")
    return [], "master"

def _pick(paths, aliases, mode):
    """Pick the best path: mode 'folder_readme' -> '<Folder>/README.md'; 'root_md' -> '<File>.md'."""
    best, best_score = None, 0
    for p in paths:
        low = p.lower()
        if mode == "folder_readme":
            m = re.match(r"^([^/]+)/readme\.md$", low)
            if not m:
                continue
            name = p.split("/")[0]
        else:  # root_md
            if not re.match(r"^[^/]+\.md$", low):
                continue
            name = p[:-3]
        n = _norm(name)
        for a in aliases:
            na = _norm(a)
            if not na:
                continue
            score = 100 if na == n else (len(na) if (na in n or n in na) else 0)
            if score > best_score:
                best, best_score = p, score
    return best

def gather(repo, mode):
    """slug -> raw markdown for the best-matching file in `repo`."""
    paths, br = fetch_tree_any(repo)
    if not paths:
        return {}
    raw = f"https://raw.githubusercontent.com/{repo}/{br}/"
    out = {}
    for slug, aliases in ALIASES.items():
        p = _pick(paths, aliases, mode)
        if not p:
            continue
        try:
            out[slug] = fetch(raw + urllib.parse.quote(p))
        except Exception as e:
            print(f"  WARN {repo} {slug}: {e}")
    return out

def fetch_tree_sized(repo):
    """Return ([(path, size)], branch) trying master then main."""
    for br in ("master", "main"):
        try:
            data = json.loads(fetch(f"https://api.github.com/repos/{repo}/git/trees/{br}?recursive=1"))
            items = [(t["path"], t.get("size", 0)) for t in data.get("tree", []) if t.get("type") == "blob"]
            if items:
                return items, br
        except Exception as e:
            print(f"  WARN tree {repo}@{br}: {e}")
    return [], "master"

def _pick_deep(paths, aliases):
    """Pick the best .md at ANY depth. Name = filename (or parent folder if README)."""
    best, best_score = None, 0
    for p in paths:
        low = p.lower()
        if not low.endswith(".md"):
            continue
        parts = p.split("/")
        fname = parts[-1][:-3]
        name = parts[-2] if (fname.lower() == "readme" and len(parts) >= 2) else fname
        n = _norm(name)
        for a in aliases:
            na = _norm(a)
            if not na:
                continue
            score = 100 if na == n else (len(na) if (na in n or n in na) else 0)
            if score > best_score:
                best, best_score = p, score
    return best

def gather_deep(repo):
    """slug -> raw markdown for the best-matching .md at any depth (WSTG / HackTricks)."""
    paths, br = fetch_tree_any(repo)
    if not paths:
        return {}
    raw = f"https://raw.githubusercontent.com/{repo}/{br}/"
    out = {}
    for slug, aliases in ALIASES.items():
        p = _pick_deep(paths, aliases)
        if not p:
            continue
        try:
            out[slug] = fetch(raw + urllib.parse.quote(p))
        except Exception as e:
            print(f"  WARN {repo} {slug}: {e}")
    return out

def gather_payloadbox():
    """slug -> payload lines, picking the largest .txt in each curated payloadbox repo."""
    out = {}
    for slug, repo in PAYLOADBOX.items():
        items, br = fetch_tree_sized(repo)
        txts = [(p, s) for p, s in items if p.lower().endswith(".txt")]
        if not txts:
            continue
        txts.sort(key=lambda x: x[1], reverse=True)  # largest list first
        path = txts[0][0]
        raw = f"https://raw.githubusercontent.com/{repo}/{br}/"
        try:
            body = fetch(raw + urllib.parse.quote(path))
            lines = [l.strip() for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]
            if lines:
                out[slug] = (repo, path, lines[:40])  # cap 40 real payloads per class
        except Exception as e:
            print(f"  WARN payloadbox {slug}: {e}")
    return out

def redfill(red_data):
    """Map classes with no reddelexc reports to an available TOP*.md via alias match."""
    try:
        data = json.loads(fetch(RED_TREE))
    except Exception as e:
        print(f"  WARN reddelexc tree: {e}")
        return
    stems = {}
    for t in data.get("tree", []):
        p = t.get("path", "")
        if p.startswith("docs/tops_by_bug_type/TOP") and p.endswith(".md"):
            stem = p.split("/")[-1][:-3]  # e.g. TOPJWT
            stems[_norm(stem[3:])] = stem  # normalized name without 'TOP'
    for slug, m in CLASSES.items():
        cur = m.get("red")
        if cur and red_data.get(cur):  # already has reports
            continue
        # alias-match to an available TOP stem
        best, best_score, best_stem = None, 0, None
        for a in ALIASES.get(slug, []):
            na = _norm(a)
            for key, stem in stems.items():
                score = 100 if na == key else (len(na) if (na in key or key in na) else 0)
                if score > best_score:
                    best_score, best_stem = score, stem
        if best_stem and best_stem not in red_data:
            try:
                red_data[best_stem] = fetch(RED_BASE + best_stem + ".md")
                m["red"] = best_stem
                print(f"  redfill {slug} -> {best_stem}")
            except Exception as e:
                print(f"  WARN redfill {slug}: {e}")
        elif best_stem:
            m["red"] = best_stem

def code_blocks(md, cap=60):
    """Extract fenced code blocks (the real payloads) from a README, capped."""
    out, infence, count = [], False, 0
    for line in (md or "").splitlines():
        if line.strip().startswith("```"):
            if infence:
                out.append("```"); infence = False
            else:
                infence = True; out.append("```")
            continue
        if infence:
            out.append(line); count += 1
            if count >= cap:
                out.append("```"); break
    return "\n".join(out).strip()

def trim_md(md, cap=70):
    """Trim methodology markdown: drop images/badges/HTML, cap length."""
    lines = []
    for line in (md or "").splitlines():
        s = line.strip()
        if s.startswith("![") or s.startswith("<img") or s.startswith("<p") or s.startswith("<div"):
            continue
        if s.startswith("{{") or s.startswith("{%"):  # mdbook/hacktricks include & template directives
            continue
        # demote imported headings 2 levels so they nest under our ### subsection
        hm = re.match(r"^(#{1,6})\s+(.*)$", s)
        if hm:
            level = min(len(hm.group(1)) + 2, 6)
            line = "#" * level + " " + hm.group(2)
        lines.append(line)
        if len(lines) >= cap:
            lines.append("\n*(truncated — open the source link for the full method)*")
            break
    return "\n".join(lines).strip()

def fetch_reddelexc():
    out = {}
    for m in CLASSES.values():
        stem = m.get("red")
        if not stem or stem in out:
            continue
        try:
            out[stem] = fetch(RED_BASE + stem + ".md")
        except Exception as e:
            print(f"  WARN reddelexc {stem}: {e}")
            out[stem] = ""
    return out

def fetch_az():
    """Return {az-path: text} for every Az0x7 file referenced in CLASSES."""
    wanted = {p for m in CLASSES.values() for p in (m.get("az") or [])}
    out = {}
    for p in wanted:
        try:
            out[p] = fetch(AZ_BASE + urllib.parse.quote(p))
        except Exception as e:
            print(f"  WARN az0x7 {p}: {e}")
            out[p] = ""
    return out

def parse_reddelexc(text, topn=18):
    rows = []
    pat = re.compile(r"^\d+\.\s+\[(.+?)\]\((https://hackerone\.com/reports/\d+)\)\s+to\s+(.+?)\s+-\s+(\d+)\s+upvotes,\s+\$([0-9,]+)")
    for line in (text or "").splitlines():
        m = pat.match(line.strip())
        if m:
            title, url, prog, up, bounty = m.groups()
            rows.append((title.strip(), url, prog.strip(), int(up), int(bounty.replace(",", ""))))
    rows.sort(key=lambda r: (r[4], r[3]), reverse=True)
    return rows[:topn]

def build(red_data, az_data, patt_data, hth_data, aab_data, pb_data, wstg_data, ht_data):
    OUT.mkdir(parents=True, exist_ok=True)
    written = []
    for slug, m in CLASSES.items():
        red = parse_reddelexc(red_data.get(m.get("red"), ""), 18)
        az_body = "\n\n".join(az_data.get(p, "").strip() for p in (m.get("az") or []) if az_data.get(p, "").strip())
        patt_body = code_blocks(patt_data.get(slug, ""))
        hth_body = trim_md(hth_data.get(slug, ""))
        aab_body = trim_md(aab_data.get(slug, ""))
        pb = pb_data.get(slug)  # (repo, path, [lines]) or None
        wstg_body = trim_md(wstg_data.get(slug, ""), cap=60)
        ht_body = trim_md(ht_data.get(slug, ""), cap=22)  # HackTricks: short excerpt only (NC license)
        out = [f"# Real-World Playbook — {m['title']}\n",
               f"**Class:** `{slug}` · **Coverage-matrix tier:** {m['tier']} · **Hunter2:** {m['tool']} · **Skill:** {m['skill']}",
               "**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) "
               "(disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · "
               "[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + "
               "[payloadbox](https://github.com/payloadbox) (payloads) · "
               "[OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + "
               "[AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + "
               "[HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)\n"]
        if red:
            maxb = max(r[4] for r in red)
            progs = ", ".join(sorted({r[2] for r in red})[:8])
            out.append("## Why it pays (real bounty signal)")
            out.append(f"Top disclosed {m['title'].split('(')[0].strip()} reports peak at **${maxb:,}**. Rewarded across: {progs}.\n")
            out.append("## How real hackers found it — top disclosed reports")
            out.append("*(title = the actual technique; open the report for the full PoC)*\n")
            for title, url, prog, up, bounty in red:
                b = f"${bounty:,}" if bounty else "$0 (disclosed)"
                out.append(f"- **{title}** — {prog}, {b} · {up}👍 · [{url.split('/')[-1]}]({url})")
            out.append("")
        if az_body:
            out.append("## Test flow / checklist — do these in order")
            out.append("*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*\n")
            out.append(az_body); out.append("")
        if patt_body or pb:
            out.append("## Real payloads")
            out.append("*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*\n")
            if patt_body:
                out.append("### PayloadsAllTheThings"); out.append(patt_body); out.append("")
            if pb:
                repo, path, lines = pb
                out.append(f"### payloadbox ([{repo}](https://github.com/{repo}))")
                out.append("```"); out += lines; out.append("```"); out.append("")
        if hth_body or aab_body or wstg_body or ht_body:
            out.append("## Real attacker flow / methodology")
            out.append("*(how real hunters approach this class step by step)*\n")
            if wstg_body:
                out.append("### From OWASP WSTG (testing guide)"); out.append(wstg_body); out.append("")
            if hth_body:
                out.append("### From HowToHunt"); out.append(hth_body); out.append("")
            if aab_body:
                out.append("### From AllAboutBugBounty"); out.append(aab_body); out.append("")
            if ht_body:
                out.append("### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)")
                out.append(ht_body); out.append("")
        out.append("## Chaining — always ask \"what does this unlock?\"")
        out += [f"- {c}" for c in m["chain"]]
        out.append("")
        out.append("## Hunter2 wiring")
        out.append(f"- **Run:** `{m['tool']}`")
        out.append(f"- **Skill:** `{m['skill']}`")
        out.append(f"- **Coverage-matrix tier:** {m['tier']} (Tier 0 = test first)\n")
        (OUT / f"{slug}.md").write_text("\n".join(out), encoding="utf-8")
        written.append((slug, len(red), bool(az_body),
                        bool(patt_body or pb), bool(hth_body or aab_body or wstg_body or ht_body)))
    return written

def main():
    print("Fetching reddelexc/hackerone-reports + Az0x7/vulnerability-Checklist ...")
    red_data = fetch_reddelexc()
    az_data = fetch_az()
    print("Filling report gaps from reddelexc TOP index ...")
    redfill(red_data)
    print("Fetching PayloadsAllTheThings + payloadbox (payloads) ...")
    patt_data = gather(PATT_REPO, "folder_readme")
    pb_data = gather_payloadbox()
    print("Fetching OWASP WSTG + HowToHunt + AllAboutBugBounty + HackTricks (methodology) ...")
    wstg_data = gather_deep(WSTG_REPO)
    hth_data = gather(HTH_REPO, "folder_readme")
    aab_data = gather(AAB_REPO, "root_md")
    ht_data = gather_deep(HACKTRICKS_REPO)
    written = build(red_data, az_data, patt_data, hth_data, aab_data, pb_data, wstg_data, ht_data)
    print(f"Wrote {len(written)} playbooks to {OUT.relative_to(ROOT)}")
    for slug, nred, haz, hpatt, hmeth in written:
        print(f"  {slug:22s} reports={nred:2d} checklist={'Y' if haz else '-'} "
              f"payloads={'Y' if hpatt else '-'} method={'Y' if hmeth else '-'}")
    print("\nReminder: also copy to .claude/skills/ for Claude Code parity:")
    print("  cp -r skills/real-world-playbooks .claude/skills/real-world-playbooks")

if __name__ == "__main__":
    main()
