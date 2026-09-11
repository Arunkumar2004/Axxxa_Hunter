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

def fetch(url, timeout=45):
    req = urllib.request.Request(url, headers={"User-Agent": "hunter2-playbook-gen"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")

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

def build(red_data, az_data):
    OUT.mkdir(parents=True, exist_ok=True)
    written = []
    for slug, m in CLASSES.items():
        red = parse_reddelexc(red_data.get(m.get("red"), ""), 18)
        az_body = "\n\n".join(az_data.get(p, "").strip() for p in (m.get("az") or []) if az_data.get(p, "").strip())
        out = [f"# Real-World Playbook — {m['title']}\n",
               f"**Class:** `{slug}` · **Coverage-matrix tier:** {m['tier']} · **Hunter2:** {m['tool']} · **Skill:** {m['skill']}",
               "**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) "
               "(disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)\n"]
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
        out.append("## Chaining — always ask \"what does this unlock?\"")
        out += [f"- {c}" for c in m["chain"]]
        out.append("")
        out.append("## Hunter2 wiring")
        out.append(f"- **Run:** `{m['tool']}`")
        out.append(f"- **Skill:** `{m['skill']}`")
        out.append(f"- **Coverage-matrix tier:** {m['tier']} (Tier 0 = test first)\n")
        (OUT / f"{slug}.md").write_text("\n".join(out), encoding="utf-8")
        written.append((slug, len(red), bool(az_body)))
    return written

def main():
    print("Fetching reddelexc/hackerone-reports + Az0x7/vulnerability-Checklist ...")
    red_data = fetch_reddelexc()
    az_data = fetch_az()
    written = build(red_data, az_data)
    print(f"Wrote {len(written)} playbooks to {OUT.relative_to(ROOT)}")
    for slug, nred, haz in written:
        print(f"  {slug:22s} reports={nred:2d} checklist={'Y' if haz else '-'}")
    print("\nReminder: also copy to .claude/skills/ for Claude Code parity:")
    print("  cp -r skills/real-world-playbooks .claude/skills/real-world-playbooks")

if __name__ == "__main__":
    main()
