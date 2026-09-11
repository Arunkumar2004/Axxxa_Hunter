# Real-World Playbook — CORS Misconfiguration

**Class:** `cors` · **Coverage-matrix tier:** 1 · **Hunter2:** /cors · tools/cors_scanner.py · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Chaining — always ask "what does this unlock?"
- ACAO reflects Origin + ACAC:true → exfil authed data cross-site
- null origin / suffix-match regex bypass → data theft → chain to ATO

## Hunter2 wiring
- **Run:** `/cors · tools/cors_scanner.py`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
