# Real-World Playbook — JWT Attacks

**Class:** `jwt` · **Coverage-matrix tier:** 1 · **Hunter2:** /jwt-scan · tools/jwt_scanner.py · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Chaining — always ask "what does this unlock?"
- alg:none forgery → forge any user → ATO
- RS256→HS256 confusion (sign with public key as HMAC secret) → forge tokens
- Weak HMAC secret crack (offline) → mint admin token
- kid header injection / jwk embedding → signature bypass

## Hunter2 wiring
- **Run:** `/jwt-scan · tools/jwt_scanner.py`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
