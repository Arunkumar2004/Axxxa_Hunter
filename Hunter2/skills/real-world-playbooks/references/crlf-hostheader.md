# Real-World Playbook — CRLF / Response-Splitting / Host-Header

**Class:** `crlf-hostheader` · **Coverage-matrix tier:** 1 · **Hunter2:** /crlf · tools/crlf_scanner.py · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Chaining — always ask "what does this unlock?"
- Host-header → password-reset poisoning → ATO
- CRLF → Set-Cookie injection / cache poisoning
- CRLF → reflected XSS via injected header

## Hunter2 wiring
- **Run:** `/crlf · tools/crlf_scanner.py`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
