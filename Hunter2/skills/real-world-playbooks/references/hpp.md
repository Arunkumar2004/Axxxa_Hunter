# Real-World Playbook — HTTP Parameter Pollution + postMessage

**Class:** `hpp` · **Coverage-matrix tier:** 1 · **Hunter2:** /hpp · tools/hpp_postmessage_scanner.py · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Chaining — always ask "what does this unlock?"
- Param pollution → bypass WAF/validation, alter server parsing
- postMessage listener without origin check → DOM XSS / data theft

## Hunter2 wiring
- **Run:** `/hpp · tools/hpp_postmessage_scanner.py`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
