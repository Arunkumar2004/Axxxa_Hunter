# Real-World Playbook — Prototype Pollution

**Class:** `prototype-pollution` · **Coverage-matrix tier:** 1 · **Hunter2:** /proto-pollution · tools/prototype_pollution_scanner.py · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Chaining — always ask "what does this unlock?"
- Client PP + gadget → DOM XSS
- Server PP (__proto__ in JSON) → privesc / RCE gadget / DoS

## Hunter2 wiring
- **Run:** `/proto-pollution · tools/prototype_pollution_scanner.py`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
