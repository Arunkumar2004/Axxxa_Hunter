# Real-World Playbook — OS Command Injection

**Class:** `command-injection` · **Coverage-matrix tier:** 1 · **Hunter2:** oob_listener.py · vuln_scanner.sh · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Chaining — always ask "what does this unlock?"
- Blind cmd injection → OOB callback confirm → RCE
- Argument/flag injection into a CLI wrapped by the app

## Hunter2 wiring
- **Run:** `oob_listener.py · vuln_scanner.sh`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
