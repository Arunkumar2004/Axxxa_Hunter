# Real-World Playbook — Insecure Deserialization

**Class:** `deserialization` · **Coverage-matrix tier:** 2 · **Hunter2:** /deser-hunt · tools/deser_probe.py · **Skill:** deserialization
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Chaining — always ask "what does this unlock?"
- Java/PHP/.NET/Python gadget chain → **RCE**
- Serialized cookie/viewstate/blob → tamper → privesc or RCE

## Hunter2 wiring
- **Run:** `/deser-hunt · tools/deser_probe.py`
- **Skill:** `deserialization`
- **Coverage-matrix tier:** 2 (Tier 0 = test first)
