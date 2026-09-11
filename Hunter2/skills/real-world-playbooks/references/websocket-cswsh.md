# Real-World Playbook — WebSocket / CSWSH

**Class:** `websocket-cswsh` · **Coverage-matrix tier:** 1 · **Hunter2:** /websocket · tools/websocket_scanner.py · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Chaining — always ask "what does this unlock?"
- No Origin check on WS handshake → hijack authed socket → data/actions
- Injection over WS messages

## Hunter2 wiring
- **Run:** `/websocket · tools/websocket_scanner.py`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
