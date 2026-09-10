---
description: LLM/AI feature red-team - prompt injection, jailbreaks, system prompt leak, data exfil, output handling. Usage: llm-hunt <endpoint-url> [--type chat|agent|rag] [--corpus full|core]
---

# /llm-hunt

Red-team an AI feature (chatbot, copilot, agent, RAG).

## Run This

```bash
# Fingerprint the AI surface:
python tools/hai_probe.py <url>

# Run the categorized corpus (prompt injection, jailbreak, system-prompt leak, data exfil, indirect injection, guardrail bypass):
python tools/llm_redteam.py <endpoint> --corpus full

# Targeted single-class runs:
python tools/llm_redteam.py <endpoint> --category prompt-injection
python tools/llm_redteam.py <endpoint> --category system-prompt-leak
python tools/llm_redteam.py <endpoint> --category data-exfil

# Blind exfil confirmation (your own OOB endpoint only):
python tools/oob_listener.py --start
python tools/hai_payload_builder.py --goal exfil --callback <your-callback-domain>
```

## Workflow

1. `hai_probe.py` → confirm AI feature + endpoint + model hints.
2. `llm_redteam.py` → canary-detected successes = CONFIRMED injection.
3. For each hit, chain impact: does it call a tool, fetch a URL, leak data, reach an output sink (XSS/SQLi)?
4. System prompt leak → extract → look for tool names/endpoints/secrets.
5. Report: only with observable canary + impact.

## Rules

- Exfil only to your own interactsh/OOB endpoint, only with human approval.
- Never use the target AI to attack third parties.
- Respect program terms (some programs exclude AI abuse testing).

## Output

`findings/<target>/llm-<date>.json`; validate each confirmed finding.
