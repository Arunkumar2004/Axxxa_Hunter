# Real-World Playbook - LLM and Agentic Security

**Class:** `llm-agentic` · **Coverage-matrix tier:** 3 · **Hunter2:** `/llm-redteam` · `/llm-hunt` · `tools/llm_redteam.py` · **Skill:** llm-security

**Route:** `llm-security` -> `llm-hunter` -> `/llm-redteam` or `/llm-hunt` -> controlled
canary/side-effect proof -> validator/report-writer.

## Conditions

- A target exposes an LLM, retrieval feature, tool/function call, or model output sink.
- Test data and tool permissions are explicitly authorized.

## Safe method

- Separate direct, indirect, multimodal, and retrieval-originated inputs.
- Use canary data to test prompt/system leakage and retrieval boundaries.
- Test tool authorization with read-only mock tools before any state-changing action.
- Check output sinks for controlled markers, not real external data.
- Bound token/cost tests and stop before service degradation.

## Proof and rejection

- Prompt text alone is not a vulnerability; prove sensitive disclosure, unauthorized
  tool action, cross-tenant data access, or a controlled sink execution.
- Reject jailbreak success without impact, fictional model claims, and uncorrelated
  output differences.
- Redact system prompts, secrets, personal data, and tool credentials.

## Test flow / checklist — do these in order
*(public methodology — OWASP GenAI/LLM Top 10 2025 / OWASP AI testing / NIST AI taxonomy; run each, mark result in the coverage matrix)*

[ ] Map the LLM surface: chat, completions, RAG/retrieval, tools/function-calls, agents, multimodal (image/file) inputs
[ ] Separate input channels — direct prompt, indirect (RAG doc, webpage, email, file), and multimodal
[ ] Test direct prompt injection to override system instructions (LLM01) using a benign canary instruction
[ ] Test indirect/RAG injection: plant a canary instruction in a retrievable document and see if the model obeys it (LLM01/LLM04)
[ ] Test system-prompt / config leakage with canary probes (LLM07); confirm sensitive content, not guesses
[ ] Test sensitive-info disclosure — does the model reveal other users' data, secrets, or training data (LLM02)?
[ ] Enumerate agent tools/functions; test excessive agency — can you invoke a tool or state-changing action you shouldn't (LLM06)?
[ ] Use read-only/mock tools first; test state-changing tool actions only with explicit authorization and a canary
[ ] Test improper output handling: make the model emit a marker payload that lands in a downstream XSS/SSRF/SQLi sink (LLM05)
[ ] Test cross-tenant/RAG boundary — can your session retrieve another tenant's indexed data?
[ ] Bound any cost/consumption test (LLM10) with wide margins; stop before service degradation
[ ] Redact leaked system prompts, secrets, PII, and tool credentials in evidence

## What gets this rejected (kill before you write)
*(from `skills/triage-validation/SKILL.md` — one wrong answer = kill it and move on)*

- Jailbreak / policy-refusal bypass with no downstream impact (just making the model say something).
- "The model followed my instruction" without sensitive disclosure, unauthorized tool action, or a real sink.
- Fictional/hallucinated model claims (the model "says" it can do X) with no proven action.
- Uncorrelated output differences or non-deterministic quirks.
- System-prompt content that is public/documented, or a canary you planted echoed back with no cross-user impact.
- Cost/DoS tests that degrade the live service — do not run them.
- **Conditionally valid (only WITH a chain):** prompt injection → tool/function abuse reading another user's data (IDOR) or SSRF/SQLi via the LLM; improper output handling → executed XSS/SSRF/SQLi in a downstream sink.

## Sources

OWASP GenAI/AI Testing guidance, NIST AI vulnerability taxonomy, and Hunter2's existing
`llm-security` skill and `llm_redteam.py`.
