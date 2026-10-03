# Level 1 Phase 2 Coverage Register

This register records the classes that were previously only implied by generic skills
or scanners and now have canonical Phase 2 playbooks.

| Coverage area | Canonical playbook | Primary route | Proof requirement |
|---|---|---|---|
| SAML / SSO | `saml-sso.md` | `auth-attacks` -> `/auth-hunt` | Controlled assertion and identity-binding change |
| LLM / agentic | `llm-agentic.md` | `llm-security` -> `llm-hunter` | Sensitive disclosure or controlled tool/sink impact |
| Public cloud storage | `cloud-storage.md` | `cloud-security` -> `cloud-hunter` | Unauthorized test-object read/write/takeover |
| Kubernetes | `kubernetes.md` | `kubernetes-security` -> `/k8s-audit` | Read-only unauthorized test-namespace access |
| CI/CD supply chain | `cicd-supply-chain.md` | `cicd-security` -> scanner/source review | Isolated canary workflow execution |
| Secrets and API keys | `secrets-leak.md` | recon/cloud -> secrets tooling | Scoped validity and permission proof |
| API inventory/consumption | `api-inventory-consumption.md` | `api-security` -> `api-hunter` | Unauthorized old API or third-party trust effect |
| Resource consumption | `resource-consumption.md` | API/LLM agents -> bounded probes | Persistent controlled quota/cost effect |
| Parser differentials | `parser-differentials.md` | `novel-vuln-reasoner` | Security-sensitive interpretation difference |
| Security misconfiguration | `security-misconfiguration.md` | recon/cloud agents | Sensitive access or exploitable control bypass |

## Required Status Model

Every matrix row is persisted under `memory/coverage/<target>.json` as one of:

```text
TESTED | FOUND | N/A | BLOCKED | PENDING
```

`N/A` and `BLOCKED` require reasons. `TESTED` and `FOUND` require evidence or a result
note. Reachable `PENDING` or `BLOCKED` classes keep a hunt incomplete.

## Remaining Deepening Work

The existing playbooks for IDOR, auth, SSRF, injection, client-side, GraphQL, Web3,
mobile, and cloud chains remain active. Phase 2 should continue strengthening them
with class-specific public cases and tool-level tests; the new files above close the
largest missing-playbook gaps without replacing existing capabilities.
