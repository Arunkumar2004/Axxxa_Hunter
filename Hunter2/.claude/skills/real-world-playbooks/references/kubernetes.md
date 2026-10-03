# Real-World Playbook - Kubernetes Exposure

**Class:** `kubernetes` · **Coverage-matrix tier:** 3 · **Hunter2:** `/k8s-audit` · **Skill:** kubernetes-security

**Route:** `kubernetes-security` -> `cloud-hunter`/primary `hunter` -> `/k8s-audit` ->
read-only RBAC or test-namespace proof -> validator/report-writer.

## Conditions

- Kubernetes API, kubelet, dashboard, ingress, registry, or cloud control plane is in scope.

## Safe method

- Check anonymous discovery and authorization with read-only requests.
- Enumerate only a permitted test namespace and inspect effective RBAC.
- Check dashboard exposure, service-account token scope, and ingress isolation.

## Proof and rejection

- Confirm only with unauthorized read/action in an owned test namespace or clearly
  exposed sensitive configuration.
- Reject version banners, health endpoints, and public service metadata alone.
- Never create workloads, retrieve production secrets, or alter cluster state.

## Test flow / checklist — do these in order
*(public methodology — CISA/NSA k8s hardening / Kubernetes security checklist / HackTricks k8s; run each, mark result in the coverage matrix)*

[ ] Discover exposed components: API server (6443/8443), kubelet (10250/10255), etcd (2379), Dashboard, cAdvisor, ingress
[ ] Test anonymous access to the API server (`/version`, `/api`, `/apis`) and whether `system:anonymous` can list resources
[ ] Check kubelet endpoints (`/pods`, `/runningpods`, `/metrics`) for anonymous exposure
[ ] Look for an exposed Kubernetes Dashboard reachable without auth or with a privileged default service account
[ ] Enumerate effective RBAC for your identity (`kubectl auth can-i --list`) — only in a permitted test namespace
[ ] Check for a mounted/leaked service-account token and its scope (namespace vs cluster-wide)
[ ] Inspect ingress isolation and whether internal services are reachable through it
[ ] Check for secrets/configmaps readable by your effective permissions in the test namespace
[ ] Look for cloud control-plane exposure (managed-k8s metadata, IMDS reachable from a pod)
[ ] Prove impact only with an unauthorized read/action in your owned test namespace or a clearly exposed sensitive config — never create workloads or alter cluster state

## What gets this rejected (kill before you write)
*(from `skills/triage-validation/SKILL.md` — one wrong answer = kill it and move on)*

- Version banners, `/healthz`, `/version`, or public service metadata alone.
- A Dashboard login page reachable but no access obtained.
- RBAC that denies your requests — that is a working permission boundary, not a bug.
- Anything that requires creating workloads, retrieving production secrets, or changing cluster state.
- Exposed metrics/health endpoints with no sensitive data.
- Clusters/components outside the program's scope.
- **Conditionally valid (only WITH a chain):** anonymous API/kubelet access → read secrets or pod exec; leaked service-account token → cross-namespace access; IMDS from a pod → cloud IAM creds.

## Sources

CISA/NSA Kubernetes hardening guidance, Kubernetes security checklist, and Hunter2's
`kubernetes-security` skill.
