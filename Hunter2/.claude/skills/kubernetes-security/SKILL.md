---
name: kubernetes-security
description: Use when recon or port scan finds Kubernetes (6443 API, kubelet 10250, ingress, dashboard), when the target exposes container infrastructure, or when the user says "k8s", "kubernetes", "kubelet", "helm", "container". Covers unauth API server, anonymous RBAC, kubelet, exposed dashboards, misconfigured ingress, and service account abuse.
---

# Kubernetes Security

Externally-exposed clusters are high-value. Most checks are read-only and safe.

## Discovery

- `python tools/port_scanner.py <target>` — flags `6443` (API), `10250` (kubelet), `10255` (read-only kubelet), `2379` (etcd), `30000-32767` (NodePort), `8080` (legacy API).
- DNS: `k8s.`, `kube.`, `api.`, `kubernetes.` subdomains; ingress hosts.
- `nuclei` templates: `exposures/configs/kubernetes`, `exposures/configs/kubelet`.

## 1. Unauthenticated API Server (CRITICAL)

```
curl -k https://<host>:6443/version          # version leak = API exposed
curl -k https://<host>:6443/api              # anonymous access to API group list
curl -k https://<host>:6443/api/v1/namespaces
curl -k https://<host>:6443/apis/apps/v1/deployments
curl -k "https://<host>:6443/api/v1/pods"    # pods -> secrets in env, node names
```

- If `/api` returns the group list without auth → **anonymous access** (report).
- Check `system:anonymous` bindings: `curl -k https://<host>:6443/apis/rbac.authorization.k8s.io/v1/clusterrolebindings` (often restricted — only report if you can actually list resources).
- Try legacy `--insecure-port`: `:8080/api/v1/pods`.

## 2. Kubelet

- `curl -k https://<host>:10250/pods` — if returns pod spec (contains secrets/env) = **unauth kubelet** (CRITICAL).
- Read-only `10255`: `curl http://<host>:10255/pods` — pod info leak (Medium).
- `curl -k https://<host>:10250/run/<namespace>/<pod>/<container> --data "id=1" --data "cmd=id"` — RCE (only with human approval; read-only checks first).

## 3. Kubernetes Dashboard

- `https://<host>:30000` / `/dashboard` — login page. Try: skip-login (`?skipLogin=1`), default `admin/admin` (old versions), anonymous token.
- If logged in read-only → secrets/namespaces exposure (report).

## 4. Ingress / Service Exposure

- Check ingress hosts for: unauthenticated internal services (Grafana, Kibana, ArgoCD, Jenkins), debug endpoints, `/metrics` (Prometheus with sensitive info), `/debug/pprof`, exposed `kube-system` services.
- `kubectl`-style paths: `/apis`, `/api/v1/namespaces/kube-system`.

## 5. Helm / Config Leaks

- Secrets in JS bundles: `kubeconfig`, `Bearer` tokens, `ca.crt` + `client-key-data`.
- `.dockerconfigjson` secrets, `~/.kube/config` strings in repo/JS leaks → validate with `secrets_hunter.sh`.

## Safety Rules

- **Read-only only** unless human explicitly approves exploit (pod exec, create pod = RCE).
- Never `kubectl apply` anything. Never touch production namespaces' state.
- Scope: k8s assets must be in scope (usually only in cloud/infra programs).

## Evidence

- Save full JSON responses (namespaces, deployments list) as proof.
- Redact any bearer tokens/secrets found.
- Severity: unauth API (Critical), unauth kubelet exec (Critical), unauth kubelet pods (High), dashboard skip (High), anonymous RBAC read (High/Medium), pprof/metrics (Medium).

## References

- Kubernetes security checklist: https://kubernetes.io/docs/concepts/security/security-checklist/
- OWASP Kubernetes Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html
- Kube-hunter (offline): https://github.com/aquasecurity/kube-hunter
- Nuclei K8s templates: `nuclei -u https://host:6443 -t exposures/configs/kubernetes/`
