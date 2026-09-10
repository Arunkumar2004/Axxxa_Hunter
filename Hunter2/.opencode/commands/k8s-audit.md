---
description: Kubernetes exposure audit - unauth API server, kubelet, dashboard, ingress. Usage: k8s-audit <host[:port]>
---

# /k8s-audit

Check an exposed Kubernetes cluster for unauthenticated access.

## Run This

```bash
# Port scan for k8s ports:
python tools/port_scanner.py <host> --ports 6443,10250,10255,8080,2379,30000-30010

# API server checks (read-only):
curl -k https://<host>:6443/version
curl -k https://<host>:6443/api
curl -k https://<host>:6443/api/v1/namespaces
curl -k https://<host>:6443/apis/apps/v1/deployments

# Kubelet:
curl -k https://<host>:10250/pods          # unauth = pod spec leak (secrets)
curl -k http://<host>:10255/pods           # read-only port

# Dashboard:
curl -k https://<host>:30000/dashboard?skipLogin=1
```

Or use nuclei: `nuclei -u https://<host>:6443 -t exposures/configs/kubernetes/` (via nuclei MCP `nuclei_scan`).

## Workflow

1. `/version` reachable → API exposed. `/api` returns groups without auth → **anonymous access**.
2. List namespaces/deployments → if data returned, confirm with a second read (pods/secrets) and stop (read-only).
3. Kubelet `/pods` unauth → High. Kubelet `/run` exec → only with human approval.
4. Dashboard skip-login → High.

## Rules

- READ-ONLY unless human explicitly approves exploitation (pod exec = RCE).
- Never `kubectl apply`. Never touch production state.
- Only in-scope cloud/infra programs.

## Output

`findings/<host>/k8s-<date>.md` with raw JSON evidence (redacted).
