# ☸️ Kubernetes Threat Detection

> **Week 12** | Phase 3: Threat Detection & SIEM

K8s RBAC hardening + OPA Gatekeeper admission policies + Falco runtime detection + network segmentation.

## Deploy OPA Gatekeeper
```bash
# Install Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

# Apply policies
kubectl apply -f opa_policies/
```

## OPA Policies
| Policy File | What It Blocks |
|-------------|---------------|
| `no_privileged_containers.rego` | `securityContext.privileged: true` |
| `require_non_root.rego` | `runAsUser: 0` or missing non-root requirement |
| `no_host_network.rego` | `hostNetwork`, `hostPID`, `hostIPC` |

## Network Policies
```bash
# Apply default-deny + selective allow
kubectl apply -f network_policies/default_deny.yaml
```

## Falco Rules
See `falco/custom_rules.yaml` — 8 runtime detection rules including:
- Shell spawned in container
- Crypto miner execution
- kubectl exec detected
- Write to /etc inside container

## RBAC Hardening
```bash
kubectl apply -f rbac/
```
