# Project 11 — Kubernetes Threat Detection: Step-by-Step Guide

> **Skill Level:** Intermediate-Advanced | **Week:** 12

## Overview
Harden a K8s cluster with RBAC, OPA Gatekeeper policies, NetworkPolicies, and Falco threat detection.

## Step 1 — Local K8s Cluster Setup
```bash
# Install kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x kind && sudo mv kind /usr/local/bin/

# Create cluster
kind create cluster --name security-lab

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/
kubectl cluster-info --context kind-security-lab
```

## Step 2 — RBAC Least-Privilege Configuration
```yaml
# rbac/developer-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: developer
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "update", "patch"]
  # Explicitly: NO create/delete on secrets or cluster-wide resources
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: production
subjects:
  - kind: User
    name: developer@company.com
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer
  apiGroup: rbac.authorization.k8s.io
```

```bash
kubectl apply -f rbac/developer-role.yaml
# Test: this should FAIL (correct)
kubectl auth can-i delete pods --namespace production --as developer@company.com
```

## Step 3 — OPA Gatekeeper Constraints
```bash
# Install OPA Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml
```

```yaml
# opa/no-privileged-containers.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8snoprivilegedcontainers
spec:
  crd:
    spec:
      names:
        kind: K8sNoPrivilegedContainers
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8snoprivilegedcontainers
        violation[{"msg": msg}] {
          c := input.review.object.spec.containers[_]
          c.securityContext.privileged == true
          msg := sprintf("Container %v is privileged — not allowed", [c.name])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoPrivilegedContainers
metadata:
  name: block-privileged-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

```yaml
# opa/require-non-root.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequirenonroot
spec:
  crd:
    spec:
      names:
        kind: K8sRequireNonRoot
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequirenonroot
        violation[{"msg": msg}] {
          c := input.review.object.spec.containers[_]
          not c.securityContext.runAsNonRoot
          msg := sprintf("Container %v must set runAsNonRoot: true", [c.name])
        }
```

## Step 4 — NetworkPolicy Isolation
```yaml
# network-policies/isolate-database.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-isolation
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: database
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Only allow traffic from the app tier
    - from:
        - podSelector:
            matchLabels:
              tier: application
      ports:
        - protocol: TCP
          port: 5432
  egress:
    # Allow outbound only to kube-dns
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
```

## Step 5 — Falco K8s Detection Rules
```yaml
# falco/k8s_rules.yaml

# Rule 1: kubectl exec in production
- rule: Kubectl Exec Into Production Pod
  desc: Detect exec/attach into a production namespace pod
  condition: >
    ka.verb in (exec, attach)
    and ka.target.namespace = production
    and not ka.user.name in (system:admin, ci-service-account)
  output: >
    kubectl exec detected in production (user=%ka.user.name
    pod=%ka.target.name namespace=%ka.target.namespace)
  priority: WARNING
  source: k8s_audit
  tags: [k8s, exec, T1609]

# Rule 2: Privilege escalation via role binding creation
- rule: Cluster Role Binding Created
  desc: A ClusterRoleBinding was created — potential privilege escalation
  condition: >
    ka.verb = create
    and ka.target.resource = clusterrolebindings
    and not ka.user.name in (system:serviceaccount:kube-system:clusterrole-aggregation-controller)
  output: >
    ClusterRoleBinding created (user=%ka.user.name binding=%ka.target.name)
  priority: CRITICAL
  source: k8s_audit
  tags: [k8s, rbac, T1098]

# Rule 3: Pod created in kube-system by non-admin
- rule: Unexpected Pod in kube-system
  desc: A pod was created in kube-system by a non-system user
  condition: >
    ka.verb = create and ka.target.namespace = kube-system
    and ka.target.resource = pods
    and not ka.user.name startswith system:
  output: >
    Unexpected pod created in kube-system (user=%ka.user.name pod=%ka.target.name)
  priority: CRITICAL
  source: k8s_audit
```

## Step 6 — Audit Script
```python
# src/k8s_auditor.py
import subprocess, json

def check_rbac_misconfigs() -> list:
    result = subprocess.run(['kubectl','get','clusterrolebindings','-o','json'],
                            capture_output=True, text=True)
    bindings = json.loads(result.stdout)
    findings = []
    for b in bindings.get('items', []):
        if b.get('roleRef', {}).get('name') == 'cluster-admin':
            for subject in b.get('subjects', []):
                if subject.get('kind') not in ('ServiceAccount',):
                    findings.append({
                        'severity': 'CRITICAL',
                        'check': 'CLUSTER_ADMIN_BINDING',
                        'detail': f'{subject["name"]} has cluster-admin via {b["metadata"]["name"]}'
                    })
    return findings

if __name__ == '__main__':
    findings = check_rbac_misconfigs()
    for f in findings:
        print(f'[{f["severity"]}] {f["check"]}: {f["detail"]}')
```

## Step 7 — Apply and Test
```bash
kubectl apply -f rbac/
kubectl apply -f opa/
kubectl apply -f network-policies/

# Test OPA: this should be REJECTED
kubectl run privileged-test --image=nginx --overrides='{"spec":{"containers":[{"name":"test","image":"nginx","securityContext":{"privileged":true}}]}}'
# Expected: Error from server: admission webhook denied the request

# Test NetworkPolicy
kubectl exec -it app-pod -- nc -zv database-pod 5432   # Should SUCCEED
kubectl exec -it other-pod -- nc -zv database-pod 5432  # Should FAIL
```
