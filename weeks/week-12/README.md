# Week 12 — Kubernetes Security: RBAC, OPA, Network Policies & Falco

**Phase 3: Threat Detection & Response | Project: 11-kubernetes-threat-detection**

---

## Learning Objectives

By the end of this week you will be able to:

- Design least-privilege Kubernetes RBAC roles and bindings
- Write OPA Gatekeeper constraint templates to enforce pod security policies
- Create Network Policies that implement micro-segmentation between namespaces
- Deploy Falco in a Kubernetes cluster and write K8s-specific detection rules
- Audit cluster security with kube-bench (CIS Kubernetes Benchmark)
- Explain the top Kubernetes attack paths: `cluster-admin` abuse, privileged pods, IMDS access

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | K8s security fundamentals — RBAC, service accounts, network policies, pod security standards | 2 hrs |
| Tue | Set up local cluster with kind/minikube, deploy kube-bench, review CIS findings | 2 hrs |
| Wed | Design and apply RBAC — ClusterRoles, Roles, Bindings, service account restrictions | 2 hrs |
| Thu | OPA Gatekeeper — install, write ConstraintTemplate, apply Constraint for no-privileged-pods | 2 hrs |
| Fri | Deploy Falco in cluster, write 5 K8s-specific Falco rules, test them | 2 hrs |
| Sat | Network Policies for namespace isolation, README, push to GitHub | 3 hrs |
| Sun | Mentor review — K8s attack and defense scenario | 1 hr |

---

## Topics Covered

### Kubernetes Attack Paths

**Path 1: Overpowered service account**
> Pod has a service account with cluster-admin. Any code execution in the pod becomes cluster-level admin via the Kubernetes API server.

**Path 2: Privileged pod**
> `securityContext.privileged: true` gives the container full host kernel access. Trivial to escape to host.

**Path 3: hostPID / hostNetwork / hostPath mount**
> Sharing the host PID namespace, network namespace, or mounting host directories gives the pod significant host access.

**Path 4: API server access from pod**
> Every pod has a mounted service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. If RBAC allows cluster-admin, the token is an admin credential.

**Path 5: Etcd access**
> Etcd stores all Kubernetes secrets in base64. Direct etcd access = all secrets.

**Path 6: Instance metadata service (IMDS)**
> In cloud-managed clusters (EKS, AKS), pods can reach the IMDS if not blocked by Network Policy, potentially getting node IAM credentials.

### Kubernetes RBAC Model

```yaml
# Role — namespaced, specific permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]  # never "create", "delete", "patch"

---
# RoleBinding — attach role to subject
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: default
  name: read-pods
subjects:
  - kind: ServiceAccount
    name: monitoring-agent
    namespace: monitoring
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### Pod Security Standards

Kubernetes has 3 built-in security profiles (replace deprecated PodSecurityPolicy):
- **Privileged** — no restrictions
- **Baseline** — prevents known privilege escalation
- **Restricted** — hardened, follows current best practices

```bash
# Apply restricted standard to a namespace
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

---

## Instructor Mentoring Guidance

**Week 12 requires a local cluster.** Make sure every student has kind or minikube working before the week starts. Docker Desktop on Mac/Windows includes a built-in K8s cluster too.

**Key coaching points:**
- The `cluster-admin` ClusterRoleBinding is a loaded gun — show students what happens when they `kubectl get secrets --all-namespaces` with it
- OPA Gatekeeper can be complex — start with a simple constraint, then build up
- Falco in K8s requires DaemonSet deployment — explain why (it needs to run on every node)

**Mentoring session agenda (60 min):**
1. (10 min) Attack demo: deploy a pod with a mounted service account token, curl the API server
2. (20 min) RBAC audit — show `kubectl auth can-i --as=system:serviceaccount:default:my-sa --list`
3. (20 min) Code review of OPA policies and Network Policies
4. (10 min) Mock interview: "We found a pod running as UID 0 with hostNetwork: true. What's the blast radius?"

---

## Hands-on Lab

### Lab 1: Local Cluster Setup with kind

```bash
# Install kind
brew install kind

# Create a 3-node cluster
cat > kind-config.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
EOF

kind create cluster --name security-lab --config kind-config.yaml
kubectl cluster-info --context kind-security-lab

# Run kube-bench for CIS findings
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench
```

### Lab 2: RBAC Audit

```bash
# Check what a service account can do
kubectl auth can-i --as=system:serviceaccount:default:default --list

# Check for cluster-admin bindings (dangerous)
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | 
      {name: .metadata.name, subjects: .subjects}'

# Find all service accounts with secrets access
kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | \
  jq -r '.items[] | .subjects[]? | 
         select(.kind=="ServiceAccount") | 
         .namespace + "/" + .name'
```

### Lab 3: OPA Gatekeeper

```bash
# Install OPA Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

# Wait for it to be ready
kubectl wait --for=condition=Ready pods -l control-plane=controller-manager \
  -n gatekeeper-system --timeout=120s
```

```yaml
# policies/no-privileged-containers.yaml

# ConstraintTemplate — defines the policy logic
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdenyprivilegedcontainers
spec:
  crd:
    spec:
      names:
        kind: K8sDenyPrivilegedContainers
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdenyprivilegedcontainers

        violation[{"msg": msg}] {
            container := input.review.object.spec.containers[_]
            container.securityContext.privileged == true
            msg := sprintf("Container '%v' is running as privileged. Remove securityContext.privileged.", [container.name])
        }

        violation[{"msg": msg}] {
            container := input.review.object.spec.initContainers[_]
            container.securityContext.privileged == true
            msg := sprintf("Init container '%v' is privileged. Remove securityContext.privileged.", [container.name])
        }

---
# Constraint — applies the template
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDenyPrivilegedContainers
metadata:
  name: deny-privileged-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:  # Apply to all non-system namespaces
      - default
      - production
      - staging
```

```yaml
# policies/require-non-root.yaml
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
            container := input.review.object.spec.containers[_]
            not container.securityContext.runAsNonRoot == true
            not container.securityContext.runAsUser > 0
            msg := sprintf("Container '%v' must set runAsNonRoot: true or runAsUser > 0", [container.name])
        }

---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequireNonRoot
metadata:
  name: require-non-root
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

```yaml
# policies/no-host-namespace.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8snohostnamespace
spec:
  crd:
    spec:
      names:
        kind: K8sNoHostNamespace
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8snohostnamespace

        violation[{"msg": msg}] {
            input.review.object.spec.hostPID == true
            msg := "hostPID is not allowed. It shares the host PID namespace."
        }

        violation[{"msg": msg}] {
            input.review.object.spec.hostNetwork == true
            msg := "hostNetwork is not allowed. It shares the host network namespace."
        }

        violation[{"msg": msg}] {
            input.review.object.spec.hostIPC == true
            msg := "hostIPC is not allowed. It shares the host IPC namespace."
        }
```

### Lab 4: Network Policy — Block IMDS from Pods

```yaml
# network-policies/deny-imds.yaml
# Block access to AWS IMDS (169.254.169.254) from all pods
# Critical for EKS — prevents pods from stealing node IAM credentials

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-imds-access
  namespace: default  # Apply to each namespace
spec:
  podSelector: {}  # All pods in namespace
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32  # Block IMDS
              - 169.254.170.2/32    # Block ECS task metadata

---
# network-policies/namespace-isolation.yaml
# Only allow pods in 'frontend' namespace to talk to 'backend' namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: backend
spec:
  podSelector:
    matchLabels:
      tier: api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: frontend
          podSelector:
            matchLabels:
              tier: web
      ports:
        - protocol: TCP
          port: 8080

---
# Deny all traffic by default in production
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

### Lab 5: Falco K8s Rules

```yaml
# falco-rules/k8s-threat-rules.yaml

# Detect kubectl exec in production namespace
- rule: Terminal Shell in Production Pod
  desc: A shell was opened inside a production pod via kubectl exec
  condition: >
    spawned_process
    and container
    and k8s.ns.name = "production"
    and proc.name in (shell_binaries)
    and proc.pname in (runc, containerd-shim, docker)
  output: >
    Terminal shell opened in production pod
    (pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository
     shell=%proc.name user=%user.name)
  priority: CRITICAL
  tags: [k8s, container, T1059]

# Service account token access from unexpected process
- rule: K8s Service Account Token Read
  desc: A process other than kubectl/curl reads the service account token
  condition: >
    open_read
    and container
    and fd.name = /var/run/secrets/kubernetes.io/serviceaccount/token
    and not proc.name in (kubectl, curl, python3, python, ruby)
  output: >
    Service account token accessed unexpectedly
    (proc=%proc.name pod=%k8s.pod.name ns=%k8s.ns.name
     image=%container.image.repository)
  priority: WARNING
  tags: [k8s, credential-access, T1528]

# etcd direct access
- rule: Etcd Access Outside Normal Path
  desc: Direct access to etcd — potential secret extraction
  condition: >
    outbound
    and not container
    and fd.sport in (2379, 2380)
    and not proc.name in (etcd, etcdctl, kube-apiserver)
  output: >
    Unexpected process accessing etcd
    (proc=%proc.name pid=%proc.pid user=%user.name dest=%fd.sip:%fd.sport)
  priority: CRITICAL
  tags: [k8s, etcd, T1552]

# Pod using hostPath to access host filesystem
- rule: Sensitive Host Path Mount Used
  desc: Container accessing sensitive host path that was mounted
  condition: >
    container
    and open_read
    and fd.name startswith /host
    and not proc.name in (known_monitoring_agents)
  output: >
    Container accessing mounted host path
    (file=%fd.name proc=%proc.name pod=%k8s.pod.name
     ns=%k8s.ns.name image=%container.image.repository)
  priority: ERROR
  tags: [k8s, host-access, T1611]

# Helm chart install in production (change control violation)
- rule: Helm Install in Production
  desc: Helm deployment in production namespace without expected CI context
  condition: >
    spawned_process
    and not container
    and proc.name = helm
    and proc.args contains "install"
    and proc.args contains "production"
    and not proc.pname in (jenkins, github-actions-runner, tekton)
  output: >
    Helm install in production outside CI context
    (user=%user.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [k8s, change-management]
```

---

## Detection Queries

### KQL — AKS Kubernetes Audit Logs in Azure Sentinel

```kql
// Privileged pod created in AKS
AzureDiagnostics
| where Category == "kube-audit"
| where log_s contains '"privileged":true'
| extend
    LogEntry = parse_json(log_s),
    Verb = tostring(parse_json(log_s).verb),
    Resource = tostring(parse_json(log_s).objectRef.resource),
    Namespace = tostring(parse_json(log_s).objectRef.namespace),
    User = tostring(parse_json(log_s).user.username)
| where Verb in ("create", "patch", "update")
  and Resource == "pods"
| project TimeGenerated, User, Verb, Namespace, Resource
| order by TimeGenerated desc
```

```kql
// kubectl exec used against production pods
AzureDiagnostics
| where Category == "kube-audit"
| extend LogEntry = parse_json(log_s)
| where LogEntry.objectRef.subresource == "exec"
  and LogEntry.objectRef.namespace == "production"
| extend User = tostring(LogEntry.user.username),
         Pod = tostring(LogEntry.objectRef.name)
| project TimeGenerated, User, Pod
| order by TimeGenerated desc
```

---

## Interview Skills Gained

**Q: What is RBAC in Kubernetes and what are the most dangerous misconfigurations?**
> RBAC (Role-Based Access Control) controls what Kubernetes API actions a subject (user, group, or service account) can perform on which resources. The most dangerous misconfigurations are: (1) binding `cluster-admin` to a service account — any compromised pod gets cluster-wide admin, (2) wildcard `*` verbs on `*` resources, (3) `get`/`list` on `secrets` — reads all secrets in the cluster, (4) `create` on `pods` — can create a privileged pod.

**Q: How does OPA Gatekeeper enforce policies in Kubernetes?**
> Gatekeeper installs as an admission controller webhook. When any resource is created or modified, the API server calls Gatekeeper's webhook before the change is admitted. Gatekeeper evaluates the resource against all active Constraints using Rego policies. If a violation is found, the request is rejected with a descriptive error message. This is enforced at the API server level — you can't bypass it with `kubectl --as=admin`.

**Q: Why should you block access to the IMDS from pods in EKS?**
> In EKS, worker nodes have IAM roles. The AWS IMDS endpoint (169.254.169.254) serves temporary credentials for the node's IAM role. If a pod can reach IMDS, it can steal the node's IAM credentials, which often have significant permissions (EBS access, ECR pull, etc.). Block IMDS via NetworkPolicy or use IMDSv2 with `--metadata-options HttpPutResponseHopLimit=1` to limit token hop count.

---

## Submission Checklist

- [ ] Local K8s cluster running with kind, kube-bench results in `reports/`
- [ ] RBAC audit completed: no service accounts with cluster-admin
- [ ] 3 OPA Gatekeeper policies deployed and tested (screenshot showing blocked privileged pod)
- [ ] Network policy blocking IMDS access applied
- [ ] Namespace isolation NetworkPolicy applied between frontend and backend
- [ ] 5 Falco rules deployed via DaemonSet, test triggers documented
- [ ] README includes architecture diagram of security controls layer
- [ ] `docs/attack-paths.md` with 5 K8s attack paths and their mitigations

---

## Links

→ Full project: [projects/11-kubernetes-threat-detection/](../../projects/11-kubernetes-threat-detection/)
→ Next: [Week 13 — DevSecOps CI/CD Security Pipelines](../week-13/README.md)
