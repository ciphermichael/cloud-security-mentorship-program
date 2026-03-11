# 📅 Week 12 — Kubernetes Security — RBAC, OPA, Network Policies

**Phase 3 | Project: 11-kubernetes-threat-detection**

---

## 🎯 Learning Objectives

-e - Design least-privilege K8s RBAC
- Write OPA Gatekeeper policies
- Implement Network Policies to restrict pod communication
- Detect threats with Falco in a K8s cluster

---

## 📅 Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | Core concepts study & reading | 2 hrs |
| Tue | Labs / hands-on exercises | 2 hrs |
| Wed | Start weekly assignment | 2 hrs |
| Thu | Continue assignment build | 2 hrs |
| Fri | Complete assignment + testing | 2 hrs |
| Sat | Polish, document, push to GitHub | 3 hrs |
| Sun | Review, mentor check-in, next week prep | 1 hr |

---

## 📝 Weekly Assignment

Deploy a local K8s cluster (kind or minikube). Implement: RBAC roles that block cluster-admin, an OPA policy blocking privileged pods, a NetworkPolicy isolating the database namespace, and Falco alerts for kubectl exec in production.

### Acceptance Criteria

- [ ] All code pushed to GitHub with meaningful commits
- [ ] README updated with week's work
- [ ] At least one diagram or screenshot documenting the work
- [ ] Reflection paragraph added to project NOTES.md

---

## ✅ Submission Checklist

- [ ] GitHub link sent to mentor
- [ ] All acceptance criteria marked complete
- [ ] Reflection written
- [ ] Next week reading started

---

## 🔗 Links

→ Project folder: [`projects/11-kubernetes-threat-detection/`](../../projects/11-kubernetes-threat-detection/)
→ Step-by-step guide: [`projects/11-kubernetes-threat-detection/STEPS.md`](../../projects/11-kubernetes-threat-detection/STEPS.md)
