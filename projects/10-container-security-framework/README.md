# 🐳 Container Security Framework

> **Week 11** | Phase 3: Threat Detection & SIEM

Docker hardening, Falco runtime detection, CI/CD container scanning integration.

## Secure Dockerfiles
See `secure_dockerfiles/` — CIS Docker Benchmark-compliant examples:

| Dockerfile | Key Controls |
|-----------|-------------|
| `python_app/` | Multi-stage build, non-root UID 1001, no setuid binaries |
| `node_app/` | Distroless runtime, read-only filesystem |
| `nginx/` | Minimal config, hidden server tokens, rate limiting |

## Falco Runtime Rules (8 rules)
See `falco_rules/` — deploy with:
```bash
helm install falco falcosecurity/falco \
  --set-file falco.rules=falco_rules/custom_rules.yaml \
  --set falco.grpc.enabled=true
```

| Rule | Severity | MITRE |
|------|----------|-------|
| Shell spawned in container | WARNING | T1059 |
| Container running as root | WARNING | T1610 |
| Sensitive file read | ERROR | T1552 |
| Crypto mining binary | CRITICAL | T1496 |
| kubectl exec detected | WARNING | T1609 |
| Container escape via privileged mount | CRITICAL | T1611 |

## Trivy Scan
```bash
trivy image your-image:tag --severity HIGH,CRITICAL --exit-code 1
trivy config Dockerfile --exit-code 1
```
