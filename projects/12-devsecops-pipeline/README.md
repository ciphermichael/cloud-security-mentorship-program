# 🔄 DevSecOps Security Pipeline

> **Week 13** | Phase 4: DevSecOps & Automation

Complete 6-stage GitHub Actions security pipeline with automated quality gates.

## Pipeline Stages
| Stage | Tool | Fail Condition |
|-------|------|---------------|
| 🔑 Secret Scanning | gitleaks | Any secret in git history |
| 🔍 SAST | Semgrep | Critical code vulnerability |
| 📦 SCA | pip-audit + OWASP DC | Critical CVE in dependency |
| 🏗️ IaC | Checkov | Critical misconfiguration |
| 🐳 Container | Trivy | CRITICAL unpatched CVE |
| 🌐 DAST | OWASP ZAP | High web vulnerability |

## Add to Your Project
```bash
cp .github/workflows/devsecops_pipeline.yml \
   /path/to/your-project/.github/workflows/
git push  # Pipeline runs automatically on next PR
```

## Results in GitHub
- Security findings appear in **Security → Code scanning alerts**
- SARIF reports uploaded to GitHub Advanced Security
- PR blocked if quality gates fail
- Summary report on every run in Actions tab

## Interview Talking Points
- "I built a 6-stage security pipeline that catches secrets, vulnerable dependencies, and IaC misconfigs before code reaches production"
- "The pipeline reduced our security finding escape rate from 30% to under 5%"
