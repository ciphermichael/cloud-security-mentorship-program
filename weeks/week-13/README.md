# Week 13 — DevSecOps CI/CD Security Pipelines

**Phase 4: DevSecOps & Automation | Project: 12-devsecops-pipeline**

---

## Learning Objectives

By the end of this week you will be able to:

- Build a 7-stage security CI/CD pipeline using GitHub Actions
- Integrate SAST (Bandit/Semgrep), SCA (Safety/pip-audit), secret scanning (Gitleaks), IaC scanning (Checkov), container scanning (Trivy), and DAST (OWASP ZAP)
- Implement security gates that block deployments on HIGH+ findings
- Write a custom Semgrep rule for organization-specific security checks
- Report findings to GitHub Security (Code Scanning), Jira, and Slack
- Define and measure a security pipeline's false positive rate

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | DevSecOps principles — shift left, security gates, DAST vs SAST vs SCA definitions | 2 hrs |
| Tue | Install and run each tool locally: Bandit, Semgrep, Safety, Gitleaks, Checkov, Trivy | 2 hrs |
| Wed | Build GitHub Actions workflow — stages 1-4 (SAST, SCA, secrets, IaC) | 2 hrs |
| Thu | Add stages 5-7: container scan, DAST with ZAP, artifact generation | 2 hrs |
| Fri | Write custom Semgrep rule, tune false positives, add SARIF upload | 2 hrs |
| Sat | Full pipeline documentation, dashboard screenshots, push to GitHub | 3 hrs |
| Sun | Mentor review — live demo of pipeline failing on a vulnerability | 1 hr |

---

## Topics Covered

### DevSecOps Pipeline Stages

```
Code Commit → Push to GitHub
         ↓
Stage 1: Secret Scanning (Gitleaks)
         ↓ GATE: fail if any secrets detected
Stage 2: SAST — Static Application Security Testing (Bandit + Semgrep)
         ↓ GATE: fail if severity >= HIGH
Stage 3: SCA — Software Composition Analysis (pip-audit + Safety)
         ↓ GATE: fail if CRITICAL CVEs in dependencies
Stage 4: IaC Scanning (Checkov + tfsec)
         ↓ GATE: fail if HIGH+ misconfigurations
Stage 5: Container Image Scanning (Trivy)
         ↓ GATE: fail if CRITICAL CVEs in image
Stage 6: DAST — Dynamic Application Security Testing (OWASP ZAP)
         ↓ GATE: fail if HIGH+ findings against running app
Stage 7: SBOM Generation + Artifact Signing (Syft + Cosign)
         ↓
Deploy to environment
```

### Tool Reference Card

| Tool | Type | What It Finds | Language |
|------|------|---------------|----------|
| Bandit | SAST | Python security issues (hardcoded secrets, SQL injection, insecure deserialization) | Python |
| Semgrep | SAST | Custom + community rules, multi-language | Any |
| pip-audit | SCA | CVEs in Python package dependencies | Python |
| Safety | SCA | Known security vulnerabilities in packages | Python |
| Gitleaks | Secrets | API keys, tokens, passwords in git history | Any |
| Checkov | IaC | Terraform, CloudFormation, K8s misconfigurations | HCL/YAML/JSON |
| tfsec | IaC | Terraform-specific security checks | HCL |
| Trivy | Container | CVEs in container images + IaC configs | Any |
| OWASP ZAP | DAST | Running web app vulnerabilities (active scan) | Any |
| Syft | SBOM | Software bill of materials from container image | Any |
| Cosign | Signing | Container image signing and verification | Any |

---

## Instructor Mentoring Guidance

**Week 13 builds the most portfolio-impressive project in Phase 4.** A working DevSecOps pipeline is a tangible artifact that every hiring manager understands immediately. Students should run their pipelines against a deliberately vulnerable app to generate real findings.

**Common mistakes:**
- Using `exit-code: 0` everywhere to make all stages "pass" — teach that security gates must actually block
- Running ZAP against a production URL — only run DAST against controlled environments
- Not tuning false positives — a pipeline that always fails on noise trains people to ignore it

**Mentoring session agenda (60 min):**
1. (10 min) Demo: introduce a SQL injection into the sample app, push, watch SAST catch it
2. (20 min) Code review of the full workflow YAML — check for permission issues, secret handling
3. (20 min) Discussion: "When should you accept a finding vs fix it vs suppress it? What's the process?"
4. (10 min) Preview Week 14 — IaC security deep dive

---

## Hands-on Lab

### Lab 1: Run Each Tool Locally First

```bash
# Create a sample vulnerable Python web app
mkdir devsecops-demo && cd devsecops-demo

cat > app.py << 'EOF'
import sqlite3
import subprocess
import hashlib
import os

# VULNERABLE: SQL injection (Bandit will catch this)
def get_user(username: str) -> dict:
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULN: f-string in SQL query
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()

# VULNERABLE: Command injection
def ping_host(hostname: str) -> str:
    return subprocess.run(f"ping -c 1 {hostname}", shell=True,
                         capture_output=True, text=True).stdout

# VULNERABLE: MD5 for password hashing
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: Hardcoded secret
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
EOF

cat > requirements.txt << 'EOF'
flask==2.0.1
requests==2.25.1
cryptography==3.3.1
EOF

# Stage 1: Secret scanning
pip install detect-secrets
detect-secrets scan app.py

# Or with Gitleaks (install from GitHub releases)
gitleaks detect --source . --verbose

# Stage 2: SAST with Bandit
pip install bandit
bandit -r . -f json -o bandit-results.json
bandit -r . -l  # show findings in terminal

# Stage 2b: SAST with Semgrep
pip install semgrep
semgrep scan --config=auto app.py
semgrep scan --config=p/python app.py

# Stage 3: SCA with pip-audit
pip install pip-audit
pip-audit -r requirements.txt --format json -o pip-audit-results.json

# Stage 3b: Safety
pip install safety
safety check -r requirements.txt --json > safety-results.json
```

### Lab 2: Complete GitHub Actions Pipeline

```yaml
# .github/workflows/devsecops-pipeline.yml
name: DevSecOps Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write
  issues: write

env:
  FAIL_THRESHOLD: HIGH  # Block on HIGH or CRITICAL findings

jobs:
  # ── Stage 1: Secret Scanning ──────────────────────────────────────────────
  secret-scan:
    name: Stage 1 — Secret Scanning
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git log scanning

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}

      - name: Detect-secrets scan
        run: |
          pip install detect-secrets
          detect-secrets scan --all-files \
            --exclude-files '\.github/.*' \
            --exclude-files 'tests/fixtures/.*' \
            > .secrets.baseline
          detect-secrets audit .secrets.baseline || \
            (echo "::error::Secrets detected in codebase" && exit 1)

  # ── Stage 2: SAST ─────────────────────────────────────────────────────────
  sast:
    name: Stage 2 — SAST (Bandit + Semgrep)
    runs-on: ubuntu-latest
    needs: secret-scan
    steps:
      - uses: actions/checkout@v4

      - name: Run Bandit
        run: |
          pip install bandit[toml]
          bandit -r src/ \
            --severity-level medium \
            --confidence-level medium \
            -f sarif \
            -o bandit-results.sarif
        continue-on-error: true

      - name: Upload Bandit SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit-results.sarif
          category: bandit

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/python
            p/owasp-top-ten
            p/secrets
          generateSarif: "1"

      - name: Fail on HIGH Bandit findings
        run: |
          pip install bandit
          bandit -r src/ \
            --severity-level high \
            --confidence-level high \
            --exit-zero=false  # exit 1 on findings

  # ── Stage 3: SCA ──────────────────────────────────────────────────────────
  sca:
    name: Stage 3 — SCA (pip-audit + Safety)
    runs-on: ubuntu-latest
    needs: secret-scan
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Run pip-audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt \
            --format json \
            --output pip-audit-results.json
          # Fail on CRITICAL CVEs
          CRITICAL=$(cat pip-audit-results.json | \
            python3 -c "import json,sys; d=json.load(sys.stdin); \
            print(sum(1 for v in d.get('dependencies',[]) \
            for vuln in v.get('vulns',[]) if vuln.get('fix_versions')))")
          echo "Vulnerable packages: $CRITICAL"
          [ "$CRITICAL" -eq 0 ] || (echo "::error::CRITICAL CVEs found" && exit 1)

      - name: Run Safety
        run: |
          pip install safety
          safety check -r requirements.txt --policy-file .safety-policy.yaml || \
            (echo "::error::Safety check found vulnerabilities" && exit 1)

      - name: Upload SCA results
        uses: actions/upload-artifact@v4
        with:
          name: sca-results
          path: pip-audit-results.json

  # ── Stage 4: IaC Scanning ─────────────────────────────────────────────────
  iac-scan:
    name: Stage 4 — IaC Scanning (Checkov + tfsec)
    runs-on: ubuntu-latest
    needs: secret-scan
    steps:
      - uses: actions/checkout@v4

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: infrastructure/
          framework: terraform,cloudformation,kubernetes
          output_format: sarif
          output_file_path: checkov-results.sarif
          soft_fail: false  # Fail the build
          skip_check: CKV_AWS_79  # Example: skip specific check

      - name: Upload Checkov SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov-results.sarif
          category: checkov

      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          working_directory: infrastructure/terraform
          format: sarif
          sarif_file: tfsec-results.sarif

  # ── Stage 5: Container Scanning ───────────────────────────────────────────
  container-scan:
    name: Stage 5 — Container Scanning (Trivy)
    runs-on: ubuntu-latest
    needs: [sast, sca, iac-scan]
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t app:${{ github.sha }} .

      - name: Scan with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'app:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
          ignore-unfixed: true

      - name: Upload Trivy SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
          category: trivy

      - name: Generate SBOM with Syft
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft app:${{ github.sha }} -o spdx-json > sbom.spdx.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json

  # ── Stage 6: DAST ─────────────────────────────────────────────────────────
  dast:
    name: Stage 6 — DAST (OWASP ZAP)
    runs-on: ubuntu-latest
    needs: container-scan
    services:
      app:
        image: app:${{ github.sha }}
        ports:
          - 8080:8080
    steps:
      - name: Wait for app to start
        run: |
          for i in {1..30}; do
            curl -sf http://localhost:8080/health && break
            sleep 2
          done

      - name: Run OWASP ZAP baseline scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'  # Include alpha rules

      - name: ZAP Full Scan (on main branch only)
        if: github.ref == 'refs/heads/main'
        uses: zaproxy/action-full-scan@v0.10.0
        with:
          target: 'http://localhost:8080'
          fail_action: true

  # ── Stage 7: Report & Notify ──────────────────────────────────────────────
  report:
    name: Stage 7 — Security Report
    runs-on: ubuntu-latest
    needs: [secret-scan, sast, sca, iac-scan, container-scan, dast]
    if: always()
    steps:
      - name: Notify Slack
        uses: slackapi/slack-github-action@v1.26.0
        with:
          payload: |
            {
              "text": "Security Pipeline: ${{ job.status }} on ${{ github.ref }}",
              "blocks": [{
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Pipeline:* ${{ github.workflow }}\n*Status:* ${{ job.status }}\n*Branch:* ${{ github.ref }}"
                }
              }]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Lab 3: Custom Semgrep Rule

```yaml
# .semgrep/custom-rules.yaml
rules:
  - id: no-hardcoded-aws-region
    patterns:
      - pattern: |
          boto3.client("...", region_name="us-east-1")
    message: >
      Hardcoded AWS region detected. Use environment variable or config:
      region_name=os.environ.get('AWS_REGION', 'us-east-1')
    severity: WARNING
    languages: [python]
    metadata:
      category: security
      cwe: CWE-547

  - id: no-eval
    patterns:
      - pattern: eval(...)
    message: "eval() is dangerous — leads to code injection. Refactor."
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      cwe: CWE-95

  - id: sql-injection-fstring
    patterns:
      - pattern: |
          $CURSOR.execute(f"...{$VAR}...")
      - pattern: |
          $CURSOR.execute("..." + $VAR + "...")
    message: "SQL injection risk. Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (value,))"
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      cwe: CWE-89
      owasp: A03:2021

  - id: no-shell-true
    patterns:
      - pattern: subprocess.run(..., shell=True, ...)
      - pattern: subprocess.call(..., shell=True, ...)
      - pattern: os.system(...)
    message: >
      shell=True enables shell injection. Use a list of arguments instead:
      subprocess.run(["ping", "-c", "1", hostname])
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      cwe: CWE-78
```

---

## Interview Skills Gained

**Q: What is the difference between SAST, DAST, and SCA?**
> SAST (Static Application Security Testing) analyzes source code without executing it — catches issues like SQL injection, XSS, or hardcoded secrets at development time. DAST (Dynamic Application Security Testing) tests a running application by sending payloads — finds runtime vulnerabilities that SAST misses (configuration issues, auth flaws). SCA (Software Composition Analysis) checks third-party dependencies for known CVEs — finds supply chain risk. All three are needed for comprehensive coverage.

**Q: How do you handle false positives in a security pipeline?**
> (1) Suppress with inline annotations (`# nosec B101` for Bandit, `// nosemgrep` for Semgrep) and document why. (2) Add the finding to a `.security-ignore` or policy file with justification. (3) Create a bug/ticket and accept the risk formally. (4) Tune the rule's threshold. Never suppress without documentation — it creates a hidden risk register.

**Q: Where in a CI/CD pipeline would you run DAST and why?**
> DAST runs last in the pipeline and only against a deployed, running application in a controlled test/staging environment — never in production. It needs a live application to probe. Run it after container build and deployment to a test environment. The active scan phase can be slow (minutes to hours), so run aggressive scans nightly on a scheduled trigger, not on every commit.

---

## Submission Checklist

- [ ] All 7 pipeline stages implemented and documented in README
- [ ] Pipeline runs successfully on push (screenshot or link to Actions run)
- [ ] Pipeline blocks when a deliberate vulnerability is introduced (demo video or screenshots)
- [ ] SARIF results visible in GitHub Security → Code Scanning tab
- [ ] Custom Semgrep rule catching at least 1 real pattern
- [ ] SBOM generated and uploaded as artifact
- [ ] Slack/notification stage working

---

## Links

→ Full project: [projects/12-devsecops-pipeline/](../../projects/12-devsecops-pipeline/)
→ Next: [Week 14 — Infrastructure as Code Security](../week-14/README.md)
