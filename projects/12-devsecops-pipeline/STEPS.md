# Project 12 — DevSecOps CI/CD Pipeline: Step-by-Step Guide

> **Skill Level:** Intermediate | **Week:** 13

## Overview
Build a 6-tool security CI/CD pipeline using GitHub Actions that fails on HIGH+ findings.

## The 6 Security Gates
| Stage | Tool | Type | Blocks On |
|-------|------|------|-----------|
| 1 | Gitleaks | Secret Scanning | Any secret found |
| 2 | Bandit | SAST (Python) | HIGH+ severity |
| 3 | Safety | SCA/Dependencies | CRITICAL CVEs |
| 4 | Checkov | IaC Security | HIGH+ misconfig |
| 5 | Trivy | Container Scan | CRITICAL CVEs |
| 6 | OWASP ZAP | DAST | HIGH+ web vuln |

## Step 1 — Full GitHub Actions Pipeline
```yaml
# .github/workflows/devsecops.yml
name: DevSecOps Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  APP_IMAGE: myapp:${{ github.sha }}

jobs:
  # ============================================================
  # STAGE 1: Secret Scanning — must run FIRST
  # ============================================================
  secret-scanning:
    name: 🔑 Secret Scanning (Gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better secret detection
      - name: Gitleaks Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  # ============================================================
  # STAGE 2: SAST — Static Analysis
  # ============================================================
  sast:
    name: 🔍 SAST (Bandit)
    runs-on: ubuntu-latest
    needs: secret-scanning
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install Bandit
        run: pip install bandit[toml]
      - name: Run Bandit
        run: |
          bandit -r src/ \
            --severity-level medium \
            --confidence-level medium \
            --format json \
            --output reports/bandit.json || true
          
          # Fail if HIGH severity issues found
          bandit -r src/ --severity-level high --exit-zero-on-skips
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: bandit-report
          path: reports/bandit.json

  # ============================================================
  # STAGE 3: SCA — Dependency Analysis
  # ============================================================
  dependency-check:
    name: 📦 SCA (Safety + pip-audit)
    runs-on: ubuntu-latest
    needs: secret-scanning
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Check Dependencies
        run: |
          pip install safety pip-audit
          pip install -r requirements.txt
          
          # Safety check (fails on CRITICAL)
          safety check --full-report --json > reports/safety.json || true
          
          # pip-audit as backup
          pip-audit --format json --output reports/pip-audit.json || true
          
          # Hard fail on critical vulns
          safety check --severity critical

  # ============================================================
  # STAGE 4: IaC Security
  # ============================================================
  iac-scan:
    name: 🏗️ IaC Security (Checkov)
    runs-on: ubuntu-latest
    needs: secret-scanning
    steps:
      - uses: actions/checkout@v4
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: infra/
          framework: terraform,cloudformation
          soft_fail: false
          output_format: sarif
          output_file_path: reports/checkov.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/checkov.sarif

  # ============================================================
  # STAGE 5: Container Scanning
  # ============================================================
  container-scan:
    name: 🐳 Container Scan (Trivy)
    runs-on: ubuntu-latest
    needs: [sast, dependency-check]
    steps:
      - uses: actions/checkout@v4
      - name: Build Image
        run: docker build -t $APP_IMAGE .
      - name: Trivy Vulnerability Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.APP_IMAGE }}
          format: 'sarif'
          output: 'reports/trivy.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/trivy.sarif

  # ============================================================
  # STAGE 6: DAST (only on PRs to main)
  # ============================================================
  dast:
    name: 🌐 DAST (OWASP ZAP)
    runs-on: ubuntu-latest
    needs: container-scan
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
      - name: Start App
        run: |
          docker run -d -p 8080:8080 --name testapp $APP_IMAGE
          sleep 10  # Wait for app to start
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-I'  # Don't fail — report only (adjust for prod)
      - name: Stop App
        run: docker stop testapp

  # ============================================================
  # FINAL: Security Summary
  # ============================================================
  security-summary:
    name: 📊 Security Summary
    runs-on: ubuntu-latest
    needs: [sast, dependency-check, iac-scan, container-scan]
    if: always()
    steps:
      - name: Print Summary
        run: |
          echo "## Security Pipeline Results" >> $GITHUB_STEP_SUMMARY
          echo "| Stage | Status |" >> $GITHUB_STEP_SUMMARY
          echo "|-------|--------|" >> $GITHUB_STEP_SUMMARY
          echo "| Secret Scanning | ${{ needs.sast.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| SAST | ${{ needs.sast.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| SCA | ${{ needs.dependency-check.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| IaC Scan | ${{ needs.iac-scan.result }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Container Scan | ${{ needs.container-scan.result }} |" >> $GITHUB_STEP_SUMMARY
```

## Step 2 — Bandit Configuration
```toml
# pyproject.toml
[tool.bandit]
exclude_dirs = ["tests", "venv"]
skips = ["B101"]  # Skip assert statements in test files
```

## Step 3 — Gitleaks Configuration
```toml
# .gitleaks.toml
title = "My Gitleaks Config"

[[rules]]
id = "custom-api-key"
description = "Custom API Key Pattern"
regex = '''MYAPP_KEY_[A-Z0-9]{32}'''
tags = ["key", "api"]

[allowlist]
description = "Global allowlist"
regexes = ['''AKIAIOSFODNN7EXAMPLE''']  # AWS example key
```

## Step 4 — Deliberate Vulnerable App (for testing)
```python
# src/vulnerable_app.py — intentionally insecure for testing the pipeline
import subprocess, os, sqlite3

def get_user(username):
    # BANDIT: B608 — SQL injection
    conn = sqlite3.connect('users.db')
    return conn.execute(f"SELECT * FROM users WHERE name = '{username}'").fetchall()

def run_command(cmd):
    # BANDIT: B602 — Shell injection
    return subprocess.check_output(cmd, shell=True)

SECRET_KEY = "hardcoded-super-secret-1234"  # GITLEAKS will catch this
```

## Step 5 — Run Pipeline Locally (act)
```bash
# Install act for local GitHub Actions testing
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run the full pipeline locally
act push --secret GITHUB_TOKEN=$GITHUB_TOKEN

# Run just the SAST job
act push -j sast
```
