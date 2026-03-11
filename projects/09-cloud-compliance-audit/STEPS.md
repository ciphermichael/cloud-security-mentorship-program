# Project 09 — Cloud Compliance Audit Tool: Step-by-Step Guide

> **Skill Level:** Intermediate | **Week:** 10

## Overview
Automated CIS AWS Foundations Benchmark v2.0 + ISO 27001 compliance checker.

## Step 1 — Setup
```bash
pip install boto3 rich fpdf2 python-dotenv
mkdir -p src reports
```

## Step 2 — CIS Benchmark Checks
```python
# src/cis_checker.py
import boto3
from dataclasses import dataclass
from typing import Callable, List

@dataclass
class Control:
    id: str
    title: str
    level: int   # CIS Level 1 or 2
    check: Callable
    remediation: str

def check_1_1_root_mfa() -> dict:
    """CIS 1.5 — Root account MFA enabled"""
    iam = boto3.client('iam')
    summary = iam.get_account_summary()['SummaryMap']
    mfa_enabled = summary.get('AccountMFAEnabled', 0) == 1
    return {
        'control': '1.5',
        'title': 'Ensure MFA is enabled for the root account',
        'status': 'PASS' if mfa_enabled else 'FAIL',
        'severity': 'CRITICAL',
        'remediation': 'Enable MFA on root account via IAM console Security Credentials tab'
    }

def check_1_2_no_root_access_keys() -> dict:
    """CIS 1.4 — No root access keys"""
    iam = boto3.client('iam')
    summary = iam.get_account_summary()['SummaryMap']
    has_keys = summary.get('AccountAccessKeysPresent', 0) > 0
    return {
        'control': '1.4',
        'title': 'Ensure no root account access keys exist',
        'status': 'FAIL' if has_keys else 'PASS',
        'severity': 'CRITICAL',
        'remediation': 'Delete root access keys from IAM console'
    }

def check_2_1_cloudtrail_all_regions() -> dict:
    """CIS 3.1 — CloudTrail enabled in all regions"""
    ct = boto3.client('cloudtrail')
    trails = ct.describe_trails(includeShadowTrails=True)['trailList']
    multi_region = any(t.get('IsMultiRegionTrail') and t.get('HomeRegion') for t in trails)
    return {
        'control': '3.1',
        'title': 'Ensure CloudTrail is enabled in all regions',
        'status': 'PASS' if multi_region else 'FAIL',
        'severity': 'HIGH',
        'remediation': 'Enable CloudTrail with IsMultiRegionTrail=true'
    }

def check_2_2_cloudtrail_log_validation() -> dict:
    """CIS 3.2 — CloudTrail log file validation"""
    ct = boto3.client('cloudtrail')
    trails = ct.describe_trails(includeShadowTrails=True)['trailList']
    all_valid = all(t.get('LogFileValidationEnabled') for t in trails if t.get('IsMultiRegionTrail'))
    return {
        'control': '3.2',
        'title': 'Ensure CloudTrail log file validation is enabled',
        'status': 'PASS' if all_valid else 'FAIL',
        'severity': 'MEDIUM',
        'remediation': 'Enable log file validation on all CloudTrail trails'
    }

def check_4_1_password_policy() -> dict:
    """CIS 1.8-1.11 — Password policy"""
    iam = boto3.client('iam')
    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
        issues = []
        if policy.get('MinimumPasswordLength', 0) < 14: issues.append('MinLength<14')
        if not policy.get('RequireUppercaseCharacters'): issues.append('NoUppercase')
        if not policy.get('RequireLowercaseCharacters'): issues.append('NoLowercase')
        if not policy.get('RequireNumbers'): issues.append('NoNumbers')
        if not policy.get('RequireSymbols'): issues.append('NoSymbols')
        if not policy.get('PasswordReusePrevention'): issues.append('NoReuseCheck')
        status = 'PASS' if not issues else 'FAIL'
        detail = ', '.join(issues) if issues else 'Policy meets CIS requirements'
    except Exception:
        status, detail = 'FAIL', 'No password policy configured'
    return {'control': '1.8','title': 'Ensure IAM password policy is strong',
            'status': status, 'severity': 'HIGH', 'detail': detail,
            'remediation': 'Update password policy: min 14 chars, require all complexity types'}

ALL_CHECKS = [
    check_1_1_root_mfa,
    check_1_2_no_root_access_keys,
    check_2_1_cloudtrail_all_regions,
    check_2_2_cloudtrail_log_validation,
    check_4_1_password_policy,
]

def run_all_checks() -> list:
    results = []
    for check_fn in ALL_CHECKS:
        try:
            results.append(check_fn())
        except Exception as e:
            results.append({'control': check_fn.__name__, 'status': 'ERROR', 'detail': str(e)})
    return results
```

## Step 3 — Generate PDF Report
```python
# src/reporter.py
from fpdf import FPDF
from datetime import datetime

class ComplianceReport(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.cell(0, 10, 'Cloud Compliance Audit Report', align='C', new_x='LMARGIN', new_y='NEXT')
        self.set_font('Helvetica', '', 10)
        self.cell(0, 8, f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}',
                  align='C', new_x='LMARGIN', new_y='NEXT')
        self.ln(5)

def generate_pdf(results: list, output_path: str = 'reports/compliance.pdf'):
    pdf = ComplianceReport()
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Executive Summary', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 10)

    passed = sum(1 for r in results if r.get('status') == 'PASS')
    total  = len(results)
    score  = round(passed / total * 100) if total else 0
    pdf.cell(0, 8, f'Compliance Score: {score}% ({passed}/{total} controls passed)',
             new_x='LMARGIN', new_y='NEXT')
    pdf.ln(5)

    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 8, 'Control Results', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 9)

    for r in sorted(results, key=lambda x: x.get('status','') == 'PASS'):
        status = r.get('status','?')
        color  = (200,0,0) if status == 'FAIL' else (0,150,0)
        pdf.set_text_color(*color)
        pdf.cell(0, 7, f"[{status}] {r.get('control','?')} — {r.get('title','?')}",
                 new_x='LMARGIN', new_y='NEXT')
        if status == 'FAIL' and r.get('remediation'):
            pdf.set_text_color(100,100,100)
            pdf.set_font('Helvetica', 'I', 8)
            pdf.cell(0, 6, f"  → Remediation: {r['remediation']}", new_x='LMARGIN', new_y='NEXT')
            pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(0,0,0)

    pdf.output(output_path)
    print(f'[+] PDF report: {output_path}')
```

## Step 4 — Main
```python
# src/main.py
from .cis_checker import run_all_checks
from .reporter import generate_pdf
import json
from pathlib import Path

if __name__ == '__main__':
    Path('reports').mkdir(exist_ok=True)
    print('[*] Running CIS AWS Foundations Benchmark checks...')
    results = run_all_checks()
    passed = sum(1 for r in results if r.get('status') == 'PASS')
    print(f'\n[+] Score: {passed}/{len(results)} controls passed')
    for r in results:
        icon = '✅' if r.get('status') == 'PASS' else '❌'
        print(f'  {icon} [{r.get("control","?")}] {r.get("title","?")}')
    generate_pdf(results)
    with open('reports/compliance.json','w') as f:
        json.dump(results, f, indent=2)
```

## Step 5 — Run
```bash
python -m src.main
open reports/compliance.pdf
```
