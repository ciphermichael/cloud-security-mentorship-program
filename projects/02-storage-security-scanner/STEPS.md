# 🔍 Project 02 — Storage Security Scanner: Step-by-Step Guide

> **Skill Level:** Beginner | **Time:** ~8 hours | **Week:** 2

---

## Overview

This project scans AWS S3 buckets for public exposure, missing encryption, and PII data in objects. It produces a colour-coded HTML report.

**What you'll build:**
```
storage-security-scanner/
├── src/
│   ├── scanner.py           # Main entry point
│   ├── bucket_checker.py    # S3 security configuration checks
│   ├── pii_detector.py      # PII pattern scanning
│   └── reporter.py          # HTML report generator
├── templates/
│   └── report.html.j2       # Jinja2 HTML template
├── reports/
├── tests/
└── requirements.txt
```

---

## Prerequisites

- AWS account (free tier)
- Python 3.10+
- `s3:GetBucketAcl`, `s3:GetBucketPolicy`, `s3:GetBucketEncryption`, `s3:ListBucket`, `s3:GetObject` permissions

---

## Step 1 — Project Setup

```bash
mkdir storage-security-scanner && cd storage-security-scanner
python -m venv venv && source venv/bin/activate
pip install boto3 rich jinja2 pytest moto[s3]
mkdir -p src templates reports tests
```

`requirements.txt`:
```
boto3>=1.34.0
rich>=13.0.0
jinja2>=3.1.0
pytest>=7.4.0
moto[s3]>=5.0.0
```

---

## Step 2 — Build the Bucket Configuration Checker

Create `src/bucket_checker.py`:

```python
import boto3
from botocore.exceptions import ClientError
from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class BucketResult:
    name: str
    region: str
    findings: List[Dict] = field(default_factory=list)
    
    @property
    def risk_score(self) -> int:
        scores = {'CRITICAL': 40, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5}
        return sum(scores.get(f['severity'], 0) for f in self.findings)
    
    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 40: return 'CRITICAL'
        if score >= 20: return 'HIGH'
        if score >= 10: return 'MEDIUM'
        return 'LOW'

def scan_all_buckets(profile: str = None) -> List[BucketResult]:
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    s3 = session.client('s3')
    
    buckets = s3.list_buckets().get('Buckets', [])
    results = []
    
    for bucket in buckets:
        name = bucket['Name']
        print(f"  Scanning: {name}")
        result = scan_bucket(s3, name)
        results.append(result)
    
    return sorted(results, key=lambda x: x.risk_score, reverse=True)

def scan_bucket(s3_client, bucket_name: str) -> BucketResult:
    try:
        region_info = s3_client.get_bucket_location(Bucket=bucket_name)
        region = region_info.get('LocationConstraint') or 'us-east-1'
    except ClientError:
        region = 'unknown'
    
    result = BucketResult(name=bucket_name, region=region)
    
    # Run all checks
    _check_public_access_block(s3_client, bucket_name, result)
    _check_acl(s3_client, bucket_name, result)
    _check_bucket_policy(s3_client, bucket_name, result)
    _check_encryption(s3_client, bucket_name, result)
    _check_versioning(s3_client, bucket_name, result)
    _check_logging(s3_client, bucket_name, result)
    _check_mfa_delete(s3_client, bucket_name, result)
    
    return result

def _check_public_access_block(s3, name, result):
    try:
        pab = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
        missing = [k for k, v in pab.items() if not v]
        if missing:
            result.findings.append({
                'severity': 'HIGH',
                'check': 'PUBLIC_ACCESS_BLOCK',
                'detail': f"Block Public Access settings not fully enabled: {', '.join(missing)}"
            })
    except ClientError as e:
        if 'NoSuchPublicAccessBlockConfiguration' in str(e):
            result.findings.append({
                'severity': 'CRITICAL',
                'check': 'PUBLIC_ACCESS_BLOCK',
                'detail': 'No Block Public Access configuration found — bucket may be publicly accessible'
            })

def _check_acl(s3, name, result):
    try:
        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') in (
                'http://acs.amazonaws.com/groups/global/AllUsers',
                'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
            ):
                perm = grant.get('Permission', 'UNKNOWN')
                result.findings.append({
                    'severity': 'CRITICAL',
                    'check': 'PUBLIC_ACL',
                    'detail': f"Bucket ACL grants {perm} to {grantee['URI'].split('/')[-1]}"
                })
    except ClientError:
        pass

def _check_bucket_policy(s3, name, result):
    try:
        import json
        policy = json.loads(s3.get_bucket_policy(Bucket=name)['Policy'])
        for stmt in policy.get('Statement', []):
            if stmt.get('Effect') == 'Allow' and stmt.get('Principal') in ('*', {'AWS': '*'}):
                result.findings.append({
                    'severity': 'CRITICAL',
                    'check': 'PUBLIC_BUCKET_POLICY',
                    'detail': f"Bucket policy allows public access: Action={stmt.get('Action')}"
                })
    except ClientError as e:
        if 'NoSuchBucketPolicy' not in str(e):
            pass  # Other errors are fine to ignore here

def _check_encryption(s3, name, result):
    try:
        s3.get_bucket_encryption(Bucket=name)
    except ClientError:
        result.findings.append({
            'severity': 'HIGH',
            'check': 'NO_ENCRYPTION',
            'detail': 'No default server-side encryption configured on bucket'
        })

def _check_versioning(s3, name, result):
    versioning = s3.get_bucket_versioning(Bucket=name)
    if versioning.get('Status') != 'Enabled':
        result.findings.append({
            'severity': 'MEDIUM',
            'check': 'VERSIONING_DISABLED',
            'detail': 'Object versioning is not enabled — accidental deletions cannot be recovered'
        })

def _check_logging(s3, name, result):
    logging_cfg = s3.get_bucket_logging(Bucket=name)
    if 'LoggingEnabled' not in logging_cfg:
        result.findings.append({
            'severity': 'MEDIUM',
            'check': 'NO_ACCESS_LOGGING',
            'detail': 'Server access logging is disabled — no audit trail for object access'
        })

def _check_mfa_delete(s3, name, result):
    versioning = s3.get_bucket_versioning(Bucket=name)
    if versioning.get('MFADelete') != 'Enabled':
        result.findings.append({
            'severity': 'LOW',
            'check': 'NO_MFA_DELETE',
            'detail': 'MFA Delete not enabled — objects can be permanently deleted without MFA'
        })
```

---

## Step 3 — Build the PII Detector

Create `src/pii_detector.py`:

```python
import re
import boto3
from typing import List, Dict

PII_PATTERNS = {
    'EMAIL': (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), 'HIGH'),
    'US_SSN': (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'CRITICAL'),
    'UK_NIN': (re.compile(r'\b[A-Z]{2}\d{6}[A-D]\b'), 'CRITICAL'),
    'PHONE_US': (re.compile(r'\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b'), 'MEDIUM'),
    'CREDIT_CARD': (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'), 'CRITICAL'),
    'AWS_KEY': (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'CRITICAL'),
    'PRIVATE_KEY': (re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'), 'CRITICAL'),
    'IP_ADDRESS': (re.compile(r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'), 'LOW'),
}

def scan_bucket_for_pii(bucket_name: str, max_objects: int = 10, 
                         max_bytes_per_object: int = 102400) -> List[Dict]:
    """Sample objects from a bucket and scan for PII patterns."""
    s3 = boto3.client('s3')
    findings = []
    
    try:
        objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=max_objects)
        
        for obj in objects.get('Contents', []):
            key = obj['Key']
            
            # Skip binary-looking files
            if any(key.lower().endswith(ext) for ext in ['.jpg', '.png', '.gif', '.zip', '.gz', '.tar', '.mp4']):
                continue
            
            try:
                body = s3.get_object(Bucket=bucket_name, Key=key)['Body']
                content = body.read(max_bytes_per_object).decode('utf-8', errors='ignore')
                
                for pii_type, (pattern, severity) in PII_PATTERNS.items():
                    matches = pattern.findall(content)
                    if matches:
                        findings.append({
                            'bucket': bucket_name,
                            'object_key': key,
                            'pii_type': pii_type,
                            'severity': severity,
                            'match_count': len(matches),
                            # Mask sensitive data in report
                            'sample': _mask(str(matches[0]))
                        })
            except Exception:
                continue
                
    except Exception as e:
        print(f"  [!] Could not scan {bucket_name} for PII: {e}")
    
    return findings

def _mask(value: str) -> str:
    """Mask most characters for safe display."""
    if len(value) <= 4:
        return '****'
    return value[:2] + '*' * (len(value) - 4) + value[-2:]
```

---

## Step 4 — Build the HTML Reporter

Create `src/reporter.py`:

```python
import json
from datetime import datetime
from pathlib import Path
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>S3 Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 15px; border-radius: 8px; text-align: center; flex: 1; }
        .critical { border-left: 4px solid #dc3545; }
        .high { border-left: 4px solid #fd7e14; }
        .medium { border-left: 4px solid #ffc107; }
        .low { border-left: 4px solid #28a745; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }
        th { background: #343a40; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #dee2e6; }
        .badge-critical { background: #dc3545; color: white; padding: 2px 8px; border-radius: 4px; }
        .badge-high { background: #fd7e14; color: white; padding: 2px 8px; border-radius: 4px; }
        .badge-medium { background: #ffc107; color: black; padding: 2px 8px; border-radius: 4px; }
        .badge-low { background: #28a745; color: white; padding: 2px 8px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 S3 Security Report</h1>
        <p>Generated: {{ timestamp }} | Buckets Scanned: {{ total_buckets }}</p>
    </div>
    
    <div class="summary">
        <div class="stat-card critical"><h2 style="color:#dc3545">{{ critical }}</h2><p>Critical</p></div>
        <div class="stat-card high"><h2 style="color:#fd7e14">{{ high }}</h2><p>High</p></div>
        <div class="stat-card medium"><h2 style="color:#ffc107">{{ medium }}</h2><p>Medium</p></div>
        <div class="stat-card low"><h2 style="color:#28a745">{{ low }}</h2><p>Low</p></div>
    </div>
    
    <h2>Bucket Findings</h2>
    <table>
        <tr><th>Bucket</th><th>Region</th><th>Risk</th><th>Findings</th></tr>
        {% for bucket in buckets %}
        <tr>
            <td><strong>{{ bucket.name }}</strong></td>
            <td>{{ bucket.region }}</td>
            <td><span class="badge-{{ bucket.risk_level.lower() }}">{{ bucket.risk_level }}</span></td>
            <td>{{ bucket.findings | length }} issues</td>
        </tr>
        {% for finding in bucket.findings %}
        <tr style="background:#f8f9fa">
            <td colspan="2" style="padding-left:30px; color:#666">↳ {{ finding.check }}</td>
            <td><span class="badge-{{ finding.severity.lower() }}">{{ finding.severity }}</span></td>
            <td>{{ finding.detail }}</td>
        </tr>
        {% endfor %}
        {% endfor %}
    </table>
</body>
</html>
"""

def generate_html_report(results, output_dir='reports'):
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
    
    all_findings = [f for r in results for f in r.findings]
    
    html = Template(HTML_TEMPLATE).render(
        timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
        total_buckets=len(results),
        critical=sum(1 for f in all_findings if f['severity'] == 'CRITICAL'),
        high=sum(1 for f in all_findings if f['severity'] == 'HIGH'),
        medium=sum(1 for f in all_findings if f['severity'] == 'MEDIUM'),
        low=sum(1 for f in all_findings if f['severity'] == 'LOW'),
        buckets=results
    )
    
    path = f"{output_dir}/{timestamp}-s3-security.html"
    with open(path, 'w') as f:
        f.write(html)
    print(f"[+] HTML report: {path}")
```

---

## Step 5 — Build the Main Scanner

Create `src/scanner.py`:

```python
#!/usr/bin/env python3
import argparse
from rich.console import Console
from .bucket_checker import scan_all_buckets
from .pii_detector import scan_bucket_for_pii
from .reporter import generate_html_report

console = Console()

def main():
    parser = argparse.ArgumentParser(description='S3 Storage Security Scanner')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--output', default='reports')
    parser.add_argument('--pii', action='store_true', help='Enable PII scanning (slower)')
    args = parser.parse_args()

    console.print("\n[bold blue]🔒 S3 Storage Security Scanner[/bold blue]\n")
    
    console.print("[*] Scanning S3 buckets...", style="cyan")
    results = scan_all_buckets(args.profile)
    
    if args.pii:
        console.print("[*] Running PII detection...", style="cyan")
        for result in results:
            pii_findings = scan_bucket_for_pii(result.name)
            for pf in pii_findings:
                result.findings.append({
                    'severity': pf['severity'],
                    'check': f"PII_{pf['pii_type']}",
                    'detail': f"Found {pf['match_count']} {pf['pii_type']} matches in {pf['object_key']}"
                })
    
    generate_html_report(results, args.output)
    
    console.print(f"\n[green]✅ Scanned {len(results)} buckets[/green]")
    for r in results[:5]:
        console.print(f"  [{r.risk_level}] {r.name} — {len(r.findings)} findings")

if __name__ == '__main__':
    main()
```

---

## Step 6 — Run & Test

```bash
# Run basic scan
python -m src.scanner --profile default

# Run with PII detection
python -m src.scanner --profile default --pii

# Run tests
pytest tests/ -v

# Open report in browser
open reports/*.html   # macOS
xdg-open reports/*.html  # Linux
```

---

## Step 7 — Enhancements

1. **Add Azure Blob Storage scanning** using the `azure-storage-blob` SDK
2. **Integrate AWS Macie** findings via the Macie API
3. **Add remediation functions** that fix misconfigured buckets automatically
4. **Email report** using Amazon SES
5. **Deploy as a Lambda** scheduled daily with EventBridge
