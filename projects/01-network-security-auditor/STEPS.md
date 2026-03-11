# 🔍 Project 01 — Network Security Auditor: Step-by-Step Guide

> **Skill Level:** Beginner | **Time:** ~8 hours | **Week:** 1

---

## Overview

This project scans AWS VPCs and Security Groups for dangerous misconfigurations. It produces a JSON + HTML report with severity-graded findings.

**What you'll build:**
```
auditor/
├── src/
│   ├── auditor.py          # Main entry point
│   ├── sg_checker.py       # Security Group checks
│   ├── vpc_checker.py      # VPC/Flow Log checks
│   └── reporter.py         # JSON + HTML report generator
├── reports/                # Output reports land here
├── tests/
│   └── test_sg_checker.py
├── requirements.txt
└── README.md
```

---

## Prerequisites

- AWS account (free tier)
- Python 3.10+
- AWS CLI configured (`aws configure`)
- IAM user/role with `ec2:Describe*` and `logs:Describe*` permissions

---

## Step 1 — Set Up the Project

```bash
mkdir network-security-auditor && cd network-security-auditor
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install boto3 rich jinja2 pytest moto

# Create folder structure
mkdir -p src reports tests
touch src/__init__.py src/auditor.py src/sg_checker.py src/vpc_checker.py src/reporter.py
touch tests/__init__.py tests/test_sg_checker.py
touch requirements.txt README.md
```

Write `requirements.txt`:
```
boto3>=1.34.0
rich>=13.0.0
jinja2>=3.1.0
pytest>=7.4.0
moto[ec2]>=5.0.0
```

---

## Step 2 — Build the Security Group Checker

Create `src/sg_checker.py`:

```python
import boto3
from dataclasses import dataclass, field
from typing import List, Optional

DANGEROUS_PORTS = {
    22: ('SSH', 'CRITICAL'),
    3389: ('RDP', 'CRITICAL'),
    3306: ('MySQL', 'HIGH'),
    5432: ('PostgreSQL', 'HIGH'),
    1433: ('MSSQL', 'HIGH'),
    27017: ('MongoDB', 'HIGH'),
    6379: ('Redis', 'HIGH'),
    9200: ('Elasticsearch', 'HIGH'),
    443: ('HTTPS', 'MEDIUM'),
    80: ('HTTP', 'MEDIUM'),
}

@dataclass
class SGFinding:
    sg_id: str
    sg_name: str
    vpc_id: str
    port: int
    protocol: str
    cidr: str
    service: str
    severity: str
    description: str

def check_security_groups(region: str) -> List[SGFinding]:
    """Scan all security groups in a region for open ingress rules."""
    ec2 = boto3.client('ec2', region_name=region)
    paginator = ec2.get_paginator('describe_security_groups')
    
    findings = []
    
    for page in paginator.paginate():
        for sg in page['SecurityGroups']:
            findings.extend(_check_sg(sg))
    
    return findings

def _check_sg(sg: dict) -> List[SGFinding]:
    findings = []
    
    for rule in sg.get('IpPermissions', []):
        from_port = rule.get('FromPort', -1)
        to_port = rule.get('ToPort', -1)
        protocol = rule.get('IpProtocol', 'tcp')
        
        # Check IPv4 open CIDRs
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') in ('0.0.0.0/0',):
                finding = _create_finding(sg, from_port, to_port, protocol, ip_range['CidrIp'])
                if finding:
                    findings.append(finding)
        
        # Check IPv6 open CIDRs  
        for ip_range in rule.get('Ipv6Ranges', []):
            if ip_range.get('CidrIpv6') in ('::/0',):
                finding = _create_finding(sg, from_port, to_port, protocol, ip_range['CidrIpv6'])
                if finding:
                    findings.append(finding)
    
    return findings

def _create_finding(sg, from_port, to_port, protocol, cidr) -> Optional[SGFinding]:
    # All traffic rule
    if protocol == '-1':
        return SGFinding(
            sg_id=sg['GroupId'],
            sg_name=sg.get('GroupName', 'N/A'),
            vpc_id=sg.get('VpcId', 'N/A'),
            port=-1,
            protocol='ALL',
            cidr=cidr,
            service='ALL TRAFFIC',
            severity='CRITICAL',
            description=f"Security group allows ALL inbound traffic from {cidr}"
        )
    
    # Specific port checks
    if from_port in DANGEROUS_PORTS:
        service, severity = DANGEROUS_PORTS[from_port]
        return SGFinding(
            sg_id=sg['GroupId'],
            sg_name=sg.get('GroupName', 'N/A'),
            vpc_id=sg.get('VpcId', 'N/A'),
            port=from_port,
            protocol=protocol,
            cidr=cidr,
            service=service,
            severity=severity,
            description=f"Port {from_port} ({service}) open to the internet from {cidr}"
        )
    
    return None
```

---

## Step 3 — Build the VPC Checker

Create `src/vpc_checker.py`:

```python
import boto3
from dataclasses import dataclass
from typing import List

@dataclass  
class VPCFinding:
    vpc_id: str
    vpc_name: str
    cidr: str
    severity: str
    issue: str
    description: str

def check_vpcs(region: str) -> List[VPCFinding]:
    ec2 = boto3.client('ec2', region_name=region)
    findings = []
    
    vpcs = ec2.describe_vpcs(Filters=[{'Name': 'state', 'Values': ['available']}])['Vpcs']
    
    for vpc in vpcs:
        vpc_id = vpc['VpcId']
        vpc_name = next((t['Value'] for t in vpc.get('Tags', []) if t['Key'] == 'Name'), 'Unnamed')
        
        # Check for flow logs
        flow_logs = ec2.describe_flow_logs(
            Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
        )['FlowLogs']
        
        if not flow_logs:
            findings.append(VPCFinding(
                vpc_id=vpc_id,
                vpc_name=vpc_name,
                cidr=vpc.get('CidrBlock', 'N/A'),
                severity='HIGH',
                issue='NO_FLOW_LOGS',
                description=f"VPC {vpc_id} has no VPC Flow Logs enabled — network traffic is unaudited"
            ))
        else:
            # Check if any flow log is in ACTIVE state
            active = [fl for fl in flow_logs if fl.get('FlowLogStatus') == 'ACTIVE']
            if not active:
                findings.append(VPCFinding(
                    vpc_id=vpc_id,
                    vpc_name=vpc_name,
                    cidr=vpc.get('CidrBlock', 'N/A'),
                    severity='HIGH',
                    issue='FLOW_LOGS_NOT_ACTIVE',
                    description=f"VPC {vpc_id} has flow logs configured but none are ACTIVE"
                ))
        
        # Check for default VPC usage
        if vpc.get('IsDefault'):
            findings.append(VPCFinding(
                vpc_id=vpc_id,
                vpc_name='DEFAULT',
                cidr=vpc.get('CidrBlock', 'N/A'),
                severity='MEDIUM',
                issue='DEFAULT_VPC_IN_USE',
                description="Default VPC detected — resources should use dedicated VPCs with custom network design"
            ))
    
    return findings
```

---

## Step 4 — Build the Reporter

Create `src/reporter.py`:

```python
import json
from datetime import datetime
from pathlib import Path
from typing import List
from .sg_checker import SGFinding
from .vpc_checker import VPCFinding

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

def generate_report(sg_findings: List[SGFinding], vpc_findings: List[VPCFinding], 
                    region: str, output_dir: str = 'reports') -> dict:
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
    
    report = {
        'report_metadata': {
            'timestamp': datetime.utcnow().isoformat(),
            'region': region,
            'tool': 'Network Security Auditor v1.0',
        },
        'summary': {
            'total_findings': len(sg_findings) + len(vpc_findings),
            'critical': sum(1 for f in sg_findings + vpc_findings if f.severity == 'CRITICAL'),
            'high': sum(1 for f in sg_findings + vpc_findings if f.severity == 'HIGH'),
            'medium': sum(1 for f in sg_findings + vpc_findings if f.severity == 'MEDIUM'),
        },
        'security_group_findings': [vars(f) for f in sorted(sg_findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9))],
        'vpc_findings': [vars(f) for f in sorted(vpc_findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9))],
    }
    
    json_path = f"{output_dir}/{timestamp}-network-audit.json"
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"[+] JSON report saved: {json_path}")
    return report
```

---

## Step 5 — Build the Main Entry Point

Create `src/auditor.py`:

```python
#!/usr/bin/env python3
"""AWS Network Security Auditor — Main Entry Point"""

import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich import box

from .sg_checker import check_security_groups
from .vpc_checker import check_vpcs
from .reporter import generate_report

console = Console()

def main():
    parser = argparse.ArgumentParser(description='AWS Network Security Auditor')
    parser.add_argument('--region', default='us-east-1', help='AWS region to scan')
    parser.add_argument('--output', default='reports', help='Output directory for reports')
    args = parser.parse_args()

    console.print(f"\n[bold blue]🔍 AWS Network Security Auditor[/bold blue]")
    console.print(f"Region: [yellow]{args.region}[/yellow]\n")

    # Run checks
    console.print("[*] Scanning Security Groups...", style="cyan")
    sg_findings = check_security_groups(args.region)
    
    console.print("[*] Scanning VPCs...", style="cyan")
    vpc_findings = check_vpcs(args.region)
    
    # Print results table
    table = Table(title="Security Findings", box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Resource", width=25)
    table.add_column("Issue", width=40)
    
    severity_styles = {'CRITICAL': 'red', 'HIGH': 'orange3', 'MEDIUM': 'yellow', 'LOW': 'green'}
    
    for f in sg_findings:
        style = severity_styles.get(f.severity, 'white')
        table.add_row(f"[{style}]{f.severity}[/{style}]", f.sg_id, f.description)
    
    for f in vpc_findings:
        style = severity_styles.get(f.severity, 'white')
        table.add_row(f"[{style}]{f.severity}[/{style}]", f.vpc_id, f.description)
    
    console.print(table)
    
    # Generate report
    report = generate_report(sg_findings, vpc_findings, args.region, args.output)
    
    console.print(f"\n[bold green]✅ Scan Complete![/bold green]")
    console.print(f"   Critical: [red]{report['summary']['critical']}[/red]")
    console.print(f"   High:     [orange3]{report['summary']['high']}[/orange3]")
    console.print(f"   Medium:   [yellow]{report['summary']['medium']}[/yellow]")

if __name__ == '__main__':
    main()
```

---

## Step 6 — Write Tests

Create `tests/test_sg_checker.py`:

```python
import pytest
from moto import mock_ec2
import boto3
from src.sg_checker import check_security_groups

@mock_ec2
def test_detects_open_ssh():
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    # Create VPC and SG with open SSH
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']
    sg = ec2.create_security_group(
        GroupName='test-open-ssh',
        Description='Test SG',
        VpcId=vpc['VpcId']
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }]
    )
    
    findings = check_security_groups('us-east-1')
    ssh_findings = [f for f in findings if f.port == 22 and f.severity == 'CRITICAL']
    assert len(ssh_findings) >= 1

@mock_ec2
def test_no_findings_for_private_cidr():
    ec2 = boto3.client('ec2', region_name='us-east-1')
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']
    sg = ec2.create_security_group(
        GroupName='test-private',
        Description='Private SG',
        VpcId=vpc['VpcId']
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
        }]
    )
    
    findings = check_security_groups('us-east-1')
    # Private CIDR SSH should not be flagged
    open_ssh = [f for f in findings if f.port == 22 and f.cidr == '10.0.0.0/8']
    assert len(open_ssh) == 0
```

---

## Step 7 — Run the Tool

```bash
# Install dependencies
pip install -r requirements.txt

# Run against your AWS account
python -m src.auditor --region us-east-1

# Run tests
pytest tests/ -v

# Run against multiple regions
for region in us-east-1 eu-west-1 ap-southeast-1; do
    python -m src.auditor --region $region --output reports
done
```

---

## Step 8 — Sample Output

```
🔍 AWS Network Security Auditor
Region: us-east-1

[*] Scanning Security Groups...
[*] Scanning VPCs...

┌─────────────────────────────────────────────────────────────────┐
│                      Security Findings                          │
├──────────┬──────────────────────────┬────────────────────────── ┤
│ Severity │ Resource                 │ Issue                     │
├──────────┼──────────────────────────┼────────────────────────── ┤
│ CRITICAL │ sg-0abc123def456789      │ Port 22 (SSH) open...     │
│ HIGH     │ vpc-0123456789abcdef0    │ VPC has no flow logs      │
└──────────┴──────────────────────────┴────────────────────────── ┘

✅ Scan Complete!
   Critical: 2
   High:     1
   Medium:   0
```

---

## Step 9 — Enhancements to Try

1. **Add NACL scanning** — check for permissive Network ACL rules
2. **Multi-region parallel scanning** — use `concurrent.futures`
3. **Auto-remediation** — add `--fix` flag that revokes dangerous rules
4. **Slack notification** — post summary to a Slack webhook
5. **Schedule with Lambda** — run daily and store results in S3

---

## Common Errors & Fixes

| Error | Fix |
|-------|-----|
| `NoCredentialsError` | Run `aws configure` or set `AWS_PROFILE` |
| `ClientError: AccessDenied` | Add `ec2:DescribeSecurityGroups` to your IAM policy |
| `EndpointResolutionError` | Check region name spelling |
| `ModuleNotFoundError: boto3` | Run `pip install -r requirements.txt` in your venv |
