"""
AWS Security Hub findings collector.
"""
import boto3
from datetime import datetime, timedelta


def get_securityhub_findings(region: str = 'us-east-1', days: int = 7) -> list:
    """Fetch active Security Hub findings from the last N days."""
    sh = boto3.client('securityhub', region_name=region)
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')

    findings = []
    paginator = sh.get_paginator('get_findings')
    filters = {
        'UpdatedAt': [{'DateRange': {'Value': days, 'Unit': 'DAYS'}}],
        'WorkflowStatus': [
            {'Value': 'NEW', 'Comparison': 'EQUALS'},
            {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'},
        ],
        'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
    }
    for page in paginator.paginate(Filters=filters):
        for f in page['Findings']:
            findings.append({
                'cloud': 'AWS',
                'id': f.get('Id', '')[:80],
                'title': f.get('Title', 'Unknown')[:120],
                'severity': f.get('Severity', {}).get('Label', 'UNKNOWN'),
                'resource': f.get('Resources', [{}])[0].get('Id', 'N/A')[:100],
                'resource_type': f.get('Resources', [{}])[0].get('Type', 'N/A'),
                'region': f.get('Region', region),
                'service': f.get('ProductFields', {}).get('aws/securityhub/ProductName', ''),
                'created_at': f.get('CreatedAt', ''),
                'updated_at': f.get('UpdatedAt', ''),
                'compliance_status': f.get('Compliance', {}).get('Status', 'N/A'),
                'aws_account': f.get('AwsAccountId', ''),
                'remediation': f.get('Remediation', {}).get(
                    'Recommendation', {}).get('Text', ''),
            })
    return findings
