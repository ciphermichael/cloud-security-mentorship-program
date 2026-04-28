"""
Azure Defender for Cloud findings collector.
Requires: azure-mgmt-security, azure-identity
"""
import os
from typing import Optional


def get_azure_findings(subscription_id: Optional[str] = None) -> list:
    """Fetch active security alerts from Azure Defender for Cloud."""
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.security import SecurityCenter

    sub_id = subscription_id or os.environ.get('AZURE_SUBSCRIPTION_ID')
    if not sub_id:
        raise ValueError('AZURE_SUBSCRIPTION_ID not set and not provided')

    client = SecurityCenter(DefaultAzureCredential(), sub_id)

    findings = []
    for alert in client.alerts.list():
        sev = (alert.severity or 'Unknown').upper()
        findings.append({
            'cloud': 'Azure',
            'id': alert.name or '',
            'title': alert.alert_display_name or 'Unknown',
            'severity': sev,
            'resource': alert.compromised_entity or 'N/A',
            'resource_type': 'Azure Resource',
            'region': alert.location or 'unknown',
            'service': alert.alert_type or '',
            'created_at': str(alert.time_generated_utc) if alert.time_generated_utc else '',
            'updated_at': str(alert.time_generated_utc) if alert.time_generated_utc else '',
            'status': alert.status or 'Unknown',
            'subscription': sub_id,
            'remediation': alert.remediation_steps[0] if alert.remediation_steps else '',
        })
    return findings
