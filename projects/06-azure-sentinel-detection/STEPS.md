# Project 06 — Azure Sentinel Detection Engineering: Step-by-Step Guide

## Overview
Build and deploy 20+ KQL analytics rules in Microsoft Azure Sentinel, all mapped to MITRE ATT&CK.

## Step 1 — Prerequisites
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login
az extension add --name sentinel
pip install azure-mgmt-securityinsight azure-identity pyyaml
```

## Step 2 — Core KQL Detection Rules

### Rule 1: Impossible Travel Detection
```kql
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| join kind=inner (
    SigninLogs | where TimeGenerated > ago(1d) and ResultType == 0
    | project T2=TimeGenerated, UserPrincipalName, IP2=IPAddress, Loc2=Location
) on UserPrincipalName
| where abs(datetime_diff('minute', TimeGenerated, T2)) < 60
| where Location != Loc2 and IPAddress != IP2
| summarize count() by UserPrincipalName, Location, Loc2
```

### Rule 2: Mass Azure Blob Download (Exfiltration)
```kql
StorageBlobLogs
| where TimeGenerated > ago(1h) and OperationName == "GetBlob"
| summarize DownloadCount=count(), BytesTotal=sum(ResponseBodySize)
    by CallerIpAddress, AccountName, bin(TimeGenerated, 5m)
| where DownloadCount > 100 or BytesTotal > 1073741824
```

### Rule 3: Service Principal Secret Added
```kql
AuditLogs
| where OperationName == "Add service principal credentials" and Result == "success"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetApp = tostring(TargetResources[0].displayName)
| project TimeGenerated, Actor, TargetApp
```

### Rule 4: Admin MFA Bypass
```kql
SigninLogs
| where ResultType == 0 and AuthenticationRequirement != "multiFactorAuthentication"
| join kind=inner (
    IdentityInfo
    | where AssignedRoles has_any ("Global Administrator", "Security Administrator")
    | project AccountUPN
) on $left.UserPrincipalName == $right.AccountUPN
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName
```

### Rule 5: New Country Sign-In
```kql
let known = SigninLogs | where TimeGenerated between (ago(30d)..ago(1d)) and ResultType == 0
    | summarize known=make_set(Location) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == 0
| join kind=leftouter known on UserPrincipalName
| where not(Location in (known))
| project TimeGenerated, UserPrincipalName, Location, IPAddress
```

### Rule 6: Mass Role Assignment
```kql
AuditLogs
| where OperationName in ("Add member to role", "Add app role assignment to service principal")
| summarize count() by InitiatedBy=tostring(InitiatedBy.user.userPrincipalName), bin(TimeGenerated, 10m)
| where count_ > 5
```

### Rule 7: Suspicious PowerShell in Azure Cloud Shell
```kql
AzureActivity
| where OperationNameValue contains "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND"
| extend CommandType = tostring(Properties.requestbody)
| where CommandType contains "Invoke-WebRequest" or CommandType contains "IEX"
```

### Rule 8: Lateral Movement via Delegated Permissions
```kql
AuditLogs
| where OperationName == "Consent to application"
| extend Permissions = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where Permissions contains "Mail.ReadWrite" or Permissions contains "Files.ReadWrite.All"
| project TimeGenerated, InitiatedBy, Permissions
```

## Step 3 — Deploy Rules via Python
```python
# src/rule_deployer.py
from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights
import yaml, os, uuid

SUBSCRIPTION_ID = os.environ['AZURE_SUBSCRIPTION_ID']
RESOURCE_GROUP  = os.environ['AZURE_RESOURCE_GROUP']
WORKSPACE_NAME  = os.environ['SENTINEL_WORKSPACE_NAME']

def deploy_rule(rule: dict):
    client = SecurityInsights(DefaultAzureCredential(), SUBSCRIPTION_ID)
    rule_id = str(uuid.uuid4())
    client.alert_rules.create_or_update(
        resource_group_name=RESOURCE_GROUP,
        workspace_name=WORKSPACE_NAME,
        rule_id=rule_id,
        alert_rule={
            'kind': 'Scheduled',
            'displayName': rule['name'],
            'description': rule.get('description',''),
            'severity': rule.get('severity','Medium'),
            'enabled': True,
            'query': rule['query'],
            'queryFrequency': 'PT1H',
            'queryPeriod': 'PT1H',
            'triggerOperator': 'GreaterThan',
            'triggerThreshold': 0,
            'tactics': rule.get('tactics', []),
        }
    )
    print(f'[+] Deployed: {rule["name"]}')

def load_and_deploy(rules_dir='rules/'):
    import glob
    for filepath in glob.glob(f'{rules_dir}*.yaml'):
        with open(filepath) as f:
            rule = yaml.safe_load(f)
        deploy_rule(rule)

if __name__ == '__main__':
    load_and_deploy()
```

## Step 4 — Rule YAML Format
```yaml
# rules/impossible_travel.yaml
name: "Impossible Travel Detection"
description: "Detects logins from two geographic locations within 60 minutes"
severity: "High"
tactics:
  - "InitialAccess"
techniques:
  - "T1078"
query: |
  SigninLogs
  | where TimeGenerated > ago(1d) and ResultType == 0
  | project TimeGenerated, UserPrincipalName, IPAddress, Location
  | join kind=inner (
      SigninLogs | where ResultType == 0
      | project T2=TimeGenerated, UserPrincipalName, IP2=IPAddress, Loc2=Location
  ) on UserPrincipalName
  | where abs(datetime_diff('minute', TimeGenerated, T2)) < 60
  | where Location != Loc2
  | summarize count() by UserPrincipalName
```

## Step 5 — Run
```bash
export AZURE_SUBSCRIPTION_ID=xxx
export AZURE_RESOURCE_GROUP=SecurityRG
export SENTINEL_WORKSPACE_NAME=MySentinelWorkspace
python -m src.rule_deployer
# Verify rules in Azure Portal > Sentinel > Analytics
```
