# =============================================================================
# AWS CloudWatch Logs Insights — Security Detection Queries
# Cloud Security Mentorship Programme — Shared Query Library
# Use: CloudWatch → Logs Insights → paste query → select log group → run
# =============================================================================


# ─── QUERY 1: IAM Privilege Escalation — High-Risk API Calls ─────────────────
# Log Group: CloudTrail/DefaultLogGroup
# Detects the 9 most dangerous IAM API calls used in privilege escalation

fields @timestamp, userIdentity.arn, userIdentity.type, eventName,
       sourceIPAddress, requestParameters
| filter eventSource = "iam.amazonaws.com"
| filter eventName in [
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy",
    "CreateAccessKey", "UpdateLoginProfile", "AddUserToGroup",
    "CreateUser", "CreateRole"
  ]
| filter userIdentity.type != "Root"
| filter ispresent(errorCode) = 0
| stats count(*) as event_count by userIdentity.arn, eventName
| sort event_count desc


# ─── QUERY 2: Root Account Activity ──────────────────────────────────────────
# Any API call made by the root account is suspicious and should alert

fields @timestamp, eventName, eventSource, sourceIPAddress, userAgent
| filter userIdentity.type = "Root"
| filter eventType = "AwsApiCall"
| sort @timestamp desc
| limit 100


# ─── QUERY 3: API Key Compromise — Mass Enumeration Pattern ──────────────────
# Detects compromised credentials performing wide reconnaissance
# Indicator: one key hitting many services in a short time

fields @timestamp, userIdentity.accessKeyId, userIdentity.arn,
       sourceIPAddress, userAgent, eventSource, eventName
| filter eventType = "AwsApiCall"
| filter userIdentity.type = "IAMUser"
| stats
    count(*)           as api_calls,
    count_distinct(eventSource) as services_accessed,
    min(@timestamp)    as first_seen,
    max(@timestamp)    as last_seen,
    count_distinct(sourceIPAddress) as source_ips
  by userIdentity.accessKeyId, userIdentity.arn
| filter services_accessed > 5 and api_calls > 50
| sort api_calls desc


# ─── QUERY 4: S3 Data Exfiltration — GetObject Spike ────────────────────────
# Detects anomalous GetObject calls that may indicate data theft

fields @timestamp, userIdentity.arn, requestParameters.bucketName,
       requestParameters.key, sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
| filter eventName = "GetObject"
| filter ispresent(errorCode) = 0
| stats
    count(*) as object_downloads,
    count_distinct(requestParameters.bucketName) as buckets_accessed,
    count_distinct(requestParameters.key)        as unique_objects,
    min(@timestamp) as first_download,
    max(@timestamp) as last_download
  by userIdentity.arn, bin(30m)
| filter object_downloads > 100
| sort object_downloads desc


# ─── QUERY 5: New IAM User Created ───────────────────────────────────────────
# Alert on all new IAM user creations — track actor and created user

fields @timestamp, userIdentity.arn, requestParameters.userName,
       sourceIPAddress, userAgent
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateUser"
| filter ispresent(errorCode) = 0
| sort @timestamp desc


# ─── QUERY 6: VPC Security Group Changes (Change Detection) ──────────────────
# Detect any changes to security group rules — could be opening dangerous ports

fields @timestamp, userIdentity.arn, eventName, requestParameters,
       sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in [
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "RevokeSecurityGroupEgress",
    "CreateSecurityGroup",
    "DeleteSecurityGroup"
  ]
| sort @timestamp desc


# ─── QUERY 7: Failed Login Attempts — Brute Force Detection ──────────────────
# Detect repeated ConsoleLogin failures from same IP (brute force)

fields @timestamp, userIdentity.arn, sourceIPAddress, userAgent,
       errorMessage
| filter eventName = "ConsoleLogin"
| filter responseElements.ConsoleLogin = "Failure"
| stats count(*) as failed_attempts by sourceIPAddress, userIdentity.arn, bin(5m)
| filter failed_attempts >= 5
| sort failed_attempts desc


# ─── QUERY 8: CloudTrail Tampering Detection ─────────────────────────────────
# Attackers often try to stop/delete CloudTrail to cover their tracks

fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter eventSource = "cloudtrail.amazonaws.com"
| filter eventName in [
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors"
  ]
| sort @timestamp desc


# ─── QUERY 9: Crypto Mining Indicators ───────────────────────────────────────
# Attackers spin up instances in unusual regions for mining

fields @timestamp, userIdentity.arn, eventName, awsRegion,
       requestParameters.instanceType, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "RunInstances"
| filter requestParameters.instanceType in [
    "p3.16xlarge", "p3.8xlarge", "g4dn.12xlarge",
    "c5.24xlarge", "c5.18xlarge"
  ]
| sort @timestamp desc


# ─── QUERY 10: Secret Manager — Sensitive Secret Access ──────────────────────
# Detect access to secrets by unusual principals

fields @timestamp, userIdentity.arn, userIdentity.type,
       requestParameters.secretId, sourceIPAddress, userAgent
| filter eventSource = "secretsmanager.amazonaws.com"
| filter eventName in ["GetSecretValue", "DescribeSecret"]
| filter ispresent(errorCode) = 0
| stats
    count(*) as secret_accesses,
    count_distinct(requestParameters.secretId) as unique_secrets
  by userIdentity.arn, bin(1h)
| filter secret_accesses > 10
| sort secret_accesses desc


# ─── QUERY 11: Anomalous AssumeRole Chains ───────────────────────────────────
# Detect lateral movement via chained AssumeRole calls

fields @timestamp, userIdentity.arn, requestParameters.roleArn,
       requestParameters.roleSessionName, sourceIPAddress
| filter eventSource = "sts.amazonaws.com"
| filter eventName = "AssumeRole"
| filter ispresent(errorCode) = 0
| stats
    count(*) as role_assumptions,
    count_distinct(requestParameters.roleArn) as unique_roles
  by userIdentity.arn, bin(1h)
| filter unique_roles > 3
| sort role_assumptions desc


# ─── QUERY 12: EC2 Instance Deletion Spike ───────────────────────────────────
# Detect mass instance termination (possible ransomware / destructive attack)

fields @timestamp, userIdentity.arn, requestParameters, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["TerminateInstances", "StopInstances"]
| stats count(*) as terminations by userIdentity.arn, bin(5m)
| filter terminations >= 3
| sort terminations desc
