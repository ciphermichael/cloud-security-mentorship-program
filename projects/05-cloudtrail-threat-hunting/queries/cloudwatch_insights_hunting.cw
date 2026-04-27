# ============================================================
# CloudTrail Threat Hunting — CloudWatch Logs Insights Queries
# Project: 05-cloudtrail-threat-hunting
# Paste these into the CloudWatch Logs Insights console
# Log group: /aws/cloudtrail/  (or your trail's log group)
# ============================================================

# ── Hunt 1: Root account usage ────────────────────────────────────────────────
fields @timestamp, eventName, sourceIPAddress, userAgent, awsRegion
| filter userIdentity.type = "Root"
  and eventType != "AwsServiceEvent"
| sort @timestamp desc
| limit 100

# ── Hunt 2: Console logins without MFA ───────────────────────────────────────
fields @timestamp, userIdentity.userName, sourceIPAddress, userAgent
| filter eventName = "ConsoleLogin"
  and responseElements.ConsoleLogin = "Success"
  and additionalEventData.MFAUsed = "No"
| sort @timestamp desc
| limit 50

# ── Hunt 3: Brute force — 10+ failed auth from same IP ───────────────────────
fields @timestamp, sourceIPAddress, userIdentity.userName, errorCode
| filter errorCode in [
    "Client.UnauthorizedOperation",
    "AccessDenied",
    "AuthFailure",
    "InvalidClientTokenId"
  ]
| stats count() as failures by sourceIPAddress, userIdentity.userName
| filter failures >= 10
| sort failures desc

# ── Hunt 4: CloudTrail tampering detection ────────────────────────────────────
fields @timestamp, userIdentity.arn, eventName, sourceIPAddress, awsRegion
| filter eventName in [
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
    "DeleteFlowLogs",
    "DeleteConfigRule"
  ]
| sort @timestamp desc

# ── Hunt 5: IAM escalation events ────────────────────────────────────────────
fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter eventName in [
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile"
  ]
| sort @timestamp desc
| limit 100

# ── Hunt 6: New IAM users created ────────────────────────────────────────────
fields @timestamp, userIdentity.arn as actor,
       requestParameters.userName as new_user, sourceIPAddress
| filter eventName = "CreateUser"
| sort @timestamp desc
| limit 50

# ── Hunt 7: API calls from unknown user agents (potential automation) ─────────
fields @timestamp, userIdentity.arn, eventName, userAgent, sourceIPAddress
| filter eventName not like "Describe%"
  and userAgent not like "aws-cli%"
  and userAgent not like "aws-sdk%"
  and userAgent not like "Boto3%"
  and userAgent not like "console.amazonaws.com%"
  and strlen(userAgent) > 0
| sort @timestamp desc
| limit 50

# ── Hunt 8: Enumeration burst (50+ read-only calls per IP in 5 minutes) ──────
fields @timestamp, sourceIPAddress, userIdentity.arn, eventName
| filter eventName like "Describe%" or eventName like "List%" or eventName like "Get%"
| stats count() as api_calls by sourceIPAddress, userIdentity.arn,
        datefloor(@timestamp, 5m)
| filter api_calls >= 50
| sort api_calls desc

# ── Hunt 9: S3 mass download (data exfiltration indicator) ───────────────────
fields @timestamp, userIdentity.arn, sourceIPAddress,
       requestParameters.bucketName as bucket
| filter eventSource = "s3.amazonaws.com" and eventName = "GetObject"
| stats count() as get_count by userIdentity.arn, sourceIPAddress, bucket,
        datefloor(@timestamp, 1h)
| filter get_count > 100
| sort get_count desc

# ── Hunt 10: Assume role cross-account (lateral movement) ────────────────────
fields @timestamp, userIdentity.arn as caller,
       requestParameters.roleArn as target_role, sourceIPAddress
| filter eventName = "AssumeRole"
  and not requestParameters.roleArn like concat("arn:aws:iam::", "123456789012", ":*")
| sort @timestamp desc
| limit 50
