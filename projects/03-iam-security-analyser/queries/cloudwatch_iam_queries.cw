# ============================================================
# IAM Security Analyser — CloudWatch Logs Insights Queries
# Project: 03-iam-security-analyser
# Paste into CloudWatch Logs Insights against your CloudTrail log group
# ============================================================

# ── IAM Privilege Grant Events ────────────────────────────────────────────────
fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter eventName in [
    "AttachUserPolicy","AttachRolePolicy","AttachGroupPolicy",
    "PutUserPolicy","PutRolePolicy","CreatePolicyVersion","SetDefaultPolicyVersion"
  ]
| sort @timestamp desc
| limit 100

# ── AdministratorAccess policy attached to anything ───────────────────────────
fields @timestamp, userIdentity.arn, eventName, requestParameters.policyArn
| filter eventName in ["AttachUserPolicy","AttachRolePolicy","AttachGroupPolicy"]
  and requestParameters.policyArn like "AdministratorAccess"
| sort @timestamp desc

# ── Console logins without MFA ─────────────────────────────────────────────────
fields @timestamp, userIdentity.userName, sourceIPAddress, userAgent
| filter eventName = "ConsoleLogin"
  and responseElements.ConsoleLogin = "Success"
  and additionalEventData.MFAUsed = "No"
| sort @timestamp desc

# ── Access keys created for other users ────────────────────────────────────────
fields @timestamp, userIdentity.arn as actor,
       requestParameters.userName as key_created_for, sourceIPAddress
| filter eventName = "CreateAccessKey"
| sort @timestamp desc

# ── Root account usage ─────────────────────────────────────────────────────────
fields @timestamp, eventName, sourceIPAddress, userAgent, awsRegion
| filter userIdentity.type = "Root"
| sort @timestamp desc
| limit 50
