"""
Lambda handler — receives EventBridge events from CloudTrail
and detects IAM privilege escalation in real-time.

EventBridge Rule pattern:
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "CreatePolicyVersion", "SetDefaultPolicyVersion",
      "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
      "PutUserPolicy", "PutRolePolicy", "CreateAccessKey",
      "UpdateLoginProfile", "AddUserToGroup", "CreateFunction20150331"
    ]
  }
}
"""
import json
import os
import logging
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
ESCALATION_EVENT_MAP = {
    "CreatePolicyVersion": ("EP-001", "CRITICAL", "Policy version replacement escalation"),
    "SetDefaultPolicyVersion": ("EP-006", "CRITICAL", "Policy version reversion"),
    "AttachUserPolicy": ("EP-003", "CRITICAL", "Direct policy attachment to user"),
    "AttachRolePolicy": ("EP-003", "HIGH", "Direct policy attachment to role"),
    "PutUserPolicy": ("EP-007", "HIGH", "Inline policy injection on user"),
    "CreateAccessKey": ("EP-004", "HIGH", "Access key created — possible cross-user"),
    "UpdateLoginProfile": ("EP-005", "HIGH", "Console password update"),
    "AddUserToGroup": ("EP-008", "HIGH", "User added to group"),
}


def lambda_handler(event, context):
    """Process EventBridge CloudTrail event and alert on escalation patterns."""
    try:
        detail = event.get("detail", {})
        event_name = detail.get("eventName", "")
        user_identity = detail.get("userIdentity", {})
        actor_arn = user_identity.get("arn", "unknown")
        actor_type = user_identity.get("type", "")
        source_ip = detail.get("sourceIPAddress", "unknown")
        event_time = detail.get("eventTime", datetime.utcnow().isoformat())
        error_code = detail.get("errorCode")
        request_params = detail.get("requestParameters", {})

        # Skip errors and root
        if error_code or actor_type == "Root":
            return {"statusCode": 200, "body": "Skipped (error or root)"}

        if event_name not in ESCALATION_EVENT_MAP:
            return {"statusCode": 200, "body": "No matching escalation pattern"}

        path_id, severity, description = ESCALATION_EVENT_MAP[event_name]

        # Enhanced check: CreateAccessKey on a DIFFERENT user
        actor_username = user_identity.get("userName", "")
        target_username = request_params.get("userName", "")
        cross_user = (event_name == "CreateAccessKey" and
                      target_username and target_username != actor_username)

        if event_name == "CreateAccessKey" and not cross_user:
            # Self-rotation is fine — downgrade
            severity = "LOW"
            description = "Self-service access key rotation (normal activity)"

        alert = {
            "alert_type": "IAM_PRIVILEGE_ESCALATION",
            "path_id": path_id,
            "severity": severity,
            "event_name": event_name,
            "description": description,
            "cross_user_escalation": cross_user,
            "actor_arn": actor_arn,
            "actor_type": actor_type,
            "source_ip": source_ip,
            "target_resource": target_username or request_params.get("roleName", "N/A"),
            "event_time": event_time,
            "mitre_url": f"https://attack.mitre.org/techniques/T1078/004/",
            "aws_region": event.get("region", "unknown"),
        }

        logger.warning(json.dumps(alert))

        # Send SNS notification
        if SNS_TOPIC_ARN and severity in ("CRITICAL", "HIGH"):
            sns = boto3.client("sns")
            subject = f"[{severity}] IAM Escalation Detected: {event_name} by {actor_arn}"
            message = (
                f"IAM Privilege Escalation Alert\n"
                f"==============================\n"
                f"Severity:  {severity}\n"
                f"Pattern:   {path_id} — {description}\n"
                f"Event:     {event_name}\n"
                f"Actor:     {actor_arn}\n"
                f"Target:    {alert['target_resource']}\n"
                f"Source IP: {source_ip}\n"
                f"Time:      {event_time}\n"
                f"Cross-user escalation: {cross_user}\n\n"
                f"Investigate in AWS Console:\n"
                f"https://console.aws.amazon.com/cloudtrail/\n"
            )
            sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
            logger.info(f"SNS alert sent to {SNS_TOPIC_ARN}")

        return {"statusCode": 200, "body": json.dumps(alert)}

    except Exception as e:
        logger.error(f"Error processing event: {e}", exc_info=True)
        return {"statusCode": 500, "body": str(e)}
