"""
Automated Incident Response Playbooks
Week 9 Project — Cloud Security Mentorship Programme

Playbook 1: EC2 Instance Compromise Response
- Quarantine (replace security group)
- Preserve (EBS snapshot)
- Investigate (collect metadata)
- Notify (SNS)
"""
import json
import os
import logging
import boto3
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger()
logger.setLevel(logging.INFO)

QUARANTINE_SG_NAME = os.environ.get("QUARANTINE_SG_NAME", "quarantine-no-access")
FORENSIC_S3_BUCKET = os.environ.get("FORENSIC_S3_BUCKET", "")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")


class EC2IncidentResponse:
    """Playbook: Respond to a compromised EC2 instance."""

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.ec2 = boto3.client("ec2", region_name=region)
        self.s3 = boto3.client("s3")
        self.sns = boto3.client("sns")

    def get_or_create_quarantine_sg(self, vpc_id: str) -> str:
        """Get existing quarantine SG or create one that blocks all traffic."""
        # Look for existing quarantine SG
        response = self.ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": [QUARANTINE_SG_NAME]},
            ]
        )
        if response["SecurityGroups"]:
            sg_id = response["SecurityGroups"][0]["GroupId"]
            logger.info(f"Using existing quarantine SG: {sg_id}")
            return sg_id

        # Create quarantine SG — no ingress or egress rules
        response = self.ec2.create_security_group(
            GroupName=QUARANTINE_SG_NAME,
            Description="QUARANTINE — Auto-created by IR playbook. NO traffic allowed.",
            VpcId=vpc_id,
        )
        sg_id = response["GroupId"]

        # Remove default egress rule (allow all outbound)
        self.ec2.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        )

        self.ec2.create_tags(
            Resources=[sg_id],
            Tags=[
                {"Key": "Name", "Value": QUARANTINE_SG_NAME},
                {"Key": "Purpose", "Value": "IR-Quarantine"},
                {"Key": "CreatedBy", "Value": "IR-Playbook"},
            ]
        )
        logger.info(f"Created quarantine SG: {sg_id} in VPC {vpc_id}")
        return sg_id

    def quarantine_instance(self, instance_id: str) -> Dict:
        """Replace all security groups with quarantine SG."""
        # Get instance details
        response = self.ec2.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        vpc_id = instance["VpcId"]
        original_sgs = [sg["GroupId"] for sg in instance["SecurityGroups"]]
        private_ip = instance.get("PrivateIpAddress", "unknown")
        public_ip = instance.get("PublicIpAddress", "none")
        instance_type = instance["InstanceType"]

        # Get quarantine SG
        quarantine_sg = self.get_or_create_quarantine_sg(vpc_id)

        # Replace security groups
        self.ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[quarantine_sg]
        )

        # Tag instance as quarantined
        self.ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "IR-Status", "Value": "QUARANTINED"},
                {"Key": "IR-Timestamp", "Value": datetime.now(timezone.utc).isoformat()},
                {"Key": "IR-OriginalSGs", "Value": ",".join(original_sgs)},
            ]
        )

        logger.info(f"Instance {instance_id} quarantined. Replaced SGs: {original_sgs}")

        return {
            "instance_id": instance_id,
            "vpc_id": vpc_id,
            "private_ip": private_ip,
            "public_ip": public_ip,
            "instance_type": instance_type,
            "original_security_groups": original_sgs,
            "quarantine_sg": quarantine_sg,
            "action": "QUARANTINED",
        }

    def preserve_evidence(self, instance_id: str) -> Dict:
        """Create EBS snapshots of all volumes for forensic analysis."""
        snapshots = []
        response = self.ec2.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        volumes = [
            b["Ebs"]["VolumeId"]
            for b in instance.get("BlockDeviceMappings", [])
            if "Ebs" in b
        ]

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

        for volume_id in volumes:
            snap = self.ec2.create_snapshot(
                VolumeId=volume_id,
                Description=f"IR-EVIDENCE: {instance_id} {timestamp}",
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "IR-Evidence", "Value": "true"},
                        {"Key": "IR-Instance", "Value": instance_id},
                        {"Key": "IR-Timestamp", "Value": timestamp},
                        {"Key": "Name", "Value": f"IR-{instance_id}-{timestamp}"},
                    ]
                }]
            )
            snapshots.append(snap["SnapshotId"])
            logger.info(f"Evidence snapshot created: {snap['SnapshotId']} for volume {volume_id}")

        return {
            "instance_id": instance_id,
            "volumes": volumes,
            "snapshots": snapshots,
            "action": "EVIDENCE_PRESERVED",
        }

    def collect_metadata(self, instance_id: str) -> Dict:
        """Collect instance metadata for investigation."""
        response = self.ec2.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]

        # Get instance console output (last ~64KB of serial console)
        try:
            console = self.ec2.get_console_output(InstanceId=instance_id)
            console_output = console.get("Output", "")
        except Exception:
            console_output = "Console output unavailable"

        metadata = {
            "instance_id": instance_id,
            "collection_time": datetime.now(timezone.utc).isoformat(),
            "instance_state": instance["State"]["Name"],
            "launch_time": instance["LaunchTime"].isoformat(),
            "instance_type": instance["InstanceType"],
            "image_id": instance["ImageId"],
            "key_name": instance.get("KeyName", "none"),
            "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn", "none"),
            "tags": {t["Key"]: t["Value"] for t in instance.get("Tags", [])},
            "security_groups": [sg["GroupId"] for sg in instance["SecurityGroups"]],
            "console_output_preview": console_output[:2000],
        }

        # Save to forensic S3 bucket if configured
        if FORENSIC_S3_BUCKET:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            key = f"ir-evidence/{instance_id}/{timestamp}/metadata.json"
            self.s3.put_object(
                Bucket=FORENSIC_S3_BUCKET,
                Key=key,
                Body=json.dumps(metadata, indent=2),
                ServerSideEncryption="aws:kms",
            )
            metadata["s3_evidence_path"] = f"s3://{FORENSIC_S3_BUCKET}/{key}"
            logger.info(f"Metadata saved to {metadata['s3_evidence_path']}")

        return metadata

    def notify(self, incident_data: Dict, finding_title: str) -> None:
        """Send SNS notification with incident details."""
        if not SNS_TOPIC_ARN:
            logger.warning("SNS_TOPIC_ARN not set — skipping notification")
            return

        instance_id = incident_data.get("instance_id", "unknown")
        subject = f"[CRITICAL] IR: Compromised EC2 Instance Quarantined — {instance_id}"

        message = (
            f"INCIDENT RESPONSE EXECUTED\n"
            f"==========================\n\n"
            f"Trigger:     {finding_title}\n"
            f"Instance:    {instance_id}\n"
            f"Private IP:  {incident_data.get('private_ip', 'unknown')}\n"
            f"Public IP:   {incident_data.get('public_ip', 'none')}\n"
            f"Region:      {self.region}\n"
            f"Time:        {datetime.now(timezone.utc).isoformat()}\n\n"
            f"Actions Taken:\n"
            f"  ✅ Instance QUARANTINED (all network traffic blocked)\n"
            f"  ✅ EBS snapshots created for forensic analysis\n"
            f"  ✅ Metadata collected and saved\n\n"
            f"Original Security Groups:\n"
            f"  {incident_data.get('original_security_groups', [])}\n\n"
            f"Evidence Snapshots:\n"
            f"  {incident_data.get('snapshots', [])}\n\n"
            f"Next Steps:\n"
            f"  1. Review CloudTrail for this instance's recent API calls\n"
            f"  2. Analyse EBS snapshot in forensic VPC\n"
            f"  3. Check VPC Flow Logs for unusual outbound connections\n"
            f"  4. Search for additional IOCs in Security Hub\n\n"
            f"Do NOT restore network access without security team approval.\n"
        )

        self.sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        logger.info(f"Incident notification sent to {SNS_TOPIC_ARN}")


def lambda_handler(event: Dict, context: Any) -> Dict:
    """
    Lambda handler — triggered by GuardDuty finding via EventBridge.

    Supported finding types:
    - EC2: UnauthorizedAccess:EC2/SSHBruteForce
    - EC2: CryptoCurrency:EC2/BitcoinTool.B!DNS
    - EC2: Backdoor:EC2/C&CActivity.B!DNS
    """
    logger.info(f"IR Playbook triggered: {json.dumps(event, default=str)}")

    try:
        # Parse GuardDuty finding from EventBridge
        detail = event.get("detail", {})
        finding_type = detail.get("type", "Unknown")
        finding_title = detail.get("title", "Unknown finding")
        severity = detail.get("severity", 0)
        region = event.get("region", "us-east-1")

        # Extract instance ID from finding resource
        resource = detail.get("resource", {})
        instance_details = resource.get("instanceDetails", {})
        instance_id = instance_details.get("instanceId")

        if not instance_id:
            logger.warning("No EC2 instance ID in finding — skipping")
            return {"statusCode": 200, "body": "No EC2 instance in finding"}

        logger.info(f"Responding to {finding_type} on {instance_id} (severity: {severity})")

        # Only auto-respond to HIGH/CRITICAL severity (>= 7.0)
        if severity < 7.0:
            logger.info(f"Severity {severity} < 7.0 — logging only, no auto-response")
            return {"statusCode": 200, "body": f"Low severity {severity} — no action"}

        # Execute playbook
        ir = EC2IncidentResponse(region=region)
        results = {}

        # Step 1: Quarantine
        results["quarantine"] = ir.quarantine_instance(instance_id)

        # Step 2: Preserve evidence
        results["evidence"] = ir.preserve_evidence(instance_id)

        # Step 3: Collect metadata
        results["metadata"] = ir.collect_metadata(instance_id)

        # Step 4: Notify
        ir.notify({**results["quarantine"], **results["evidence"]}, finding_title)

        logger.info(f"IR playbook completed for {instance_id}")
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "IR playbook executed successfully",
                "instance_id": instance_id,
                "finding_type": finding_type,
                "actions_taken": ["QUARANTINED", "EVIDENCE_PRESERVED", "METADATA_COLLECTED", "NOTIFIED"],
                "results": results,
            }, default=str)
        }

    except Exception as e:
        logger.error(f"IR playbook failed: {e}", exc_info=True)
        return {"statusCode": 500, "body": str(e)}
