"""
Cloud Security Operations Platform — Detection Engine
Week 21-24 Capstone Project

YAML-based rule engine that evaluates CloudTrail events against
detection rules and generates findings with MITRE ATT&CK mapping.
"""
import yaml
import json
import re
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class DetectionRule:
    """A single detection rule loaded from YAML."""

    def __init__(self, rule_dict: Dict):
        self.id = rule_dict["id"]
        self.name = rule_dict["name"]
        self.description = rule_dict.get("description", "")
        self.severity = rule_dict.get("severity", "MEDIUM")
        self.mitre_technique = rule_dict.get("mitre_technique", "")
        self.mitre_tactic = rule_dict.get("mitre_tactic", "")
        self.conditions = rule_dict.get("conditions", [])
        self.threshold = rule_dict.get("threshold", 1)
        self.window_minutes = rule_dict.get("window_minutes", 60)
        self.tags = rule_dict.get("tags", [])
        self.remediation = rule_dict.get("remediation", "")
        self.enabled = rule_dict.get("enabled", True)
        self._match_cache: Dict = {}

    def evaluate(self, event: Dict) -> bool:
        """Evaluate whether an event matches ALL conditions in this rule."""
        if not self.enabled:
            return False
        for condition in self.conditions:
            if not self._evaluate_condition(event, condition):
                return False
        return True

    def _evaluate_condition(self, event: Dict, condition: Dict) -> bool:
        """Evaluate a single condition against an event field."""
        field = condition.get("field", "")
        operator = condition.get("operator", "equals")
        value = condition.get("value")

        # Navigate nested event fields using dot notation
        event_value = self._get_nested(event, field)
        if event_value is None:
            return operator == "not_exists"

        if operator == "equals":
            return str(event_value) == str(value)
        elif operator == "not_equals":
            return str(event_value) != str(value)
        elif operator == "in":
            return str(event_value) in [str(v) for v in (value or [])]
        elif operator == "not_in":
            return str(event_value) not in [str(v) for v in (value or [])]
        elif operator == "contains":
            return str(value) in str(event_value)
        elif operator == "starts_with":
            return str(event_value).startswith(str(value))
        elif operator == "regex":
            return bool(re.search(str(value), str(event_value), re.IGNORECASE))
        elif operator == "exists":
            return event_value is not None
        elif operator == "not_exists":
            return event_value is None
        elif operator == "greater_than":
            try:
                return float(event_value) > float(value)
            except (ValueError, TypeError):
                return False
        return False

    @staticmethod
    def _get_nested(data: Dict, path: str) -> Any:
        """Get nested dict value using dot notation (e.g., userIdentity.type)."""
        keys = path.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return current


class RuleEngine:
    """Loads detection rules from YAML files and evaluates events."""

    def __init__(self, rules_directory: str = "rules"):
        self.rules: List[DetectionRule] = []
        self.rules_dir = Path(rules_directory)
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all YAML rule files from the rules directory."""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            self._load_builtin_rules()
            return

        rule_files = list(self.rules_dir.glob("*.yaml")) + list(self.rules_dir.glob("*.yml"))
        for rule_file in rule_files:
            try:
                with open(rule_file) as fh:
                    rule_data = yaml.safe_load(fh)
                    if isinstance(rule_data, list):
                        for r in rule_data:
                            self.rules.append(DetectionRule(r))
                    elif isinstance(rule_data, dict):
                        self.rules.append(DetectionRule(rule_data))
            except Exception as e:
                logger.error(f"Failed to load rule file {rule_file}: {e}")

        if not self.rules:
            self._load_builtin_rules()

        enabled = sum(1 for r in self.rules if r.enabled)
        logger.info(f"Loaded {len(self.rules)} rules ({enabled} enabled)")

    def _load_builtin_rules(self) -> None:
        """Load built-in rules as fallback."""
        builtin_rules = [
            {
                "id": "CSOP-001",
                "name": "Root Account API Activity",
                "description": "Any API call from the root account should generate an immediate alert",
                "severity": "CRITICAL",
                "mitre_technique": "T1078.004",
                "mitre_tactic": "Privilege Escalation",
                "conditions": [
                    {"field": "userIdentity.type", "operator": "equals", "value": "Root"},
                    {"field": "eventType", "operator": "equals", "value": "AwsApiCall"},
                ],
                "remediation": "Investigate root account usage immediately. Root should never be used for API calls.",
                "enabled": True,
            },
            {
                "id": "CSOP-002",
                "name": "IAM Privilege Escalation — CreatePolicyVersion",
                "description": "Attacker creates new policy version with admin permissions",
                "severity": "CRITICAL",
                "mitre_technique": "T1078.004",
                "mitre_tactic": "Privilege Escalation",
                "conditions": [
                    {"field": "eventSource", "operator": "equals", "value": "iam.amazonaws.com"},
                    {"field": "eventName", "operator": "equals", "value": "CreatePolicyVersion"},
                    {"field": "errorCode", "operator": "not_exists"},
                ],
                "remediation": "Restrict iam:CreatePolicyVersion. Review the created policy version immediately.",
                "enabled": True,
            },
            {
                "id": "CSOP-003",
                "name": "CloudTrail Logging Disabled",
                "description": "Attacker stopped CloudTrail to cover their tracks",
                "severity": "CRITICAL",
                "mitre_technique": "T1562.008",
                "mitre_tactic": "Defence Evasion",
                "conditions": [
                    {"field": "eventSource", "operator": "equals", "value": "cloudtrail.amazonaws.com"},
                    {"field": "eventName", "operator": "in",
                     "value": ["StopLogging", "DeleteTrail", "UpdateTrail"]},
                    {"field": "errorCode", "operator": "not_exists"},
                ],
                "remediation": "Re-enable CloudTrail immediately. Investigate who disabled it and why.",
                "enabled": True,
            },
            {
                "id": "CSOP-004",
                "name": "S3 Bucket Made Public",
                "description": "S3 bucket Block Public Access disabled",
                "severity": "HIGH",
                "mitre_technique": "T1530",
                "mitre_tactic": "Exfiltration",
                "conditions": [
                    {"field": "eventSource", "operator": "equals", "value": "s3.amazonaws.com"},
                    {"field": "eventName", "operator": "in",
                     "value": ["DeleteBucketPublicAccessBlock", "PutBucketAcl",
                               "PutBucketPolicy"]},
                    {"field": "errorCode", "operator": "not_exists"},
                ],
                "remediation": "Immediately re-enable Block Public Access. Review bucket policy for unintended permissions.",
                "enabled": True,
            },
            {
                "id": "CSOP-005",
                "name": "New IAM User Created",
                "description": "Track all IAM user creation events",
                "severity": "MEDIUM",
                "mitre_technique": "T1136.003",
                "mitre_tactic": "Persistence",
                "conditions": [
                    {"field": "eventSource", "operator": "equals", "value": "iam.amazonaws.com"},
                    {"field": "eventName", "operator": "equals", "value": "CreateUser"},
                    {"field": "errorCode", "operator": "not_exists"},
                ],
                "remediation": "Verify the new IAM user was created via approved change process.",
                "enabled": True,
            },
        ]
        self.rules = [DetectionRule(r) for r in builtin_rules]
        logger.info(f"Loaded {len(self.rules)} built-in rules")

    def evaluate_event(self, event: Dict) -> List[Dict]:
        """Evaluate a single CloudTrail event against all rules."""
        findings = []
        for rule in self.rules:
            if rule.evaluate(event):
                finding = {
                    "finding_id": f"{rule.id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "mitre_technique": rule.mitre_technique,
                    "mitre_tactic": rule.mitre_tactic,
                    "description": rule.description,
                    "remediation": rule.remediation,
                    "tags": rule.tags,
                    "event_summary": {
                        "eventTime": event.get("eventTime"),
                        "eventSource": event.get("eventSource"),
                        "eventName": event.get("eventName"),
                        "awsRegion": event.get("awsRegion"),
                        "sourceIPAddress": event.get("sourceIPAddress"),
                        "userIdentity": event.get("userIdentity", {}),
                        "requestParameters": event.get("requestParameters"),
                    },
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                }
                findings.append(finding)
                logger.warning(
                    f"DETECTION [{rule.severity}] {rule.id}: {rule.name} | "
                    f"Actor: {event.get('userIdentity', {}).get('arn', 'unknown')}"
                )
        return findings

    def evaluate_batch(self, events: List[Dict]) -> List[Dict]:
        """Evaluate a batch of events and return all findings."""
        all_findings = []
        for event in events:
            all_findings.extend(self.evaluate_event(event))
        return all_findings

    def get_coverage_matrix(self) -> List[Dict]:
        """Return MITRE ATT&CK coverage matrix for loaded rules."""
        return [
            {
                "rule_id": r.id,
                "rule_name": r.name,
                "severity": r.severity,
                "mitre_technique": r.mitre_technique,
                "mitre_tactic": r.mitre_tactic,
                "enabled": r.enabled,
            }
            for r in self.rules
        ]


# ─── EXAMPLE YAML RULE FORMAT ─────────────────────────────────────────────────
EXAMPLE_RULE_YAML = """
# Example: rules/iam_escalation.yaml
id: CSOP-IAM-001
name: AttachUserPolicy — Direct Privilege Escalation
description: >
  Attacker attaches a managed policy (e.g., AdministratorAccess) directly 
  to an IAM user, bypassing intended permission boundaries.
severity: CRITICAL
mitre_technique: T1078.004
mitre_tactic: Privilege Escalation
tags:
  - iam
  - privilege-escalation
  - mitre-t1078
conditions:
  - field: eventSource
    operator: equals
    value: iam.amazonaws.com
  - field: eventName
    operator: equals
    value: AttachUserPolicy
  - field: errorCode
    operator: not_exists
threshold: 1
window_minutes: 60
remediation: >
  Immediately review the policy attachment. Remove AdministratorAccess if 
  unintended. Restrict iam:AttachUserPolicy using permission boundaries.
enabled: true
"""


if __name__ == "__main__":
    # Demo
    engine = RuleEngine()
    print(f"Loaded {len(engine.rules)} detection rules\n")
    print("Coverage Matrix:")
    print(f"{'Rule ID':<15} {'Severity':<10} {'MITRE':<15} {'Name'}")
    print("-" * 75)
    for entry in engine.get_coverage_matrix():
        print(f"{entry['rule_id']:<15} {entry['severity']:<10} "
              f"{entry['mitre_technique']:<15} {entry['rule_name']}")

    # Test against sample events
    test_events = [
        {
            "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
            "eventSource": "s3.amazonaws.com", "eventName": "ListBuckets",
            "eventType": "AwsApiCall", "awsRegion": "us-east-1",
            "sourceIPAddress": "1.2.3.4",
        },
        {
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/attacker"},
            "eventSource": "iam.amazonaws.com", "eventName": "CreatePolicyVersion",
            "eventType": "AwsApiCall", "awsRegion": "us-east-1",
            "sourceIPAddress": "5.6.7.8",
        },
    ]

    print("\n\nEvaluating test events...")
    findings = engine.evaluate_batch(test_events)
    print(f"\n{len(findings)} finding(s) generated:")
    for f in findings:
        print(f"  [{f['severity']}] {f['rule_id']}: {f['rule_name']}")
