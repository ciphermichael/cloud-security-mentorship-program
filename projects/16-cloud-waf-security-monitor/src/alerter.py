"""
WAF real-time alerter — Lambda handler triggered by S3 PUT of new WAF log.
Analyses the log, classifies attacks, and sends Slack/SNS alerts on thresholds.
"""
import json
import os
import urllib.request
from collections import Counter
from datetime import datetime, timezone

import boto3

from .log_parser import parse_waf_log_file, WAFEvent

BLOCK_THRESHOLD = int(os.environ.get('BLOCK_THRESHOLD', '50'))
CRITICAL_THRESHOLD = int(os.environ.get('CRITICAL_THRESHOLD', '10'))
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')


def _post_slack(message: dict) -> bool:
    if not SLACK_WEBHOOK_URL:
        return False
    data = json.dumps(message).encode('utf-8')
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL, data=data,
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status == 200


def _publish_sns(subject: str, body: str) -> bool:
    if not SNS_TOPIC_ARN:
        return False
    sns = boto3.client('sns')
    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=body)
    return True


def build_alert_payload(events: list[WAFEvent]) -> dict:
    blocked = [e for e in events if e.blocked]
    attack_counts = Counter(e.attack_type for e in events if e.attack_type)
    top_ips = Counter(e.client_ip for e in blocked).most_common(5)
    top_countries = Counter(e.country for e in blocked).most_common(3)

    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'total_requests': len(events),
        'blocked': len(blocked),
        'block_rate_pct': round(len(blocked) / max(len(events), 1) * 100, 1),
        'attack_counts': dict(attack_counts),
        'top_ips': top_ips,
        'top_countries': top_countries,
        'critical_attacks': sum(
            v for k, v in attack_counts.items()
            if k in ('SQL_INJECTION', 'COMMAND_INJECTION', 'LOG4SHELL')
        ),
    }


def should_alert(payload: dict) -> tuple[bool, str]:
    """Return (should_alert, reason)."""
    if payload['critical_attacks'] >= CRITICAL_THRESHOLD:
        return True, f'{payload["critical_attacks"]} critical attacks detected'
    if payload['blocked'] >= BLOCK_THRESHOLD:
        return True, f'{payload["blocked"]} requests blocked'
    return False, ''


def lambda_handler(event: dict, context) -> dict:
    """Lambda entry point — triggered by S3:ObjectCreated event."""
    record = event['Records'][0]
    bucket = record['s3']['bucket']['name']
    key = record['s3']['object']['key']

    print(f'[*] Processing WAF log: s3://{bucket}/{key}')

    waf_events = parse_waf_log_file(key, bucket=bucket)
    payload = build_alert_payload(waf_events)

    print(f'[+] Processed {len(waf_events)} events, {payload["blocked"]} blocked')

    alert_needed, reason = should_alert(payload)
    if alert_needed:
        subject = f':shield: WAF Alert — {reason}'
        body = json.dumps(payload, indent=2)

        slack_msg = {
            'text': subject,
            'attachments': [{
                'color': '#FF0000',
                'fields': [
                    {'title': 'Total Requests', 'value': str(payload['total_requests']), 'short': True},
                    {'title': 'Blocked', 'value': str(payload['blocked']), 'short': True},
                    {'title': 'Block Rate', 'value': f'{payload["block_rate_pct"]}%', 'short': True},
                    {'title': 'Attack Types', 'value': str(payload['attack_counts']), 'short': False},
                    {'title': 'Top Source IPs', 'value': str(payload['top_ips']), 'short': False},
                ],
            }]
        }
        _post_slack(slack_msg)
        _publish_sns(subject, body)
        print(f'[!] Alert sent: {reason}')

    return {
        'processed': len(waf_events),
        'blocked': payload['blocked'],
        'alerted': alert_needed,
    }
