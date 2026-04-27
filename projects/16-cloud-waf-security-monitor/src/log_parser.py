"""
AWS WAF log parser — reads WAF logs from S3 and extracts structured events.
WAF logs are delivered as gzipped NDJSON (one JSON object per line).
"""
import gzip
import json
import re
import boto3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Attack Pattern Signatures ──────────────────────────────────────────────────

ATTACK_SIGNATURES: dict[str, list[re.Pattern]] = {
    'SQL_INJECTION': [
        re.compile(r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from)", re.I),
        re.compile(r"(?i)(1\s*=\s*1|or\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1)", re.I),
        re.compile(r"(?i)(exec\s*\(|xp_cmdshell|information_schema)", re.I),
    ],
    'XSS': [
        re.compile(r"<script[\s>]", re.I),
        re.compile(r"javascript\s*:", re.I),
        re.compile(r"onerror\s*=|onload\s*=|onclick\s*=", re.I),
        re.compile(r"document\.cookie|window\.location", re.I),
    ],
    'PATH_TRAVERSAL': [
        re.compile(r"\.\./|\.\.\\", re.I),
        re.compile(r"%2e%2e%2f|%2e%2e/|\.\.%2f", re.I),
        re.compile(r"/etc/passwd|/etc/shadow|/proc/self", re.I),
    ],
    'COMMAND_INJECTION': [
        re.compile(r";\s*(ls|cat|id|whoami|uname|wget|curl)\s", re.I),
        re.compile(r"\|\s*(ls|cat|id|whoami|bash|sh)\s", re.I),
        re.compile(r"`[^`]+`", re.I),
    ],
    'SCANNER': [
        re.compile(r"(?i)(sqlmap|nikto|nuclei|ffuf|gobuster|dirbuster|nmap)", re.I),
        re.compile(r"(?i)(metasploit|burpsuite|acunetix|nessus)", re.I),
    ],
    'LOG4SHELL': [
        re.compile(r"\$\{jndi:", re.I),
        re.compile(r"\$\{.*:\/\/", re.I),
    ],
}

SEVERITY_MAP = {
    'SQL_INJECTION': 'CRITICAL',
    'XSS': 'HIGH',
    'PATH_TRAVERSAL': 'HIGH',
    'COMMAND_INJECTION': 'CRITICAL',
    'SCANNER': 'MEDIUM',
    'LOG4SHELL': 'CRITICAL',
}


@dataclass
class WAFEvent:
    timestamp: str
    action: str                    # ALLOW | BLOCK | COUNT
    client_ip: str
    country: str
    uri: str
    method: str
    host: str
    user_agent: str
    rules_matched: list[str] = field(default_factory=list)
    attack_type: Optional[str] = None
    attack_severity: Optional[str] = None
    blocked: bool = False
    query_string: str = ''


def parse_waf_log_line(line: str) -> Optional[WAFEvent]:
    """Parse a single line from a WAF log file."""
    try:
        raw = json.loads(line.strip())
    except json.JSONDecodeError:
        return None

    http_req = raw.get('httpRequest', {})
    uri = http_req.get('uri', '')
    qs = http_req.get('queryString', '')
    user_agent = ''
    for header in http_req.get('httpVersion', {}) and http_req.get('headers', []):
        if header.get('name', '').lower() == 'user-agent':
            user_agent = header.get('value', '')

    action = raw.get('action', 'ALLOW')
    rules_matched = [
        r.get('ruleId', '')
        for r in raw.get('terminatingRuleMatchDetails', [])
        + raw.get('nonTerminatingMatchingRules', [])
    ]

    event = WAFEvent(
        timestamp=raw.get('timestamp', ''),
        action=action,
        client_ip=http_req.get('clientIp', ''),
        country=http_req.get('country', ''),
        uri=uri,
        method=http_req.get('httpMethod', ''),
        host=http_req.get('httpVersion', ''),
        user_agent=user_agent,
        rules_matched=rules_matched,
        blocked=(action == 'BLOCK'),
        query_string=qs,
    )

    # Classify attack type from URI + query string
    target = f'{uri}?{qs}'
    for attack_type, patterns in ATTACK_SIGNATURES.items():
        if any(p.search(target) for p in patterns):
            event.attack_type = attack_type
            event.attack_severity = SEVERITY_MAP.get(attack_type, 'MEDIUM')
            break

    # Also classify from rules matched
    if not event.attack_type and rules_matched:
        rule_str = ' '.join(rules_matched).upper()
        if 'SQLI' in rule_str:
            event.attack_type = 'SQL_INJECTION'
        elif 'XSS' in rule_str:
            event.attack_type = 'XSS'

    return event


def parse_waf_log_file(source: str, bucket: str = None) -> list[WAFEvent]:
    """
    Parse a WAF log file from S3 or local path.

    Args:
        source: S3 key (when bucket provided) or local file path
        bucket: S3 bucket name (if reading from S3)
    """
    if bucket:
        s3 = boto3.client('s3')
        resp = s3.get_object(Bucket=bucket, Key=source)
        content = resp['Body'].read()
    else:
        content = Path(source).read_bytes()

    if source.endswith('.gz'):
        content = gzip.decompress(content)

    lines = content.decode('utf-8').strip().split('\n')
    events = []
    for line in lines:
        if not line.strip():
            continue
        event = parse_waf_log_line(line)
        if event:
            events.append(event)
    return events


def parse_recent_from_s3(bucket: str, prefix: str = '',
                          max_files: int = 20) -> list[WAFEvent]:
    """Fetch and parse the most recent WAF log files from S3."""
    s3 = boto3.client('s3')
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=max_files)
    keys = sorted(
        [o['Key'] for o in resp.get('Contents', [])],
        reverse=True
    )[:max_files]

    all_events = []
    for key in keys:
        all_events.extend(parse_waf_log_file(key, bucket=bucket))
    return all_events
