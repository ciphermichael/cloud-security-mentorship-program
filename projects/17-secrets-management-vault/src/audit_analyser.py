"""
Vault audit log analyser — parses the Vault audit log (NDJSON format)
and flags suspicious access patterns: root token usage, access denied bursts,
secret mass-reading, and after-hours access.
"""
import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Hours considered "outside business hours" (UTC)
BUSINESS_HOURS = set(range(8, 19))  # 08:00–18:59 UTC


@dataclass
class AuditFinding:
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    rule_id: str
    description: str
    evidence: str
    accessor: str = ''
    path: str = ''
    timestamp: str = ''


def _parse_entry(line: str) -> dict | None:
    try:
        return json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None


def _utc_hour(ts_str: str) -> int | None:
    """Extract UTC hour from an RFC3339 timestamp string."""
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return dt.hour
    except (ValueError, TypeError):
        return None


def analyse_vault_audit(log_path: str) -> list[AuditFinding]:
    """
    Parse a Vault audit log file and return security findings.

    Args:
        log_path: Path to the Vault audit log file (NDJSON format)

    Returns:
        List of AuditFinding sorted by severity
    """
    findings: list[AuditFinding] = []
    denied_by_accessor: Counter = Counter()
    read_by_accessor: Counter = Counter()
    after_hours_by_accessor: Counter = Counter()

    path = Path(log_path)
    if not path.exists():
        logger.warning('Audit log not found: %s', log_path)
        return []

    entries = []
    with open(path) as f:
        for line in f:
            entry = _parse_entry(line)
            if entry:
                entries.append(entry)

    for entry in entries:
        auth = entry.get('auth', {})
        req = entry.get('request', {})
        resp = entry.get('response', {})
        error = entry.get('error', '')
        ts = entry.get('time', '')
        accessor = auth.get('accessor', auth.get('display_name', 'unknown'))
        req_path = req.get('path', '')
        http_status = resp.get('status_code', 0)

        # ── Rule 1: Root token used ───────────────────────────────────────────
        if auth.get('token_type') == 'service' and auth.get('display_name') == 'root':
            findings.append(AuditFinding(
                severity='CRITICAL',
                rule_id='VAULT-001',
                description='Root Vault token used for an operation.',
                evidence=f'Operation: {req.get("operation")} on path: {req_path}',
                accessor=accessor,
                path=req_path,
                timestamp=ts,
            ))

        # ── Rule 2: Access denied ─────────────────────────────────────────────
        if http_status == 403 or 'permission denied' in error.lower():
            denied_by_accessor[accessor] += 1

        # ── Rule 3: Mass secret reading ───────────────────────────────────────
        if req.get('operation') in ('read', 'list') and 'secret/' in req_path:
            read_by_accessor[accessor] += 1

        # ── Rule 4: After-hours access ────────────────────────────────────────
        hour = _utc_hour(ts)
        if hour is not None and hour not in BUSINESS_HOURS:
            after_hours_by_accessor[accessor] += 1

    # Threshold-based findings
    for accessor, count in denied_by_accessor.items():
        if count >= 10:
            findings.append(AuditFinding(
                severity='HIGH',
                rule_id='VAULT-002',
                description=f'Accessor denied {count} times — potential brute force or misconfiguration.',
                evidence=f'{count} permission-denied events',
                accessor=accessor,
            ))

    for accessor, count in read_by_accessor.items():
        if count >= 50:
            findings.append(AuditFinding(
                severity='MEDIUM',
                rule_id='VAULT-003',
                description=f'Accessor read {count} secrets — potential bulk exfiltration.',
                evidence=f'{count} secret read operations',
                accessor=accessor,
            ))

    for accessor, count in after_hours_by_accessor.items():
        if count >= 5:
            findings.append(AuditFinding(
                severity='MEDIUM',
                rule_id='VAULT-004',
                description=f'Accessor performed {count} operations outside business hours.',
                evidence=f'{count} operations outside 08:00–18:59 UTC',
                accessor=accessor,
            ))

    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    findings.sort(key=lambda f: order.get(f.severity, 9))

    logger.info('Vault audit analysis: %d findings from %d entries',
                len(findings), len(entries))
    return findings


def generate_audit_report(findings: list[AuditFinding],
                           output_path: str = 'reports/vault-audit.json') -> str:
    """Save findings as a JSON report and return the path."""
    out = Path(output_path)
    out.parent.mkdir(exist_ok=True)
    report = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'total_findings': len(findings),
        'by_severity': {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        },
        'findings': [asdict(f) for f in findings],
    }
    out.write_text(json.dumps(report, indent=2))
    return str(out)
