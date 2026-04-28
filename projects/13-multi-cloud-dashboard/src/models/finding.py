"""
Unified finding model for multi-cloud security data.
"""
from dataclasses import dataclass, field
from typing import Optional


SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFORMATIONAL': 4, 'UNKNOWN': 5}
SEVERITY_SCORES = {'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 40, 'LOW': 10, 'INFORMATIONAL': 5, 'UNKNOWN': 0}


@dataclass
class Finding:
    cloud: str              # 'AWS', 'Azure', 'GCP'
    id: str
    title: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
    resource: str
    resource_type: str = ''
    region: str = ''
    service: str = ''
    created_at: str = ''
    updated_at: str = ''
    remediation: str = ''
    tags: dict = field(default_factory=dict)

    @property
    def severity_score(self) -> int:
        return SEVERITY_SCORES.get(self.severity.upper(), 0)

    @property
    def sort_key(self) -> int:
        return SEVERITY_ORDER.get(self.severity.upper(), 5)

    def to_dict(self) -> dict:
        return {
            'cloud': self.cloud,
            'id': self.id,
            'title': self.title,
            'severity': self.severity,
            'resource': self.resource,
            'resource_type': self.resource_type,
            'region': self.region,
            'service': self.service,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'remediation': self.remediation,
            'severity_score': self.severity_score,
        }


def calculate_risk_score(findings: list) -> dict:
    """Calculate overall risk score (0–100, higher = better) from a list of findings or dicts."""
    if not findings:
        return {'overall_score': 100.0, 'grade': 'A', 'total_findings': 0,
                'by_severity': {}, 'by_cloud': {}}

    raw_score = sum(
        SEVERITY_SCORES.get(
            (f.severity if isinstance(f, Finding) else f.get('severity', '')).upper(), 0
        )
        for f in findings
    )
    normalized = max(0.0, 100.0 - min(raw_score / 10.0, 100.0))
    grade = ('A' if normalized >= 90 else 'B' if normalized >= 75 else
             'C' if normalized >= 60 else 'D' if normalized >= 40 else 'F')

    def get_sev(f):
        return (f.severity if isinstance(f, Finding) else f.get('severity', '')).upper()

    def get_cloud(f):
        return f.cloud if isinstance(f, Finding) else f.get('cloud', '')

    return {
        'overall_score': round(normalized, 1),
        'grade': grade,
        'total_findings': len(findings),
        'by_severity': {sev: sum(1 for f in findings if get_sev(f) == sev)
                        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']},
        'by_cloud': {cloud: sum(1 for f in findings if get_cloud(f) == cloud)
                     for cloud in ['AWS', 'Azure', 'GCP']},
    }
