"""
Cloud Security Posture Scoring Engine.
Aggregates findings from Security Hub, GuardDuty, Config, and IAM
into a single weighted risk score (0 = perfect, 100 = critical risk).
"""
import boto3
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


# ── Scoring Weights ────────────────────────────────────────────────────────────

CATEGORY_WEIGHTS: dict[str, float] = {
    'iam':        0.25,
    'network':    0.20,
    'data':       0.20,
    'logging':    0.15,
    'compliance': 0.10,
    'runtime':    0.10,
}

SEVERITY_SCORES: dict[str, int] = {
    'CRITICAL': 100,
    'HIGH':     70,
    'MEDIUM':   40,
    'LOW':      10,
    'INFO':     2,
}

# Security Hub product-to-category mapping
PRODUCT_CATEGORY_MAP = {
    'GuardDuty':    'runtime',
    'IAM':          'iam',
    'S3':           'data',
    'RDS':          'data',
    'KMS':          'data',
    'EC2':          'network',
    'VPC':          'network',
    'CloudTrail':   'logging',
    'Config':       'compliance',
    'SecurityHub':  'compliance',
}


@dataclass
class CategoryScore:
    category: str
    score: float          # 0-100 (higher = more risk)
    finding_count: int
    critical_count: int
    high_count: int
    top_findings: list[dict] = field(default_factory=list)


@dataclass
class PostureReport:
    account_id: str
    region: str
    generated_at: str
    overall_score: float          # 0-100
    risk_level: str               # CRITICAL | HIGH | MEDIUM | LOW | MINIMAL
    category_scores: dict[str, CategoryScore]
    total_findings: int
    findings_by_severity: dict[str, int]
    trend: str = 'unknown'        # improved | degraded | stable | unknown


class PostureScorer:

    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self.sh = boto3.client('securityhub', region_name=region)
        self.iam = boto3.client('iam', region_name=region)
        self.ec2 = boto3.client('ec2', region_name=region)
        self.sts = boto3.client('sts', region_name=region)
        self._findings: list[dict] = []

    def _get_account_id(self) -> str:
        return self.sts.get_caller_identity()['Account']

    # ── Data Collection ────────────────────────────────────────────────────────

    def collect_security_hub_findings(self) -> list[dict]:
        """Pull all active, non-suppressed findings from Security Hub."""
        findings = []
        paginator = self.sh.get_paginator('get_findings')
        for page in paginator.paginate(
            Filters={
                'RecordState':    [{'Value': 'ACTIVE',    'Comparison': 'EQUALS'}],
                'WorkflowStatus': [{'Value': 'NEW',       'Comparison': 'EQUALS'},
                                   {'Value': 'NOTIFIED',  'Comparison': 'EQUALS'}],
            },
            SortCriteria=[{'Field': 'SeverityNormalized', 'SortOrder': 'desc'}]
        ):
            findings.extend(page['Findings'])
        self._findings = findings
        return findings

    def _categorise_finding(self, finding: dict) -> str:
        """Determine which posture category a finding belongs to."""
        product = finding.get('ProductName', '')
        for key, category in PRODUCT_CATEGORY_MAP.items():
            if key.lower() in product.lower():
                return category

        # Fallback: look at resource types
        for resource in finding.get('Resources', []):
            rtype = resource.get('Type', '')
            for key, category in PRODUCT_CATEGORY_MAP.items():
                if key.lower() in rtype.lower():
                    return category

        return 'compliance'  # Default category

    # ── Scoring ────────────────────────────────────────────────────────────────

    def score_category(self, category: str, findings: list[dict]) -> CategoryScore:
        """Score a single posture category 0-100."""
        if not findings:
            return CategoryScore(
                category=category, score=0.0,
                finding_count=0, critical_count=0, high_count=0
            )

        scores = [
            SEVERITY_SCORES.get(f.get('Severity', {}).get('Label', 'LOW'), 10)
            for f in findings
        ]
        # Score = weighted average of individual finding scores
        raw_score = sum(scores) / len(scores)
        # Apply a multiplier for critical count (more criticals = higher risk)
        critical_count = sum(1 for f in findings
                             if f.get('Severity', {}).get('Label') == 'CRITICAL')
        high_count = sum(1 for f in findings
                         if f.get('Severity', {}).get('Label') == 'HIGH')

        # Boost score if there are criticals
        boost = min(critical_count * 5, 20)
        final_score = min(raw_score + boost, 100.0)

        top = sorted(
            findings,
            key=lambda f: SEVERITY_SCORES.get(f.get('Severity', {}).get('Label', 'LOW'), 0),
            reverse=True
        )[:5]

        return CategoryScore(
            category=category,
            score=round(final_score, 1),
            finding_count=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            top_findings=[
                {
                    'id': f.get('Id', '')[-40:],
                    'severity': f.get('Severity', {}).get('Label', ''),
                    'title': f.get('Title', '')[:100],
                    'resource': (f.get('Resources', [{}])[0].get('Id', ''))[-60:],
                }
                for f in top
            ]
        )

    def calculate_overall_score(self,
                                category_scores: dict[str, CategoryScore]) -> float:
        """Weighted average of category scores."""
        weighted_sum = sum(
            CATEGORY_WEIGHTS.get(cat, 0.1) * cs.score
            for cat, cs in category_scores.items()
        )
        total_weight = sum(
            CATEGORY_WEIGHTS.get(cat, 0.1)
            for cat in category_scores
        )
        return round(weighted_sum / max(total_weight, 0.001), 1)

    @staticmethod
    def risk_level(score: float) -> str:
        if score >= 70:  return 'CRITICAL'
        if score >= 50:  return 'HIGH'
        if score >= 30:  return 'MEDIUM'
        if score >= 10:  return 'LOW'
        return 'MINIMAL'

    # ── Main Runner ────────────────────────────────────────────────────────────

    def run(self) -> PostureReport:
        account_id = self._get_account_id()
        findings = self.collect_security_hub_findings()

        # Group findings by category
        by_category: dict[str, list[dict]] = {cat: [] for cat in CATEGORY_WEIGHTS}
        for f in findings:
            cat = self._categorise_finding(f)
            by_category.setdefault(cat, []).append(f)

        category_scores = {
            cat: self.score_category(cat, cat_findings)
            for cat, cat_findings in by_category.items()
        }

        overall = self.calculate_overall_score(category_scores)

        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get('Severity', {}).get('Label', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return PostureReport(
            account_id=account_id,
            region=self.region,
            generated_at=datetime.now(timezone.utc).isoformat(),
            overall_score=overall,
            risk_level=self.risk_level(overall),
            category_scores=category_scores,
            total_findings=len(findings),
            findings_by_severity=severity_counts,
        )

    def save_report(self, report: PostureReport, output_dir: str = 'reports') -> Path:
        out = Path(output_dir)
        out.mkdir(exist_ok=True)

        def serialise(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return asdict(obj)
            raise TypeError(f'Unserializable: {type(obj)}')

        filename = out / f"posture-score-{datetime.now().strftime('%Y-%m-%d')}.json"
        filename.write_text(json.dumps(asdict(report), indent=2))
        return filename


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Cloud Security Posture Scorer')
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--output', default='reports')
    args = parser.parse_args()

    scorer = PostureScorer(region=args.region)
    print('[*] Collecting Security Hub findings...')
    report = scorer.run()
    path = scorer.save_report(report, args.output)

    print(f'\n{"="*50}')
    print(f'Cloud Security Posture Score: {report.overall_score}/100')
    print(f'Risk Level: {report.risk_level}')
    print(f'Total Findings: {report.total_findings}')
    print(f'\nCategory Breakdown:')
    for cat, cs in report.category_scores.items():
        print(f'  {cat:12s}: {cs.score:5.1f}/100  ({cs.finding_count} findings, '
              f'{cs.critical_count} CRITICAL)')
    print(f'\nReport saved → {path}')
