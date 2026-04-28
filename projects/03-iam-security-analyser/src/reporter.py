"""
IAM Security Analyser — report generation.
Wraps the shared report generator with IAM-specific formatting.
"""
import json
import sys
import os
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../shared'))
from utils.report_generator import (
    generate_html_report,
    generate_markdown_report,
    generate_json_report,
    print_summary,
)
from utils.aws_helpers import count_by_severity, sort_findings


def save_report(findings: list[dict], account_id: str,
                output_dir: str = 'reports',
                formats: list[str] | None = None) -> dict[str, str]:
    """
    Save the IAM security report in one or more formats.

    Args:
        findings:   List of finding dicts from all checks
        account_id: AWS account ID being audited
        output_dir: Directory to write reports to
        formats:    List of formats: ['json', 'html', 'markdown']
                    Defaults to ['json']

    Returns:
        Dict mapping format → output file path
    """
    formats = formats or ['json']
    out = Path(output_dir)
    out.mkdir(exist_ok=True)
    ts = datetime.now().strftime('%Y-%m-%d')
    title = f'IAM Security Assessment — Account {account_id}'
    sorted_findings = sort_findings(findings)
    paths: dict[str, str] = {}

    if 'json' in formats:
        path = out / f'{ts}-iam-audit.json'
        path.write_text(json.dumps(
            generate_json_report(sorted_findings, title, account_id), indent=2
        ))
        paths['json'] = str(path)

    if 'html' in formats:
        path = out / f'{ts}-iam-audit.html'
        path.write_text(generate_html_report(sorted_findings, title, account_id))
        paths['html'] = str(path)

    if 'markdown' in formats:
        path = out / f'{ts}-iam-audit.md'
        path.write_text(generate_markdown_report(sorted_findings, title, account_id))
        paths['markdown'] = str(path)

    return paths


def print_console_summary(findings: list[dict]):
    """Print a coloured console summary."""
    print_summary(findings, 'IAM Security Analyser')
    counts = count_by_severity(findings)
    if counts.get('CRITICAL', 0) > 0:
        print('  ⚠️  Immediate action required for CRITICAL findings.')
