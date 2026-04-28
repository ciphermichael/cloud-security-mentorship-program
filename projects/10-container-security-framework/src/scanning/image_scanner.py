"""
Container image scanner — wraps Trivy CLI and parses its JSON output.
Provides a Python API for CI/CD integration and report generation.

Requirements:
    trivy must be installed: brew install trivy (macOS) or see https://trivy.dev
"""
import json
import shutil
import subprocess
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}


@dataclass
class Vulnerability:
    vuln_id: str
    pkg_name: str
    severity: str
    title: str
    description: str
    installed_version: str
    fixed_version: str
    references: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    image: str
    total_vulns: int
    by_severity: dict[str, int]
    vulnerabilities: list[Vulnerability]
    passed_gate: bool
    gate_threshold: str  # CRITICAL, HIGH, MEDIUM, or LOW


def _trivy_available() -> bool:
    return shutil.which('trivy') is not None


def scan_image(image: str,
               severity_threshold: str = 'HIGH',
               ignore_unfixed: bool = True) -> ScanResult:
    """
    Scan a container image with Trivy and return structured results.

    Args:
        image:             Docker image reference (e.g. 'nginx:latest')
        severity_threshold: Minimum severity to report ('CRITICAL','HIGH','MEDIUM','LOW')
        ignore_unfixed:    Skip CVEs with no fix available

    Returns:
        ScanResult with vulnerability counts and pass/fail gate decision
    """
    if not _trivy_available():
        raise RuntimeError(
            'Trivy is not installed. Install with: brew install trivy '
            'or https://trivy.dev/latest/getting-started/installation/'
        )

    cmd = [
        'trivy', 'image',
        '--format', 'json',
        '--severity', ','.join(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
        '--quiet',
    ]
    if ignore_unfixed:
        cmd.append('--ignore-unfixed')
    cmd.append(image)

    logger.info('Scanning image: %s', image)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode not in (0, 1):
        raise RuntimeError(f'Trivy scan failed: {result.stderr}')

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f'Could not parse Trivy output: {e}') from e

    return _parse_trivy_output(image, data, severity_threshold)


def _parse_trivy_output(image: str, data: dict,
                         gate_threshold: str) -> ScanResult:
    """Parse raw Trivy JSON output into a ScanResult."""
    vulns: list[Vulnerability] = []
    counts: dict[str, int] = dict.fromkeys(
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'], 0
    )

    for result in data.get('Results', []):
        for v in result.get('Vulnerabilities') or []:
            sev = v.get('Severity', 'UNKNOWN')
            counts[sev] = counts.get(sev, 0) + 1
            vulns.append(Vulnerability(
                vuln_id=v.get('VulnerabilityID', ''),
                pkg_name=v.get('PkgName', ''),
                severity=sev,
                title=v.get('Title', ''),
                description=(v.get('Description', ''))[:200],
                installed_version=v.get('InstalledVersion', ''),
                fixed_version=v.get('FixedVersion', ''),
                references=v.get('References', [])[:3],
            ))

    vulns.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 9))
    threshold_idx = SEVERITY_ORDER.get(gate_threshold, 1)
    passed = all(
        SEVERITY_ORDER.get(v.severity, 9) > threshold_idx
        for v in vulns
    )

    return ScanResult(
        image=image,
        total_vulns=len(vulns),
        by_severity=counts,
        vulnerabilities=vulns,
        passed_gate=passed,
        gate_threshold=gate_threshold,
    )


def passes_gate(scan_result: ScanResult | dict,
                severity_threshold: str = 'HIGH') -> bool:
    """
    Return True if the scan result passes the CI/CD security gate.

    Args:
        scan_result:       ScanResult or dict from parse_trivy_result()
        severity_threshold: Block on this severity and above
    """
    if isinstance(scan_result, dict):
        counts = scan_result
    else:
        counts = scan_result.by_severity

    threshold_idx = SEVERITY_ORDER.get(severity_threshold, 1)
    for sev, count in counts.items():
        sev_idx = SEVERITY_ORDER.get(sev, 9)
        if sev_idx <= threshold_idx and count > 0:
            return False
    return True


def parse_trivy_result(raw: dict) -> dict[str, int]:
    """Parse a Trivy JSON result dict into severity counts. For unit testing."""
    counts: dict[str, int] = dict.fromkeys(
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'], 0
    )
    for result in raw.get('Results', []):
        for v in result.get('Vulnerabilities') or []:
            sev = v.get('Severity', 'UNKNOWN')
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def scan_dockerfile(dockerfile_path: str) -> list[dict]:
    """
    Run Trivy config scan on a Dockerfile for misconfigurations.
    Returns list of misconfiguration findings.
    """
    if not _trivy_available():
        raise RuntimeError('Trivy is not installed.')

    cmd = ['trivy', 'config', '--format', 'json', '--quiet', dockerfile_path]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for r in data.get('Results', []):
        for m in r.get('Misconfigurations') or []:
            findings.append({
                'id': m.get('ID', ''),
                'title': m.get('Title', ''),
                'severity': m.get('Severity', ''),
                'description': m.get('Description', '')[:200],
                'resolution': m.get('Resolution', ''),
            })
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f['severity'], 9))
