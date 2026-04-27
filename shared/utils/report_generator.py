"""Shared report generator — HTML, Markdown, and JSON output for all projects."""
import json
from datetime import datetime, timezone
from pathlib import Path


SEV_COLORS = {
    'CRITICAL': '#dc2626',
    'HIGH':     '#ea580c',
    'MEDIUM':   '#d97706',
    'LOW':      '#16a34a',
    'INFO':     '#2563eb',
}

SEV_EMOJI = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MEDIUM':   '🟡',
    'LOW':      '🟢',
    'INFO':     '🔵',
}


def _count_severities(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = dict.fromkeys(SEV_COLORS, 0)
    for f in findings:
        s = f.get('severity', 'INFO')
        counts[s] = counts.get(s, 0) + 1
    return counts


def _sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: f.get('severity_score', 0), reverse=True)


# ── JSON Report ────────────────────────────────────────────────────────────────

def generate_json_report(findings: list[dict], title: str,
                         account_id: str = 'unknown',
                         metadata: dict | None = None) -> dict:
    """Return a structured dict ready for json.dumps()."""
    counts = _count_severities(findings)
    return {
        'report_title': title,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'account_id': account_id,
        'metadata': metadata or {},
        'summary': {
            'total_findings': len(findings),
            'by_severity': counts,
        },
        'findings': _sort_findings(findings),
    }


def save_json_report(findings: list[dict], title: str,
                     output_dir: str = 'reports',
                     account_id: str = 'unknown',
                     filename: str | None = None) -> Path:
    """Save a JSON report to disk and return the path."""
    out = Path(output_dir)
    out.mkdir(exist_ok=True)
    if not filename:
        ts = datetime.now().strftime('%Y-%m-%d')
        slug = title.lower().replace(' ', '-').replace('/', '-')[:30]
        filename = f'{ts}-{slug}.json'
    path = out / filename
    report = generate_json_report(findings, title, account_id)
    path.write_text(json.dumps(report, indent=2))
    return path


# ── HTML Report ────────────────────────────────────────────────────────────────

def generate_html_report(findings: list[dict], title: str,
                         account_id: str = 'unknown') -> str:
    """Generate a styled standalone HTML security report."""
    counts = _count_severities(findings)
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    rows = ''
    for f in _sort_findings(findings):
        sev = f.get('severity', 'INFO')
        color = SEV_COLORS.get(sev, '#6b7280')
        mitre = f.get('mitre_technique', '')
        mitre_cell = f'<code>{mitre}</code>' if mitre else '—'
        resource = str(f.get('resource', ''))[:80]
        rows += (
            f'<tr>'
            f'<td><span class="badge" style="background:{color}">{sev}</span></td>'
            f'<td><code>{f.get("check_id", "")}</code></td>'
            f'<td class="mono">{resource}</td>'
            f'<td>{f.get("description", "")}</td>'
            f'<td>{f.get("remediation", "")}</td>'
            f'<td>{mitre_cell}</td>'
            f'</tr>'
        )

    sev_cards = ''.join(
        f'<div class="sev-card" style="background:{SEV_COLORS[s]}">'
        f'{s}<span>{counts.get(s, 0)}</span></div>'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,Arial,sans-serif;background:#f3f4f6;
         color:#111827;padding:24px}}
    .header{{background:#0d2137;color:#fff;padding:28px 32px;
             border-radius:10px;margin-bottom:24px}}
    .header h1{{font-size:22px;margin-bottom:6px}}
    .meta{{opacity:.75;font-size:13px}}
    .summary{{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}}
    .sev-card{{padding:12px 18px;border-radius:8px;color:#fff;font-weight:700;
               min-width:90px;text-align:center}}
    .sev-card span{{display:block;font-size:26px}}
    table{{width:100%;border-collapse:collapse;background:#fff;
           border-radius:10px;overflow:hidden;
           box-shadow:0 1px 4px rgba(0,0,0,.1)}}
    th{{background:#1b4f8a;color:#fff;padding:10px 14px;
        text-align:left;font-size:12px;text-transform:uppercase}}
    td{{padding:9px 14px;border-bottom:1px solid #e5e7eb;
        font-size:12px;vertical-align:top}}
    tr:last-child td{{border-bottom:none}}
    tr:hover{{background:#f0f7ff}}
    .badge{{color:#fff;padding:2px 8px;border-radius:4px;
            font-size:11px;font-weight:700;white-space:nowrap}}
    .mono{{font-family:monospace;word-break:break-all;font-size:11px}}
    code{{background:#f3f4f6;padding:1px 5px;border-radius:3px;font-size:11px}}
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ {title}</h1>
    <p class="meta">Account: {account_id} &nbsp;|&nbsp; Generated: {ts}
       &nbsp;|&nbsp; Total: {len(findings)} findings</p>
  </div>
  <div class="summary">{sev_cards}</div>
  <table>
    <thead><tr>
      <th>Severity</th><th>Check ID</th><th>Resource</th>
      <th>Description</th><th>Remediation</th><th>MITRE</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""


# ── Markdown Report ────────────────────────────────────────────────────────────

def generate_markdown_report(findings: list[dict], title: str,
                              account_id: str = 'unknown') -> str:
    """Generate a GitHub-flavored Markdown security report."""
    counts = _count_severities(findings)
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    lines = [
        f'# 🛡️ {title}',
        '',
        f'**Generated:** {ts}  ',
        f'**Account:** {account_id}  ',
        f'**Total Findings:** {len(findings)}',
        '',
        '## Summary',
        '',
    ]
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
        lines.append(f'- {SEV_EMOJI[sev]} **{sev}:** {counts.get(sev, 0)}')

    lines += [
        '',
        '## Findings',
        '',
        '| Severity | Check ID | Resource | Description | Remediation | MITRE |',
        '|----------|----------|----------|-------------|-------------|-------|',
    ]

    for f in _sort_findings(findings):
        sev = f.get('severity', 'INFO')
        emoji = SEV_EMOJI.get(sev, '')
        cid = f.get('check_id', '')
        res = str(f.get('resource', ''))[:55].replace('|', '\\|')
        desc = str(f.get('description', ''))[:90].replace('|', '\\|')
        rem = str(f.get('remediation', ''))[:80].replace('|', '\\|')
        mitre = f.get('mitre_technique', '—')
        lines.append(
            f'| {emoji} **{sev}** | `{cid}` | `{res}` | {desc} | {rem} | {mitre} |'
        )

    return '\n'.join(lines) + '\n'


# ── Console Summary ────────────────────────────────────────────────────────────

def print_summary(findings: list[dict], tool_name: str = 'Security Audit'):
    """Print a coloured console summary of findings."""
    counts = _count_severities(findings)
    print(f'\n{"=" * 55}')
    print(f'  {tool_name}')
    print(f'  Total findings: {len(findings)}')
    print(f'{"=" * 55}')
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        count = counts.get(sev, 0)
        if count:
            print(f'  {SEV_EMOJI[sev]} {sev:<10} {count}')
    print()
