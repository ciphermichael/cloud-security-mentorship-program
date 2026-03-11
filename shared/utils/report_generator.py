"""Generate HTML and Markdown security reports from findings lists."""
from datetime import datetime
from typing import List


SEV_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
    "MEDIUM": "#d97706", "LOW": "#16a34a", "INFO": "#2563eb",
}


def _count_severities(findings: List[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1
    return counts


def generate_html_report(findings: List[dict], title: str,
                         account_id: str = "unknown") -> str:
    """Generate a styled HTML security report."""
    counts = _count_severities(findings)
    rows = ""
    for f in sorted(findings, key=lambda x: -x.get("severity_score", 0)):
        color = SEV_COLORS.get(f["severity"], "#6b7280")
        rows += (
            f'<tr>'
            f'<td><span class="badge" style="background:{color}">'
            f'{f["severity"]}</span></td>'
            f'<td><code>{f["check_id"]}</code></td>'
            f'<td class="resource">{f["resource"]}</td>'
            f'<td>{f["description"]}</td>'
            f'<td>{f["remediation"]}</td>'
            f'</tr>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, Arial, sans-serif; background: #f3f4f6;
            color: #111827; padding: 24px; }}
    .header {{ background: #0d2137; color: #fff; padding: 28px 32px;
               border-radius: 10px; margin-bottom: 24px; }}
    .header h1 {{ font-size: 24px; margin-bottom: 8px; }}
    .meta {{ opacity: .75; font-size: 14px; }}
    .summary {{ display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }}
    .sev-card {{ padding: 14px 20px; border-radius: 8px; color: #fff;
                 font-weight: 700; min-width: 90px; text-align: center; }}
    .sev-card span {{ display: block; font-size: 28px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff;
             border-radius: 10px; overflow: hidden;
             box-shadow: 0 1px 4px rgba(0,0,0,.1); }}
    th {{ background: #1b4f8a; color: #fff; padding: 10px 14px;
          text-align: left; font-size: 13px; }}
    td {{ padding: 10px 14px; border-bottom: 1px solid #e5e7eb;
          font-size: 13px; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover {{ background: #f0f7ff; }}
    .badge {{ color: #fff; padding: 2px 8px; border-radius: 4px;
              font-size: 11px; font-weight: 700; }}
    .resource {{ font-family: monospace; font-size: 12px; word-break: break-all; }}
    code {{ background: #f3f4f6; padding: 1px 5px; border-radius: 3px;
            font-size: 12px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ {title}</h1>
    <p class="meta">Account: {account_id} &nbsp;|&nbsp;
       Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
       Total: {len(findings)} findings</p>
  </div>
  <div class="summary">
    <div class="sev-card" style="background:#dc2626">CRITICAL<span>{counts['CRITICAL']}</span></div>
    <div class="sev-card" style="background:#ea580c">HIGH<span>{counts['HIGH']}</span></div>
    <div class="sev-card" style="background:#d97706">MEDIUM<span>{counts['MEDIUM']}</span></div>
    <div class="sev-card" style="background:#16a34a">LOW<span>{counts['LOW']}</span></div>
    <div class="sev-card" style="background:#2563eb">INFO<span>{counts['INFO']}</span></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>Check ID</th><th>Resource</th>
        <th>Description</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
    return html


def generate_markdown_report(findings: List[dict], title: str) -> str:
    """Generate a Markdown security report."""
    counts = _count_severities(findings)
    ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    md = f"# 🛡️ {title}\n\n"
    md += f"**Generated:** {ts}  \n**Total Findings:** {len(findings)}\n\n"
    md += "## Summary\n\n"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                 "LOW": "🟢", "INFO": "🔵"}[sev]
        md += f"- {emoji} **{sev}:** {counts.get(sev, 0)}\n"

    md += "\n## Findings\n\n"
    md += "| Severity | Check ID | Resource | Description | Remediation |\n"
    md += "|----------|----------|----------|-------------|-------------|\n"
    for f in sorted(findings, key=lambda x: -x.get("severity_score", 0)):
        res = f['resource'][:55].replace("|", "\\|")
        desc = f['description'][:80].replace("|", "\\|")
        rem = f['remediation'][:80].replace("|", "\\|")
        md += f"| **{f['severity']}** | `{f['check_id']}` | `{res}` | {desc} | {rem} |\n"
    return md
