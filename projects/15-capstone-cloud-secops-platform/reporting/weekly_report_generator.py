"""Weekly Security Report Generator — produces HTML summary for email dispatch."""
import json
from datetime import datetime, timezone

def generate_weekly_html(findings: list, posture_score: float,
                          week_start: str, week_end: str) -> str:
    """Generate styled HTML weekly security report."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f.get("severity","LOW")
        if s in sev_counts:
            sev_counts[s] += 1

    trend = "↑ Improved" if posture_score >= 70 else "↓ Needs attention"
    score_color = "#16a34a" if posture_score >= 70 else "#ea580c" if posture_score >= 50 else "#dc2626"

    rows = ""
    for f in sorted(findings, key=lambda x: -x.get("severity_score",0))[:10]:
        sev_c = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706"}.get(f["severity"],"#6b7280")
        rows += (f'<tr><td><b style="color:{sev_c}">{f["severity"]}</b></td>'
                 f'<td>{f.get("check_id","")}</td>'
                 f'<td style="font-size:12px">{f.get("resource","")[:60]}</td>'
                 f'<td style="font-size:12px">{f.get("description","")[:80]}</td></tr>')

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Weekly Security Report</title>
<style>body{{font-family:Arial,sans-serif;max-width:800px;margin:auto;padding:24px;color:#111}}
.header{{background:#0d2137;color:#fff;padding:24px;border-radius:8px;margin-bottom:20px}}
.score{{font-size:48px;font-weight:700;color:{score_color}}}
.kpi{{display:flex;gap:12px;margin:16px 0}}
.card{{flex:1;padding:14px;border-radius:6px;color:#fff;text-align:center;font-weight:700}}
table{{width:100%;border-collapse:collapse}}th{{background:#1b4f8a;color:#fff;padding:8px;text-align:left}}
td{{padding:8px;border-bottom:1px solid #e5e7eb;font-size:13px}}</style>
</head><body>
<div class="header">
<h2 style="margin:0">🛡️ Weekly Security Report</h2>
<p style="margin:4px 0 0;opacity:.8">{week_start} → {week_end}</p>
</div>
<div class="kpi">
<div class="card" style="background:#0d2137">Security Score<div class="score">{posture_score}</div><small>/100 {trend}</small></div>
<div class="card" style="background:#dc2626">CRITICAL<div style="font-size:28px">{sev_counts['CRITICAL']}</div></div>
<div class="card" style="background:#ea580c">HIGH<div style="font-size:28px">{sev_counts['HIGH']}</div></div>
<div class="card" style="background:#d97706">MEDIUM<div style="font-size:28px">{sev_counts['MEDIUM']}</div></div>
</div>
<h3>Top 10 Findings Requiring Action</h3>
<table><tr><th>Severity</th><th>Check ID</th><th>Resource</th><th>Description</th></tr>
{rows}</table>
<p style="font-size:12px;color:#6b7280;margin-top:24px">
Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by Cloud Security Operations Platform</p>
</body></html>"""

if __name__ == "__main__":
    sample_findings = [
        {"severity":"CRITICAL","severity_score":4,"check_id":"IAM-001",
         "resource":"iam/user/alice","description":"No MFA on console user","remediation":"Enable MFA"},
        {"severity":"HIGH","severity_score":3,"check_id":"SG-001",
         "resource":"sg/sg-abc123","description":"SSH open to 0.0.0.0/0","remediation":"Restrict SG"},
    ]
    html = generate_weekly_html(sample_findings, 72.5, "2024-03-04", "2024-03-10")
    with open("reports/templates/weekly_sample.html","w") as f:
        f.write(html)
    print("Weekly report generated: reports/templates/weekly_sample.html")
