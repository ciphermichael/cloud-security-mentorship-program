# 📊 Multi-Cloud Security Dashboard

> **Week 15** | Phase 4: DevSecOps & Automation

Streamlit CSPM dashboard aggregating AWS Security Hub, Prowler, and Azure Defender findings in a single pane of glass.

## Run
```bash
pip install streamlit plotly pandas boto3
streamlit run src/app.py
```

Opens at http://localhost:8501

## Data Sources
| Source | How to Connect |
|--------|---------------|
| Demo Data | Select in sidebar — no setup needed |
| AWS Security Hub | Set AWS credentials in environment |
| Prowler | Run Prowler, point to JSON output file |

## Dashboard Pages
| Tab | What It Shows |
|-----|--------------|
| 🏠 Overview | Security posture score, severity breakdown, top critical/high findings |
| 📋 All Findings | Full filterable table by severity, cloud, and service |
| 📊 Compliance | Risk heatmap by service, per-cloud posture gauges |

## Posture Score
Score = 100 − (CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1)

Higher score = better security posture. Target: ≥ 70.
