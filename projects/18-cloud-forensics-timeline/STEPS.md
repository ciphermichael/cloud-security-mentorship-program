# Project 18 — Cloud Forensics Timeline Builder: Step-by-Step Guide

> **Skill Level:** Advanced | **Time:** ~12 hours | **Week:** 18

---

## Overview

Build an automated cloud forensic investigation tool that collects CloudTrail evidence, builds chronological attack timelines, maps events to MITRE ATT&CK, and generates an executive incident report.

**Architecture:**
```
CloudTrail S3 Bucket
      ↓ (ForensicEvidenceCollector)
evidence/INCIDENT-ID/
  ├── cloudtrail/          ← downloaded + SHA-256 verified
  └── chain-of-custody.json
      ↓ (TimelineBuilder)
Chronological DataFrame + MITRE annotations
      ↓ (NarrativeGenerator)
  ├── reports/attack-narrative.md    ← executive report
  ├── reports/timeline.csv           ← analyst spreadsheet
  └── reports/mitre-navigator.json   ← ATT&CK Navigator layer
```

---

## Prerequisites

```bash
pip install boto3 pandas plotly pytest moto
```

AWS permissions needed:
- `s3:GetObject`, `s3:ListBucket` on the CloudTrail log bucket
- `sts:GetCallerIdentity`
- `athena:StartQueryExecution`, `athena:GetQueryResults` (for Athena queries)

---

## Step 1 — Prepare Your Evidence Directory

```bash
cd projects/18-cloud-forensics-timeline
mkdir -p evidence data/simulated_incidents reports

# The evidence directory must NEVER be committed to git
# It's in .gitignore already — verify:
grep evidence .gitignore
```

---

## Step 2 — Generate a Simulated Incident Dataset

```bash
python scripts/generate_incident.py --incident-id IR-2024-001

# This creates: data/simulated_incidents/IR-2024-001/cloudtrail_events.json
# Scenario: EC2 IMDS credential theft → enumeration → escalation → exfiltration
```

The simulated incident follows this kill chain:
```
03:00  ConsoleLogin from 198.51.100.42 (Initial Access)
03:02  GetCallerIdentity (Discovery)
03:03  ListUsers, ListRoles, ListBuckets (Discovery)
03:08  CreatePolicyVersion + SetDefaultPolicyVersion (Privilege Escalation)
03:12  GetObject x 500 on company-financials bucket (Collection)
03:15  CreateUser "backdoor-user" (Persistence)
03:18  CreateAccessKey for backdoor-user (Persistence)
```

---

## Step 3 — Run the Timeline Builder

```bash
# Against simulated data
python -m src.timeline_builder \
  --evidence-dir data/simulated_incidents/IR-2024-001 \
  --filter-ip 198.51.100.42 \
  --output reports

# Against real CloudTrail evidence (after collection)
python -m src.evidence_collector \
  --incident-id IR-2024-001 \
  --bucket your-cloudtrail-bucket \
  --prefix AWSLogs/123456789012/CloudTrail \
  --start 2024-01-15 \
  --end 2024-01-16

python -m src.timeline_builder \
  --evidence-dir evidence/IR-2024-001 \
  --filter-ip 198.51.100.42 \
  --output reports
```

---

## Step 4 — Run Tests

```bash
pytest tests/ -v --tb=short

# Expected: 22 tests pass covering:
# - MITRE mapping accuracy
# - Timeline sorting
# - Entity filtering
# - Kill chain stage detection
# - Narrative generation
```

---

## Step 5 — Generate MITRE ATT&CK Navigator Layer

```python
# src/mitre_navigator.py
import json
from timeline_builder import MITRE_MAP

def generate_navigator_layer(techniques_detected: set, incident_id: str) -> dict:
    """Generate an ATT&CK Navigator layer JSON for the observed techniques."""
    layer = {
        "name": f"Incident {incident_id}",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Techniques observed in incident {incident_id}",
        "techniques": [
            {
                "techniqueID": tid,
                "tactic": tactic.lower().replace(" ", "-"),
                "color": "#ff6666" if "Escalation" in tactic else "#ffaa00",
                "comment": f"Observed in {incident_id}",
                "enabled": True,
                "score": 100,
            }
            for tid, _, tactic in MITRE_MAP.values()
            if tid in techniques_detected
        ],
    }
    return layer

# Usage
detected = {'T1033', 'T1087.004', 'T1098.003', 'T1530', 'T1136.003', 'T1098.001'}
layer = generate_navigator_layer(detected, 'IR-2024-001')
with open('reports/mitre-navigator.json', 'w') as f:
    json.dump(layer, f, indent=2)
# Upload to https://mitre-attack.github.io/attack-navigator/
```

---

## Step 6 — Review the Output Files

After running the tool, `reports/` contains:

```
reports/
├── timeline.csv               # Every event: time, actor, IP, MITRE tactic
├── attack-narrative.md        # Human-readable attack story
├── mitre-navigator.json       # Import into ATT&CK Navigator
└── chain-of-custody.json      # SHA-256 hashes of all evidence files
```

**Sample attack-narrative.md section:**
```markdown
## Attack Summary
| Field | Value |
|-------|-------|
| Start | 2024-01-15 03:00:00 UTC |
| End | 2024-01-15 03:18:00 UTC |
| Duration | 0:18:00 |
| Total Events | 47 |
| Source IPs | 198.51.100.42 |

## MITRE ATT&CK Tactics (chronological)
- Initial Access
- Discovery
- Privilege Escalation
- Collection
- Persistence
```

---

## Step 7 — GitHub Portfolio Checklist

- [ ] `src/evidence_collector.py` — downloads and SHA-256 verifies CloudTrail files
- [ ] `src/timeline_builder.py` — builds sorted MITRE-annotated timeline
- [ ] `tests/test_timeline.py` — 22 unit tests, all passing
- [ ] `queries/` — Athena queries for timeline reconstruction
- [ ] `data/simulated_incidents/` — sample incident for demo (no real data)
- [ ] `reports/` — sample output: narrative.md, timeline.csv, mitre-navigator.json
- [ ] README with kill chain diagram and example output

---

## Common Issues

| Issue | Fix |
|-------|-----|
| `gzip.BadGzipFile` | CloudTrail files use gzip — open with `gzip.decompress()` |
| `KeyError: Records` | Some log files are JSON arrays, not `{"Records": [...]}` — handle both |
| Empty timeline | Check your `entity_filter` — typo in IP/ARN silently returns no results |
| Missing MITRE tactic | Add the event name to `MITRE_MAP` in `timeline_builder.py` |
