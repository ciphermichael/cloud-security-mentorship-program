# 📋 Cloud Compliance Audit Tool

> **Week 10** | Phase 3: Threat Detection & SIEM

Automated CIS AWS Foundations Benchmark + ISO 27001 Annex A assessment with evidence-backed HTML reports and posture scoring.

## Usage
```bash
pip install -r requirements.txt

# Console output with score
python src/audit_engine.py --region us-east-1

# Generate HTML report
python src/audit_engine.py --output html --output-file report_templates/audit.html

# JSON for SIEM / dashboard
python src/audit_engine.py --output json | jq '.score'
```

## CIS → ISO 27001 Control Mapping
| CIS Control | ISO 27001 Annex A Control |
|-------------|--------------------------|
| 1.1 Root MFA | A.9.4.3 Password Management |
| 1.4 No Root Keys | A.9.2.3 Management of Privileged Access |
| 1.10 User MFA | A.9.4.3 Password Management |
| 2.1 CloudTrail | A.12.4.1 Event Logging |
| 2.6 S3 Logging | A.12.4.1 Event Logging |
| 4.1 EBS Encryption | A.10.1.1 Cryptographic Controls |
| 5.2 No Open SSH | A.13.1.1 Network Controls |

## Compliance Scoring
Score = (Passed Checks / Total Checks) × 100

A score of 100% = all CIS controls implemented.
