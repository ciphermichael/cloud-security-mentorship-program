# 🪣 Storage Security Scanner

> **Week 3** | Phase 1: Foundations

Detects S3 misconfigurations including public exposure, missing encryption, and PII/secret patterns in object content.

## Usage
```bash
pip install -r requirements.txt
python src/scanner.py --region us-east-1 --output html
python src/scanner.py --scan-data   # enables sensitive data content scan
python src/scanner.py --output json > scan_results.json
```

## Security Checks
| Check ID | Severity | Description |
|----------|----------|-------------|
| S3-001 | 🟠 HIGH | Block Public Access disabled |
| S3-002 | 🔴 CRITICAL | Public ACL grants (AllUsers/AuthenticatedUsers) |
| S3-003 | 🟠 HIGH | No server-side encryption configured |
| S3-004 | 🟡 MEDIUM | No server access logging |
| S3-005 | 🟢 LOW | Versioning disabled (ransomware risk) |
| S3-DATA-AWS_ACCESS_KEY | 🔴 CRITICAL | AWS access key found in object |
| S3-DATA-PRIVATE_KEY | 🔴 CRITICAL | Private key file in bucket |
| S3-DATA-CREDIT_CARD | 🔴 CRITICAL | PCI DSS — credit card number found |

## Interview Talking Points
- "I built a scanner that detects 10 different sensitive data patterns in S3, including AWS keys, private keys, and PII"
- "The tool helped identify a misconfigured bucket exposing customer export files before any breach occurred"
