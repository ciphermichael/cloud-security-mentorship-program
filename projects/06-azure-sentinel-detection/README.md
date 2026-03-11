# 🔵 Azure Sentinel Detection Engineering

> **Week 7** | Phase 2: IAM & Identity Security

20+ production-ready KQL detection rules covering the MITRE ATT&CK for Cloud framework.

## How to Deploy Rules
1. Azure Portal → Microsoft Sentinel → Analytics
2. Create → Scheduled Query Rule
3. Paste KQL from `detection_rules/` or `shared/detection-queries/kql/`
4. Set: Alert threshold, Severity, MITRE technique mapping
5. Enable alert enrichment and automated response

## Detection Rules Included
| Category | Rules | Techniques |
|----------|-------|-----------|
| Identity & Access | Impossible Travel, Brute Force, MFA Bypass | T1078, T1110 |
| Persistence | Privileged Role Assignment, SP Credential Mod | T1098.003 |
| Exfiltration | Mass SharePoint Download, Bulk File Access | T1530 |
| Defence Evasion | Anonymous IP Sign-In, After-Hours Access | T1090 |
| Lateral Movement | New Admin User Fast Escalation | T1078.004 |

## KQL Query Library
See `../../shared/detection-queries/kql/sentinel_detection_rules.kql` for all 10 full KQL rules.

## Interview Talking Points
- "I wrote a KQL impossible-travel detection using geo_distance_2points() that catches account compromise within seconds"
- "The rule correlated two successful sign-ins from locations requiring >900 km/h travel speed"
