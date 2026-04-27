# Cloud Security Mentorship Program — Complete 6-Month Curriculum

> A structured 24-week program taking beginners from basic cloud knowledge to job-ready Cloud Security Engineers. Built around hands-on projects that become a professional GitHub portfolio.

---

## Program Overview

| Attribute | Detail |
|-----------|--------|
| **Duration** | 24 weeks (6 months) |
| **Format** | Weekly sessions + daily study (13 hrs/week average) |
| **Projects** | 20 GitHub portfolio projects |
| **Detection Queries** | 50+ across KQL, Athena SQL, CloudWatch Insights, Splunk SPL |
| **Target Roles** | Cloud Security Engineer, Detection Engineer, DevSecOps Engineer |
| **Prerequisites** | Basic Linux, networking, cloud (AWS or Azure), Python or Bash |

---

## How Mentoring Works

### Weekly Session Format

| Session Type | Duration | Frequency | Purpose |
|-------------|----------|-----------|---------|
| Learning Session | 2 hrs | Weekly (Mon) | Core concept delivery, live demo |
| Office Hours | 1 hr | Weekly (Wed) | Unblock students, pair debugging |
| Code Review | 1 hr | Weekly (Fri) | GitHub PR review with line-level feedback |
| Mock Interview | 1 hr | Biweekly | Progressive technical interview prep |

### Student Daily Schedule (Recommended)

```
Monday:    2-3 hrs — Learning session + concept reading
Tuesday:   2 hrs   — Hands-on labs from week guide
Wednesday: 2 hrs   — Start weekly project assignment + office hours
Thursday:  2 hrs   — Continue project build
Friday:    2 hrs   — Complete assignment + code review with mentor
Saturday:  3 hrs   — Polish, document, push to GitHub
Sunday:    1 hr    — Reflection + preview next week's reading
```

---

## GitHub Portfolio Strategy

### Profile Setup

1. **GitHub Profile README** (`github.com/USERNAME`) — create a profile README that serves as your landing page. Include your tech stack, 3-5 pinned projects, and contact information.

2. **Repository naming** — use kebab-case: `iam-privilege-escalation-detector`, `cloudtrail-threat-hunting-lab`.

3. **Commit message discipline** — use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`. Every commit message must explain WHY, not just what.

4. **Branch strategy** — work on feature branches, open PRs against main, get mentor review before merging. This builds a visible pull request history that demonstrates professional development workflow.

### README Quality Standards

Every project README must include:

```markdown
# [Project Name] — [One-line description]
## What This Solves (the security problem)
## Architecture (diagram)
## Security Concepts Demonstrated (MITRE TTPs, security controls)
## Quick Start (copy-paste commands that work)
## Sample Output (screenshot or terminal output)
## Detection Queries (if applicable)
## Interview Talking Points
```

### Professional Security Documentation

**Architecture diagrams:** Use draw.io (app.diagrams.net, free) or Excalidraw. Commit as both PNG (for rendering) and SVG or XML source (so it can be edited).

**Threat models:** Use STRIDE or the MITRE ATT&CK framework to document the threats your tool addresses.

**Findings reports:** Generate JSON with structured severity levels (CRITICAL/HIGH/MEDIUM/LOW). Include remediation steps, not just findings.

---

## Phase Breakdown & Learning Objectives

### Phase 1: Foundations (Weeks 1-4)
**Goal:** Build a secure AWS account from scratch. Understand the three pillars of cloud security: identity, logging, and network.

| Week | Title | Project | Key Skill |
|------|-------|---------|-----------|
| 1 | VPC Networking & Security Groups | Network Security Auditor | boto3, VPC security model |
| 2 | S3 Security & Encryption | Storage Security Scanner | S3 policy analysis, PII detection |
| 3 | IAM Fundamentals & Security Analysis | IAM Security Analyser | Credential report, over-privilege detection |
| 4 | CloudTrail & Logging Architecture | Foundation for Threat Hunting | Athena SQL, CloudWatch Insights |

**Phase 1 interview readiness:** By end of Phase 1, students can answer all Level 1 cloud security interview questions about IAM, S3, VPC, and logging.

---

### Phase 2: Identity & Detection (Weeks 5-8)
**Goal:** Understand identity-based attacks and build detection capabilities. Master MITRE ATT&CK mapping.

| Week | Title | Project | Key Skill |
|------|-------|---------|-----------|
| 5 | IAM Privilege Escalation — 15 Attack Paths | IAM Priv Esc Detector | EventBridge Lambda alerting, MITRE T1098 |
| 6 | Azure Sentinel & KQL Detection Engineering | Sentinel Detection Project | KQL, analytics rules, MITRE mapping |
| 7 | GitHub Supply Chain Security | GitHub Security Monitor | GitHub API, audit log analysis |
| 8 | Identity Review & Hardening Sprint | Cross-project | Security report writing, mock interview |

**Phase 2 interview readiness:** Students can explain all 15 IAM escalation paths, write KQL from scratch, and describe supply chain attack vectors.

---

### Phase 3: Threat Detection & Response (Weeks 9-12)
**Goal:** Build SOAR automation and extend security controls to containers and Kubernetes.

| Week | Title | Project | Key Skill |
|------|-------|---------|-----------|
| 9 | Automated Incident Response & SOAR | SOAR Playbooks | Step Functions, Lambda SOAR, MTTD/MTTR |
| 10 | Cloud Compliance: CIS, ISO 27001, SOC 2 | Compliance Audit Tool | CIS checks, AWS Config, evidence packages |
| 11 | Container Security: Docker & Falco | Container Security Framework | Trivy, Falco rules, CIS Docker Benchmark |
| 12 | Kubernetes Security: RBAC, OPA, Network Policies | K8s Threat Detection | kube-bench, OPA Gatekeeper, Network Policies |

**Phase 3 interview readiness:** Students can design an incident response playbook, explain compliance frameworks, and articulate container escape attack paths.

---

### Phase 4: DevSecOps & Automation (Weeks 13-16)
**Goal:** Integrate security into the software delivery lifecycle. Build CSPM and UEBA capabilities.

| Week | Title | Project | Key Skill |
|------|-------|---------|-----------|
| 13 | DevSecOps CI/CD Security Pipelines | DevSecOps Pipeline | 7-stage pipeline, SAST/DAST/SCA, SBOM |
| 14 | Infrastructure as Code Security | IaC Security (Checkov) | Terraform scanning, custom Checkov checks |
| 15 | CSPM & Multi-Cloud Dashboard | Multi-Cloud Dashboard | Streamlit, Security Hub API, risk scoring |
| 16 | UEBA & Insider Threat Detection | Insider Threat UEBA | Statistical baselines, anomaly detection |

**Phase 4 interview readiness:** Students can explain DevSecOps principles, demonstrate IaC security tooling, and describe UEBA detection methodology.

---

### Phase 5: Advanced Topics (Weeks 17-20)
**Goal:** Master advanced security architecture patterns and prepare a job-ready portfolio.

| Week | Title | Project | Key Skill |
|------|-------|---------|-----------|
| 17 | Zero Trust Architecture | Zero Trust Implementation | NIST 800-207, mTLS, Verified Access |
| 18 | Cloud Forensics & Digital Investigations | Forensics Timeline Builder | NIST IR lifecycle, evidence chain of custody |
| 19 | Threat Intelligence & CTI Integration | CTI Enrichment Pipeline | IOC enrichment, MITRE Diamond Model |
| 20 | Career Prep & Portfolio Polish | All projects | CV, LinkedIn, mock interviews, job applications |

**Phase 5 interview readiness:** Students can design Zero Trust architectures, conduct cloud forensic investigations, and articulate CTI frameworks.

---

### Phase 6: Capstone (Weeks 21-24)
**Goal:** Build a complete, production-grade Cloud Security Operations Platform integrating all program skills.

| Week | Title | Deliverable |
|------|-------|-------------|
| 21 | Architecture Design & Planning | Architecture document, STRIDE model, sprint plan |
| 22 | Core Platform Build (Sprint 1) | Detection engine + DynamoDB + Streamlit dashboard live |
| 23 | Integration, Testing & Hardening (Sprint 2) | All integrations + 70% test coverage + load test |
| 24 | Presentation, Deployment & Graduation | Live platform + Loom video + blog post + cohort presentation |

---

## Detection Query Library

### KQL (Azure Sentinel / Microsoft Defender)

```kql
// Impossible travel login
SigninLogs
| where TimeGenerated > ago(24h) and ResultType == "0"
| project UserPrincipalName, TimeGenerated,
    Country = tostring(LocationDetails.countryOrRegion),
    Lat = todouble(LocationDetails.geoCoordinates.latitude),
    Lon = todouble(LocationDetails.geoCoordinates.longitude), IPAddress
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevUser=prev(UserPrincipalName), PrevTime=prev(TimeGenerated),
    PrevCountry=prev(Country), PrevLat=prev(Lat), PrevLon=prev(Lon)
| where UserPrincipalName == PrevUser and PrevCountry != Country
| extend TimeDiffH = datetime_diff('minute', TimeGenerated, PrevTime)/60.0,
    DistKm = geo_distance_2points(Lon, Lat, PrevLon, PrevLat)/1000.0
| extend SpeedKmH = DistKm / max_of(TimeDiffH, 0.001)
| where SpeedKmH > 800 and DistKm > 100
| project UserPrincipalName, Country, PrevCountry, DistKm, SpeedKmH, IPAddress
```

```kql
// MFA fatigue attack detection
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("50074", "50076", "500121")
| summarize MFA_Challenges=count(), IPs=make_set(IPAddress)
  by UserPrincipalName
| where MFA_Challenges >= 10
| project UserPrincipalName, MFA_Challenges, IPs
```

```kql
// Password spray (many users, few attempts each)
SigninLogs
| where TimeGenerated > ago(1h) and ResultType != "0"
| summarize Attempts=count(), Users=dcount(UserPrincipalName)
  by IPAddress
| where Users >= 20 and (Attempts/Users) <= 3
| project IPAddress, Users, Attempts
| order by Users desc
```

### CloudWatch Logs Insights

```
# Root account usage
fields @timestamp, eventName, sourceIPAddress
| filter userIdentity.type = "Root"
| sort @timestamp desc
| limit 50
```

```
# Brute force: 5+ failed auth from same IP
fields @timestamp, sourceIPAddress, userIdentity.userName, errorCode
| filter errorCode in ["AccessDenied","AuthFailure","InvalidClientTokenId"]
| stats count() as failures by sourceIPAddress, userIdentity.userName
| filter failures >= 5
| sort failures desc
```

```
# CloudTrail tampering
fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter eventName in ["StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors"]
| sort @timestamp desc
```

### Athena SQL (CloudTrail)

```sql
-- IAM escalation events (last 7 days)
SELECT eventTime, eventName, userIdentity.arn AS actor, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName IN (
    'CreatePolicyVersion','SetDefaultPolicyVersion','UpdateAssumeRolePolicy',
    'AttachUserPolicy','AttachRolePolicy','PutUserPolicy','PutRolePolicy',
    'AddUserToGroup','CreateAccessKey','CreateLoginProfile','UpdateLoginProfile'
)
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC;
```

```sql
-- S3 mass download (exfiltration indicator)
SELECT userIdentity.arn, sourceIPAddress, count(*) AS downloads,
    date_trunc('hour', from_iso8601_timestamp(eventTime)) AS hour
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com' AND eventName = 'GetObject'
  AND eventTime > date_format(date_add('day', -1, now()), '%Y-%m-%dT%H:%i:%sZ')
GROUP BY 1, 2, 4
HAVING count(*) > 100
ORDER BY downloads DESC;
```

```sql
-- Impossible travel: same user, 2 source IPs within 1 hour
WITH logins AS (
    SELECT userIdentity.userName AS user,
        sourceIPAddress AS ip,
        from_iso8601_timestamp(eventTime) AS ts
    FROM cloudtrail_logs
    WHERE eventName = 'ConsoleLogin'
      AND responseElements LIKE '%Success%'
)
SELECT a.user, a.ip AS ip1, b.ip AS ip2,
    date_diff('minute', a.ts, b.ts) AS minutes
FROM logins a JOIN logins b
    ON a.user = b.user AND a.ip != b.ip
    AND abs(date_diff('minute', a.ts, b.ts)) < 60
ORDER BY minutes ASC;
```

### Splunk SPL

```
index=cloudtrail sourcetype=aws:cloudtrail
| eval is_escalation=case(
    eventName="CreatePolicyVersion", "true",
    eventName="UpdateAssumeRolePolicy", "true",
    eventName="AttachUserPolicy", "true",
    1==1, "false"
)
| where is_escalation="true"
| table _time, eventName, userIdentity.arn, sourceIPAddress
| sort -_time
```

```
index=aws_guardduty type="UnauthorizedAccess:IAMUser/*"
| rex field=description "IP Address: (?<src_ip>[0-9.]+)"
| lookup threat_intel ip AS src_ip OUTPUT threat_actor, malware_family
| table _time, type, src_ip, threat_actor, malware_family, severity
| sort -severity
```

---

## Complete Project List (20 Projects)

| # | Project | Core Technology | MITRE Coverage | Interview Value |
|---|---------|----------------|----------------|----------------|
| 01 | Network Security Auditor | boto3, Python | T1590 | HIGH |
| 02 | Storage Security Scanner | boto3, regex | T1530 | HIGH |
| 03 | IAM Security Analyser | boto3, IAM credential report | T1098 | CRITICAL |
| 04 | IAM Privilege Escalation Detector | EventBridge, Lambda | T1098.003 | CRITICAL |
| 05 | CloudTrail Threat Hunting Lab | Athena SQL, Python | T1078, T1530 | CRITICAL |
| 06 | Azure Sentinel Detection Engineering | KQL, Sentinel | Multiple | CRITICAL |
| 07 | GitHub Security Monitoring | GitHub API, Python | T1195 | HIGH |
| 08 | Automated Incident Response | Step Functions, Lambda | NIST IR | CRITICAL |
| 09 | Cloud Compliance Audit Tool | AWS Config, Python | CIS Benchmark | HIGH |
| 10 | Container Security Framework | Docker, Falco, Trivy | T1610, T1611 | HIGH |
| 11 | Kubernetes Threat Detection | K8s, OPA, Falco | T1610, T1613 | HIGH |
| 12 | DevSecOps Pipeline | GitHub Actions, Semgrep | OWASP Top 10 | CRITICAL |
| 13 | Multi-Cloud Dashboard | Streamlit, Security Hub | CSPM | HIGH |
| 14 | Insider Threat Detection | Python, pandas, statistics | T1078 | HIGH |
| 15 | Capstone: Cloud SecOps Platform | All technologies | Full ATT&CK | CRITICAL |
| 16 | Cloud WAF Security Monitor | WAF, Lambda | T1190 | MEDIUM |
| 17 | Secrets Management with Vault | Vault, Terraform | T1552 | HIGH |
| 18 | Cloud Forensics Timeline | Python, Athena | NIST IR | HIGH |
| 19 | Zero Trust Implementation | Verified Access, mTLS | T1078 | HIGH |
| 20 | Cloud Security Posture Scoring | Security Hub, Python | CSPM | MEDIUM |

---

## Interview Preparation — Complete Q&A Bank

### Identity & Access Management

**Q: Explain the difference between an IAM role and a user.**
A: A user has permanent credentials (password + access keys). A role has no credentials — it issues temporary STS tokens when assumed. Roles are preferred for services, automation, and cross-account access because temporary credentials expire automatically and reduce breach impact.

**Q: What is the most dangerous IAM permission?**
A: `iam:PassRole` combined with a service creation permission (like `ec2:RunInstances` or `lambda:CreateFunction`). This allows passing an admin IAM role to a service you create, effectively escalating to admin without directly assuming the role.

**Q: Name 5 IAM privilege escalation paths.**
A: (1) `CreatePolicyVersion` + `SetDefaultPolicyVersion` — create an admin version of an existing policy; (2) `UpdateAssumeRolePolicy` — add your identity to a high-privilege role's trust policy; (3) `iam:PassRole` + `RunInstances` — pass admin role to an EC2 instance; (4) `CreateAccessKey` on another user — create keys for an existing admin; (5) `AttachUserPolicy` — attach AdministratorAccess to your own user.

### Logging & Detection

**Q: What is the difference between CloudTrail management and data events?**
A: Management events record control plane operations — creating resources, modifying configurations. Data events record data plane access — reading/writing objects within resources (S3 GetObject, Lambda Invoke). Data events are off by default and cost extra but are essential for breach investigation.

**Q: How would you detect a compromised AWS access key?**
A: Look in CloudTrail for: API calls from unusual IP geolocation or ASN, calls outside business hours, new IAM entities created, access to resources never previously touched, GuardDuty findings like `InstanceCredentialExfiltration`. Correlate with the IAM user's normal behaviour baseline.

**Q: Write a KQL query to detect MFA fatigue attacks.**
A: Query `AADNonInteractiveUserSignInLogs` for result codes 50074/50076 (MFA challenge), group by user, alert when count exceeds threshold in a 1-hour window.

### Incident Response

**Q: Walk me through responding to a compromised EC2 instance.**
A: (1) Preserve evidence — take EBS snapshot before any changes. (2) Isolate — replace security groups with deny-all SG. Do NOT terminate. (3) Collect — Systems Manager memory artifacts, instance metadata service call history from VPC flow logs. (4) Investigate — CloudTrail timeline for the instance role's credentials. (5) Determine root cause — how did attacker get initial access? (6) Eradicate — patch vulnerability, rotate credentials. (7) Recover — build clean replacement. (8) Report.

**Q: What is MTTD and MTTR and what are good targets?**
A: MTTD (Mean Time to Detect) — time from incident start to alert firing. Target <15 minutes for high-severity cloud incidents. MTTR (Mean Time to Respond) — time from alert to containment. Target <60 minutes. These are the primary operational metrics for a cloud security team.

### Container & Kubernetes

**Q: What is a container escape and how do you prevent it?**
A: A container escape occurs when an attacker inside a container gains access to the host OS. Vectors: privileged containers, Docker socket mount, kernel CVEs. Prevention: never `--privileged`, never mount Docker socket, use read-only root filesystem, drop all capabilities, keep kernel patched.

**Q: How does OPA Gatekeeper work?**
A: Gatekeeper is a Kubernetes admission controller webhook. When a resource is created/modified, the API server calls Gatekeeper before admitting it. Gatekeeper evaluates the resource against Rego policies. If a violation is found, the request is rejected with a descriptive error.

### DevSecOps

**Q: What is SAST and how does it differ from DAST?**
A: SAST (Static) analyzes source code without execution — catches issues like SQL injection at development time. DAST (Dynamic) tests a running application by sending payloads — finds runtime vulnerabilities SAST misses. Both are needed; SAST runs in the CI pipeline, DAST runs against a deployed test environment.

**Q: How do you handle a Checkov false positive?**
A: Add a suppression inline: `#checkov:skip=CKV_AWS_24: Reason`. Document the business justification. Create a ticket for periodic review. Never suppress without documentation — it creates an invisible risk register entry.

### Compliance

**Q: What is the CIS AWS Foundations Benchmark?**
A: A prescriptive set of security configuration recommendations for AWS accounts, organized in sections: IAM (21 controls), Logging (8), Monitoring (15), Networking (4), Storage (7). Level 1 is baseline security, Level 2 is more restrictive. Widely used as an AWS account hardening baseline.

**Q: How do you get an AWS account SOC 2 ready?**
A: (1) Map Trust Service Criteria to AWS controls. (2) Enable core services: CloudTrail, Config, GuardDuty, Security Hub. (3) Implement CIS Benchmark Level 1. (4) Set up continuous compliance monitoring with conformance packs. (5) Document change management and access review procedures. (6) Engage auditor early — understand their evidence requirements.

### Architecture

**Q: What is Zero Trust and how does it differ from a VPN?**
A: Zero Trust means "never trust, always verify" — every access decision is made based on identity, device health, and context, not network location. VPN grants network-level access — once connected, you can reach any internal resource. Zero Trust grants application-level access per session. Far more granular, auditable, and resistant to lateral movement.

---

## Recommended Resources

### Free Learning

| Resource | URL | Best For |
|----------|-----|---------|
| AWS Security Documentation | docs.aws.amazon.com/security | Deep dives on specific services |
| Azure Security Documentation | docs.microsoft.com/security | Azure security reference |
| MITRE ATT&CK Cloud | attack.mitre.org/matrices/enterprise/cloud | Attack technique reference |
| Rhino Security Labs Blog | rhinosecuritylabs.com/blog | IAM escalation paths |
| CloudGoat (lab environment) | github.com/RhinoSecurityLabs/cloudgoat | Hands-on AWS attack practice |
| flaws.cloud | flaws.cloud | Free AWS security challenges |
| KQL Tutorial | learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference | KQL fundamentals |
| Falco Rules | falco.org/docs/rules | Falco rule writing |

### Key Books

- "Hacking the Cloud" (online reference: hackingthe.cloud)
- "AWS Security Cookbook" — Heartin Kanikathottu
- "Container Security" — Liz Rice (O'Reilly)
- "The Practice of Cloud System Administration" — Limoncelli, Chalup, Hogan

### YouTube Channels

- fwd:cloudsec (cloud security conference talks)
- SANS Institute (security training)
- NetworkChuck (approachable cloud content)
- TechWorld with Nana (Kubernetes and DevOps)

---

## Mentor Notes — How to Run This Program

### Student Selection Criteria

Ideal students have:
- 6+ months hands-on Linux experience (can navigate, script, troubleshoot)
- Basic understanding of HTTP, TCP/IP, DNS
- Have deployed at least one resource in AWS or Azure
- Can write a Python function (not necessarily OOP)

Do NOT require:
- Prior security experience
- CS degree
- Certifications

### Weekly Mentoring Cadence

**Monday — Learning Session (2 hrs):**
Live session. Start with 10-min review of last week's project (student demos). Teach core concepts with live demos in AWS console or terminal. Assign the week's lab. Set office hours time for Wednesday.

**Wednesday — Office Hours (1 hr):**
Async or sync. Students come with blockers. Focus: debugging, architecture questions, tool issues. Do NOT give the answer directly — ask questions that lead them to the answer.

**Friday — Code Review (1 hr):**
Student opens a PR to their own repo. Review it together. Comment on: security of the code itself (are they handling credentials correctly?), code quality (pagination, error handling), documentation quality. Approve and merge together.

**Biweekly — Mock Interview (1 hr):**
Structure: 5 min intro, 30 min technical Qs (from the Q&A bank), 15 min live problem (write a query, design a component), 10 min behavioral, 10 min feedback. Score and track improvement over time.

### Common Student Blockers

**Week 1-2:** AWS credential configuration, IAM permission for boto3 calls
→ Solution: Create a dedicated IAM user with `SecurityAudit` managed policy for sandbox use

**Week 4:** Athena SerDe configuration for CloudTrail
→ Solution: Use the official AWS CloudTrail table template — don't write from scratch

**Week 5:** EventBridge pattern matching for IAM events
→ Solution: CloudTrail events have a specific structure — reference the AWS documentation for the exact field paths

**Week 6:** Azure free trial expiry or Sentinel cost concerns
→ Solution: Microsoft offers $200 credit + free trial; Log Analytics workspace has free tier for 5 GB/month

**Week 9:** Step Functions state machine debugging
→ Solution: Use the Step Functions console visual workflow — it shows exactly which state failed and with what input

**Week 22+:** Capstone scope creep
→ Solution: Enforce the sprint plan strictly. "Scope creep is the enemy of shipped software." Cut features before cutting quality.

---

## Program Metrics — What Success Looks Like

By Week 24, a successful student should have:

| Metric | Target |
|--------|--------|
| GitHub projects | 15-20 with polished READMEs |
| GitHub commit streak | Active commits throughout the 6 months |
| Detection queries written | 50+ across all tools |
| Job applications sent | 10+ by Week 24 |
| Mock interview pass rate | Able to answer 80% of Q&A bank questions |
| Capstone completion | Live platform deployed with demo video |
| Time to first interview | Within 30 days of program completion |
| Time to first offer | Within 90 days (based on cohort data) |

---

## Changelog

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2024-01 | Initial 15-project, 24-week curriculum |
| 2.0 | 2024-07 | Added 5 new projects (16-20), expanded week guides |
| 3.0 | 2025-04 | Full rewrite of all 24 week guides with complete code, queries, interview prep |
