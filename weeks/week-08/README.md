# Week 08 — Identity Review & Hardening Sprint

**Phase 2: Review & Consolidation | Project: Cross-project identity hardening**

---

## Learning Objectives

By the end of this week you will be able to:

- Consolidate findings from Weeks 5-7 into a professional security report
- Apply IAM hardening remediations across AWS and Azure
- Build and present an executive-level risk summary
- Conduct a structured Phase 2 mock interview
- Write professional security documentation that would be acceptable in a real enterprise engagement

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | Remediate top findings from your IAM analyser (Week 3) and escalation detector (Week 5) | 2 hrs |
| Tue | Apply GitHub hardening from Week 7 audit — fix branch protection, rotate any found secrets | 2 hrs |
| Wed | Write consolidated Identity Security Report (executive summary + technical findings) | 2 hrs |
| Thu | Build risk heat map and MITRE ATT&CK coverage visualization | 2 hrs |
| Fri | Mock interview prep — practice answering all Phase 2 interview questions | 2 hrs |
| Sat | Final polish on all Phase 2 projects, update all READMEs | 3 hrs |
| Sun | Mentor review and feedback session | 1 hr |

---

## Topics Covered

### Professional Security Report Writing

A security report has two audiences: **executives** (business impact, risk, cost to fix) and **engineers** (technical detail, steps to reproduce, exact remediation commands). You must serve both.

**Executive Summary** — 1 page maximum:
- Total risk score or posture rating
- Top 3 critical risks with business impact
- Recommended priority actions
- Resource and time estimates

**Technical Findings** — one card per finding:
```
Finding: Root Account Access Keys Exist
Severity: CRITICAL
CVSS Score: 9.8 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)
Description: The AWS root account has active programmatic access keys.
             If compromised, the attacker has unrestricted access to all resources.
Evidence: [screenshot or API output]
Business Impact: Total account compromise. Estimated data breach cost: $X.
Remediation: Delete root access keys via IAM console → Security Credentials.
             Use IAM users/roles for all automation.
Effort: 15 minutes (zero cost)
```

### Risk Heat Map Format

```
                LIKELIHOOD →
                Low    Medium   High
         High  [  ]    [  ]    [XX]   ← CRITICAL quadrant
IMPACT   Med   [  ]    [XX]    [XX]
         Low   [  ]    [XX]    [  ]
```

### IAM Hardening Remediations

**1. Enforce MFA for all console users**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyWithoutMFA",
    "Effect": "Deny",
    "NotAction": ["iam:GetVirtualMFADevice", "iam:EnableMFADevice",
                  "iam:ListMFADevices", "sts:GetSessionToken"],
    "Resource": "*",
    "Condition": {
      "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" }
    }
  }]
}
```

**2. Deny access outside approved regions**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyOutsideApprovedRegions",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:RequestedRegion": ["us-east-1", "us-west-2", "eu-west-1"]
      }
    }
  }]
}
```

**3. Require tag on resource creation (cost + security governance)**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "RequireOwnerTag",
    "Effect": "Deny",
    "Action": ["ec2:RunInstances", "s3:CreateBucket", "rds:CreateDBInstance"],
    "Resource": "*",
    "Condition": {
      "Null": { "aws:RequestTag/Owner": "true" }
    }
  }]
}
```

**4. Prevent leaving approved AWS accounts via STS**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyAssumeRoleToExternalAccounts",
    "Effect": "Deny",
    "Action": "sts:AssumeRole",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalAccount": ["111111111111", "222222222222"]
      }
    }
  }]
}
```

---

## Instructor Mentoring Guidance

**Week 8 is the Phase 2 synthesis week.** Students now have 4 projects worth of findings. The goal is consolidating that experience into a coherent security narrative — the skill that differentiates good engineers from great ones.

**Key coaching points:**
- Push students to be specific about business impact, not just technical severity. "Root key exists" is worse than "Root key exists — one leaked credential gives the attacker the ability to delete every resource, exfiltrate all data, and rack up $50k in compute charges."
- The mock interview this week should be 45 minutes, structured like a real interview: 5 minutes intro, 30 minutes technical questions, 10 minutes "do you have questions for us."
- Students who struggle to explain findings verbally need extra time — the ability to communicate findings clearly is as important as finding them.

**Mentoring session agenda (60 min):**
1. (10 min) Student presents their Identity Security Report (executive summary, 5 min max)
2. (15 min) Mock interview — Phase 2 technical questions (see below)
3. (25 min) Code review of all Phase 2 projects together — discuss portfolio presentation
4. (10 min) Feedback, gaps to fill, preview of Phase 3

**Phase 2 Mock Interview Questions:**
- "If I give you read-only access to an AWS account, how would you determine its security posture in one hour?"
- "Explain IAM permission boundaries to a developer who has never heard of them."
- "We found an access key that was used last night from a Romanian IP. Walk me through your incident response."
- "What is a supply chain attack and how would you defend a Python package from one?"
- "Write a KQL query that detects successful logins from countries the user has never logged in from before."

---

## Weekly Assignment — Consolidated Identity Security Report

Write a professional Identity Security Report covering all of Phase 2. This is a deliverable you could hand to a CISO.

### Report Structure

```markdown
# Identity Security Assessment Report
**Organization:** [Your test org]
**Assessment Period:** [Dates]
**Assessor:** [Your name]
**Confidentiality:** INTERNAL USE ONLY

---

## Executive Summary

Overall Risk Rating: CRITICAL / HIGH / MEDIUM

### Key Findings

| # | Finding | Severity | Effort to Fix |
|---|---------|----------|---------------|
| 1 | Root account access keys exist | CRITICAL | 15 min |
| 2 | 3 users without MFA | HIGH | 1 hour |
| 3 | AdministratorAccess on 2 users | HIGH | 2 hours |
| ... | | | |

### Risk Heat Map
[3x3 grid visualization]

### Business Impact Summary
[Paragraph: what is the worst-case scenario if these findings are exploited?]

---

## Scope

### What Was Assessed
- AWS IAM (Week 3 findings)
- IAM Privilege Escalation Paths (Week 5 findings)
- Azure Sentinel detections (Week 6 — rule coverage gaps)
- GitHub organization security (Week 7 findings)

### What Was NOT Assessed
- Network security (to be covered in Phase 3)
- Application-level access controls
- Data classification

---

## Detailed Findings

### Finding IAM-001: Root Account Access Keys
[Full technical finding card]

### Finding IAM-002: MFA Not Enforced
[Full technical finding card]

[... all findings from all tools ...]

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Covered by Detection? |
|--------|-----------|----------------------|
| Initial Access | T1078 Valid Accounts | ✓ Week 6 Rule 14 |
| Privilege Escalation | T1098 Account Manipulation | ✓ Week 5 Detector |
| ...

---

## Recommendations Priority Order

1. **Immediate (this week)** — Root key deletion, MFA enforcement
2. **Short-term (this month)** — Access key rotation, branch protection
3. **Long-term (this quarter)** — Service principal governance, JIT access

---

## Methodology

Tools used: AWS IAM Analyser, Privilege Escalation Detector, Azure Sentinel, GitHub Monitor
Standards referenced: CIS AWS Foundations Benchmark v2.0, NIST CSF, MITRE ATT&CK v14
```

---

## Portfolio Polish Checklist

Take this week to ensure all Phase 2 project repositories meet portfolio standards:

### README Quality Bar

Every project README must have:
- [ ] **One-paragraph elevator pitch** — what does this tool do and why does it matter?
- [ ] **Architecture diagram** — even a simple ASCII or draw.io diagram
- [ ] **Prerequisites** — exact Python version, required AWS permissions (IAM policy JSON)
- [ ] **Quick start** — copy-paste commands that work
- [ ] **Sample output** — screenshot or copy of terminal output
- [ ] **Security concepts demonstrated** — bullet list
- [ ] **MITRE ATT&CK coverage** — table with technique IDs
- [ ] **Known limitations** — honest about what it doesn't detect

### GitHub Repository Hygiene

```bash
# Check each Phase 2 repo for these issues:

# 1. No credentials in git history
git log --all -p | grep -E "(AKIA|aws_secret|password|token)" | grep -v "#"

# 2. .gitignore covers key files
cat .gitignore | grep -E "(.env|.aws|reports/|*.json)"

# 3. Requirements.txt is pinned
cat requirements.txt  # should show exact versions: boto3==1.34.0

# 4. Tests exist and pass
pytest --tb=short -q

# 5. No print(password) or debug output committed
grep -r "print.*key\|print.*secret\|print.*password" src/
```

---

## Interview Skills Gained

**Q: How do you prioritize security findings when you have limited time to fix them?**
> I use a risk matrix combining severity (CVSS-based) and exploitability. Critical + easy-to-exploit goes first. I also consider compensating controls — if a CRITICAL finding requires the attacker to already have network access we don't expose, it may drop in priority. I always escalate critical findings immediately regardless of remediation timeline.

**Q: Walk me through a security assessment methodology.**
> (1) Scope definition — what systems, what time period, what attack surface. (2) Asset discovery — enumerate what exists. (3) Vulnerability identification — run automated tools, manual analysis. (4) Finding validation — confirm exploitability, avoid false positives. (5) Risk rating — CVSS or organizational matrix. (6) Reporting — executive summary + technical detail. (7) Remediation validation — verify fixes actually work.

**Q: Explain the principle of defense in depth.**
> Defense in depth means layering multiple security controls so that if one fails, others still protect the asset. Example: a cloud account might have (1) network controls — VPC, NACLs, (2) identity controls — MFA, least privilege IAM, (3) data controls — S3 encryption, (4) detection — CloudTrail, GuardDuty, (5) response — automated isolation via Lambda. An attacker must bypass all layers.

---

## Submission Checklist

- [ ] Identity Security Report written and pushed to `reports/phase-2-identity-assessment.md`
- [ ] Report reviewed and approved by mentor in office hours
- [ ] All Phase 2 project READMEs meet portfolio quality bar
- [ ] No credentials in any git history (verified with `git log -p | grep AKIA`)
- [ ] All project requirements.txt files pinned to exact versions
- [ ] Mock interview completed with mentor feedback documented
- [ ] Phase 2 retrospective written: what was hardest? what would you do differently?

---

## Links

→ Phase 2 wrap-up
→ Next: [Week 09 — Automated Incident Response & SOAR](../week-09/README.md)
