# Week 20 — Career Prep, Portfolio Polish & Job Strategy

**Phase 5: Advanced Topics | Cross-project portfolio review**

---

## Learning Objectives

By the end of this week you will be able to:

- Present any of your 15+ GitHub projects confidently in a technical interview
- Write STAR-format answers for behavioral cloud security interview questions
- Build a cloud security-focused CV and LinkedIn profile that passes recruiter screening
- Articulate your professional story: "I'm a cloud security engineer who can..."
- Apply strategically to 10 target companies with personalized applications
- Pass a Phase 5 comprehensive mock interview covering all program topics

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | Portfolio audit — every project must meet the quality bar (see checklist) | 3 hrs |
| Tue | CV and LinkedIn optimization for cloud security roles | 2 hrs |
| Wed | STAR-format answer writing — 10 behavioral questions | 2 hrs |
| Thu | Technical interview prep — live coding in security context | 2 hrs |
| Fri | Mock full interview with mentor (90 minutes) | 2 hrs |
| Sat | Apply to 10 target roles with tailored cover notes | 3 hrs |
| Sun | Debrief with mentor — feedback, gaps, capstone preview | 1 hr |

---

## Portfolio Quality Bar

Every project repository must have:

### README Structure (Required)

```markdown
# [Project Name] — [One-line description]

## What This Solves
[One paragraph: the security problem this addresses and why it matters]

## Architecture
[Diagram here — minimum ASCII art, ideally draw.io or Lucidchart]

## Security Concepts Demonstrated
- IAM privilege escalation detection (MITRE T1098)
- Real-time EventBridge → Lambda alerting
- CloudTrail forensic investigation
[3-5 bullets, each citing a real security concept or MITRE technique]

## Quick Start
```bash
pip install -r requirements.txt
export AWS_PROFILE=security-sandbox
python src/analyser.py --region us-east-1
```

## Sample Output
[Screenshot or terminal output showing real results]

## Detection Queries
[Link to your query library or embed key queries inline]

## Interview Talking Points
- What was the hardest problem you solved?
- What would you do differently?
- What did you learn?
```

### GitHub Repository Hygiene Checklist

```bash
# Run this against each project repo before applying for jobs

# 1. No secrets in history
git log --all -p | grep -Ei "(AKIA|api_key|password\s*=|secret\s*=)" | head -20

# 2. .gitignore is complete
cat .gitignore

# 3. Requirements pinned
cat requirements.txt | grep -v "==" | head -10  # Should return nothing

# 4. Tests exist
ls tests/

# 5. No debug/print statements with sensitive data
grep -rn "print.*key\|print.*secret\|print.*password\|print.*token" src/

# 6. License exists
ls LICENSE

# 7. Contributing guide (optional but impressive)
ls CONTRIBUTING.md
```

---

## CV & LinkedIn Guide

### CV Structure for Cloud Security Engineers

```
[Name] — Cloud Security Engineer
[Email] | [GitHub: github.com/yourhandle] | [LinkedIn] | [Location]

PROFESSIONAL SUMMARY (3 sentences)
Cloud Security Engineer with hands-on experience in AWS/Azure security, 
threat detection engineering, and DevSecOps automation. Built 15+ 
open-source security tools covering IAM analysis, CloudTrail forensics, 
container security, and SOAR playbooks. Passionate about detection 
engineering and building security that scales.

TECHNICAL SKILLS
Cloud: AWS (Security Hub, GuardDuty, CloudTrail, IAM, Lambda, Step Functions)
       Azure (Sentinel, Defender for Cloud, Entra ID, KQL)
Detection: CloudWatch Insights, Athena SQL, KQL, Splunk SPL
Security Tools: Falco, Trivy, Checkov, Semgrep, Gitleaks, OWASP ZAP
Languages: Python (boto3, pandas), Bash, HCL (Terraform)
Frameworks: MITRE ATT&CK, CIS Benchmarks, NIST CSF, ISO 27001

PROJECTS (6 strongest — link to GitHub)
IAM Privilege Escalation Detector
→ Python/Lambda tool detecting 15 IAM escalation paths in real time
→ EventBridge → Lambda → SNS pipeline with full MITRE ATT&CK mapping
→ github.com/yourhandle/iam-privilege-escalation-detector

[5 more projects...]

CERTIFICATIONS (if any)
AWS Security Specialty | AWS Solutions Architect Associate | CompTIA Security+

EDUCATION
[Your education — even a bootcamp or self-study is fine with the project portfolio]
```

### LinkedIn Profile Optimization

**Headline:** `Cloud Security Engineer | AWS Security | Threat Detection | DevSecOps`

**About section:** "I build security tools that protect cloud infrastructure. Over the last 6 months I've built 15 open-source projects covering IAM security analysis, CloudTrail threat hunting, Azure Sentinel detection engineering, Kubernetes security, and automated incident response. I'm looking for a cloud security engineer role where I can help a team detect and respond to threats at scale."

**Featured section:** Pin your 3 best GitHub project READMEs or screenshots.

---

## STAR-Format Behavioral Questions

Write a 2-3 minute answer for each using STAR (Situation, Task, Action, Result):

**1. Tell me about a security problem you discovered and how you fixed it.**
> (Use your IAM analyser finding root keys or open security groups)

**2. Describe a time you automated a security process.**
> (Use your SOAR playbook or CI/CD security pipeline)

**3. How do you stay current with cloud security threats?**
> (Follow CISA alerts, AWS Security Blog, MITRE ATT&CK, Krebs, Dark Reading)

**4. Tell me about a time you had to explain a security risk to a non-technical stakeholder.**
> (Use your compliance report or executive incident summary)

**5. How do you prioritize when you have multiple security issues to address?**
> (Risk matrix: severity × exploitability × asset criticality)

---

## Technical Interview Preparation

### Rapid-fire Q&A Bank (Know These Cold)

**IAM & Identity:**
- Name 5 IAM privilege escalation paths
- What is a permission boundary?
- Explain `iam:PassRole`
- How do you enforce MFA without locking users out?

**Logging & Detection:**
- What's the delay between an AWS API call and its CloudTrail appearance?
- What's the difference between CloudTrail management events and data events?
- Write a KQL query detecting impossible travel login
- Write an Athena query finding mass S3 downloads

**Incident Response:**
- Walk me through responding to a compromised EC2 instance
- Why shouldn't you terminate a compromised instance immediately?
- What does MTTD and MTTR mean?

**Container/K8s Security:**
- What is a privileged container and why is it dangerous?
- How does OPA Gatekeeper work?
- What is the Docker socket mount attack?

**Compliance:**
- What is CIS Benchmark Level 1 vs Level 2?
- How does SOC 2 differ from ISO 27001?
- What is a conformance pack in AWS Config?

**Zero Trust:**
- Explain the 3 pillars of Zero Trust
- What is mTLS and when do you use it?
- How does Zero Trust differ from VPN?

---

## Target Company Research

### Job Title Variations to Search

```
"Cloud Security Engineer"
"AWS Security Engineer"
"Azure Security Engineer"
"Detection Engineer"
"Security Detection Engineer"
"Cloud Security Analyst"
"DevSecOps Engineer"
"Platform Security Engineer"
"Infrastructure Security Engineer"
"SOC Engineer Cloud"
```

### Where to Apply

- **Direct:** Company careers pages (AWS, Google, Microsoft, Meta, Cloudflare, Datadog, Palo Alto Networks, CrowdStrike)
- **Job Boards:** LinkedIn Easy Apply, Indeed, Glassdoor, Wellfound (startups), Dice (tech focused)
- **Security-Specific:** jobs.infosec.exchange (Mastodon), ISACA job board, (ISC)² jobs
- **Recruiters:** Message security-focused recruiters on LinkedIn — tell them your stack

### Application Personalization Template

```
Subject: Cloud Security Engineer Application — [Company Name]

Hi [Recruiter Name],

I'm applying for the Cloud Security Engineer role. I've spent the last 
6 months building cloud security tools from scratch:

• IAM Privilege Escalation Detector — catches 15 attack paths in real time 
  via EventBridge → Lambda [github.com/...]
• CloudTrail Threat Hunting Lab — Athena SQL hunting queries with Python 
  orchestration [github.com/...]
• Azure Sentinel Detection Engineering — 20+ KQL rules with MITRE ATT&CK 
  mapping [github.com/...]

I noticed [Company] uses [specific technology from their job posting] — 
I've built [related project] and would love to bring that experience to 
your team.

Portfolio: github.com/yourhandle
Available for a call: [your availability]

[Your Name]
```

---

## Mock Interview Format (90 Minutes)

Week 20's mentor session is a full mock interview:

**0:00 — 5:00** — Introduction: "Tell me about yourself and your background"
**5:00 — 25:00** — Technical Q&A (rapid fire from the bank above)
**25:00 — 45:00** — Live problem: "Write an Athena query to detect privilege escalation"
**45:00 — 60:00** — System design: "Design a threat detection system for a 50-account AWS org"
**60:00 — 75:00** — Behavioral questions (2 STAR stories)
**75:00 — 85:00** — Portfolio walkthrough (present 2 projects in 5 min each)
**85:00 — 90:00** — "Do you have questions for us?" (always have 3 good questions)

**Good questions to ask:**
- "What does your detection engineering backlog look like? How do you prioritize new rules?"
- "What cloud security incident is keeping your team busiest right now?"
- "How does the security team work with the development teams — embedded or centralized?"

---

## Submission Checklist

- [ ] All 15+ project READMEs meet the quality bar (see checklist above)
- [ ] No credentials in any git history (final check)
- [ ] CV completed with 6 project highlights and technical skills table
- [ ] LinkedIn profile updated with About section and Featured projects
- [ ] 10 STAR answers written and practiced aloud
- [ ] 10 job applications submitted with personalized cover notes
- [ ] Mock interview completed with mentor feedback documented
- [ ] GitHub profile README created (optional but impressive — `github.com/yourhandle`)

---

## Links

→ Next: [Week 21 — Capstone Architecture Design](../week-21/README.md)
