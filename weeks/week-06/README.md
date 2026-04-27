# Week 06 — Azure Sentinel & KQL Detection Engineering

**Phase 2: Identity Security | Project: 06-azure-sentinel-detection**

---

## Learning Objectives

By the end of this week you will be able to:

- Understand Microsoft Sentinel's architecture: workspace, connectors, analytics rules, incidents
- Write KQL (Kusto Query Language) queries for security analysis in Log Analytics / Sentinel
- Create scheduled analytics rules with MITRE ATT&CK mappings and alert logic
- Detect Azure AD/Entra ID identity threats: impossible travel, MFA fatigue, stale service principals
- Understand the difference between Sentinel query types: Scheduled, NRT, Fusion, ML Behavior Analytics
- Build a library of 20+ production-grade KQL detection rules

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | Azure AD/Entra ID fundamentals — tenants, users, service principals, conditional access | 2 hrs |
| Tue | Microsoft Sentinel architecture — workspace, data connectors, tables, UEBA | 2 hrs |
| Wed | KQL foundations — where, project, summarize, join, make-series, extend | 2 hrs |
| Thu | Write 10 analytics rules covering identity and access threats | 2 hrs |
| Fri | Write 10 more rules: data exfiltration, persistence, lateral movement | 2 hrs |
| Sat | Build rules as ARM templates / Bicep, push to GitHub | 3 hrs |
| Sun | Mentor review of KQL rules, interview prep | 1 hr |

---

## Topics Covered

### Azure AD / Entra ID Security Model

**Key tables in Sentinel:**

| Table | What's In It |
|-------|-------------|
| `SigninLogs` | Interactive sign-ins — user logins to apps |
| `AADNonInteractiveUserSignInLogs` | Token refreshes, background auth |
| `AuditLogs` | Directory changes: user creation, role assignment, group changes |
| `AADServicePrincipalSignInLogs` | App-to-app auth via service principals |
| `BehaviorAnalytics` | UEBA — anomaly scores, entity profiles |
| `SecurityAlert` | Alerts from Defender products |
| `OfficeActivity` | Exchange, SharePoint, Teams activity |
| `AzureActivity` | Azure Resource Manager control plane |
| `CloudAppEvents` | Defender for Cloud Apps events |

### KQL Foundations

```kql
// Basic structure
TableName
| where TimeGenerated > ago(24h)
| where Column == "value"
| project Column1, Column2, Column3
| order by TimeGenerated desc
| limit 100

// Aggregation
SigninLogs
| where TimeGenerated > ago(7d)
| summarize count() by UserPrincipalName, AppDisplayName
| order by count_ desc

// Join two tables
let users = AuditLogs
    | where OperationName == "Add user"
    | project NewUser = tostring(TargetResources[0].userPrincipalName);
SigninLogs
| where UserPrincipalName in (users)
| summarize count() by UserPrincipalName

// Time series for anomaly detection
SigninLogs
| where TimeGenerated > ago(30d)
| make-series logins=count() on TimeGenerated step 1h by UserPrincipalName
| extend anomalies = series_decompose_anomalies(logins)
```

---

## Instructor Mentoring Guidance

**Week 6 introduces multi-cloud thinking.** AWS knowledge alone is not enough for most enterprise roles — Microsoft Entra ID is in 90%+ of enterprise environments. Students who can write KQL are immediately more hireable.

**Common mistakes:**
- Students write `where` before understanding the table schema — run `.show table SigninLogs` first
- KQL `join` has different semantics than SQL — `kind=inner`, `kind=leftouter` must be explicit
- Not using `ago()` and time filtering — queries without time bounds scan all data and timeout

**Mentoring session agenda (60 min):**
1. (15 min) Live KQL demo in Log Analytics — show table explorer, run basic queries
2. (20 min) Walk through an impossible travel rule together — calculate distance vs time
3. (15 min) Show how to turn a KQL query into a Sentinel analytics rule (ARM template)
4. (10 min) Mock interview: "Walk me through how you'd detect a business email compromise in Azure"

**Office hours:** Help students connect Azure free trial to Sentinel. The connector configuration can be confusing — Microsoft Defender for Identity, Entra ID Protection, and Office 365 connectors all need separate enablement.

---

## Hands-on Lab

### Lab 1: Query SigninLogs for Suspicious Activity

```kql
// Failed logins by user — brute force detection
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"  // 0 = success
| summarize
    FailureCount = count(),
    FailureTypes = make_set(ResultDescription),
    SourceIPs = make_set(IPAddress)
  by UserPrincipalName
| where FailureCount >= 10
| order by FailureCount desc
```

```kql
// Successful login after multiple failures (brute force success)
let threshold = 5;
let failures = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize FailCount = count() by UserPrincipalName, bin(TimeGenerated, 10m);

let successes = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| project UserPrincipalName, SuccessTime = TimeGenerated, IPAddress;

failures
| where FailCount >= threshold
| join kind=inner successes on UserPrincipalName
| where SuccessTime > TimeGenerated
| project UserPrincipalName, FailCount, SuccessTime, IPAddress
```

### Lab 2: Impossible Travel Detection

```kql
// Impossible travel: same user, 2 countries, < 1 hour apart
let travel_speed_km_h = 800.0;  // max realistic speed (aircraft)
let min_distance_km = 100.0;

SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| where isnotempty(LocationDetails.countryOrRegion)
| project
    UserPrincipalName,
    TimeGenerated,
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    Lat = todouble(LocationDetails.geoCoordinates.latitude),
    Lon = todouble(LocationDetails.geoCoordinates.longitude),
    IPAddress
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend
    PrevUser = prev(UserPrincipalName),
    PrevTime = prev(TimeGenerated),
    PrevCountry = prev(Country),
    PrevLat = prev(Lat),
    PrevLon = prev(Lon)
| where UserPrincipalName == PrevUser
| extend
    TimeDiffHours = datetime_diff('minute', TimeGenerated, PrevTime) / 60.0,
    DistanceKm = geo_distance_2points(Lon, Lat, PrevLon, PrevLat) / 1000.0
| where PrevCountry != Country
| extend RequiredSpeedKmH = DistanceKm / max_of(TimeDiffHours, 0.001)
| where RequiredSpeedKmH > travel_speed_km_h
| where DistanceKm > min_distance_km
| project
    UserPrincipalName, TimeGenerated, PrevTime,
    Country, PrevCountry, DistanceKm,
    TimeDiffHours, RequiredSpeedKmH, IPAddress
| order by RequiredSpeedKmH desc
```

---

## Weekly Assignment — 20 KQL Detection Rules

Build a library of 20 production-grade KQL detection rules. Each rule must have:
- Rule name and description
- MITRE ATT&CK technique mapping
- KQL query
- Severity (High/Medium/Low)
- Recommended response action

### The 20 Rules to Build

| # | Rule Name | MITRE | Severity |
|---|-----------|-------|----------|
| 01 | Impossible Travel Login | T1078 | High |
| 02 | MFA Fatigue Attack (50+ push requests) | T1621 | High |
| 03 | Service Principal Secret Added | T1098.001 | High |
| 04 | Admin Role Assigned to User | T1078.004 | High |
| 05 | Bulk User Creation (>5 in 1h) | T1136 | High |
| 06 | Azure AD Password Spray (>50 users, 1-2 attempts each) | T1110.003 | High |
| 07 | Global Admin Privilege Escalation | T1098 | Critical |
| 08 | Legacy Authentication (Basic/NTLM) Used | T1078 | Medium |
| 09 | New Conditional Access Policy Bypassed | T1556 | High |
| 10 | App Consent Phishing (OAuth) | T1528 | High |
| 11 | Mass Mailbox Forwarding Rules Created | T1114.003 | High |
| 12 | SharePoint/OneDrive Mass Download | T1530 | High |
| 13 | Service Principal Login from New Country | T1078.004 | Medium |
| 14 | Dormant Account Awakened | T1078 | Medium |
| 15 | External Collaboration Enabled by Non-Admin | T1537 | Medium |
| 16 | User Added to Privileged Role Outside Business Hours | T1098 | High |
| 17 | Security Audit Policy Disabled | T1562 | High |
| 18 | Azure Resource Deletion Spike | T1485 | High |
| 19 | Suspicious Sign-in to Azure Management Portal | T1078 | Medium |
| 20 | Unified Audit Log Disabled | T1562.008 | Critical |

### Sample Rule — MFA Fatigue Attack

```kql
// Rule 02: MFA Fatigue Attack
// Detect users receiving excessive MFA push notifications (potential MFA fatigue)
// MITRE: T1621 - Multi-Factor Authentication Request Generation
// Severity: High

let lookback = 1h;
let threshold = 10;

AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ResultType in ("50074", "50076", "500121")  // MFA challenge codes
| summarize
    MFA_Requests = count(),
    SourceIPs = make_set(IPAddress),
    Apps = make_set(AppDisplayName),
    FirstRequest = min(TimeGenerated),
    LastRequest = max(TimeGenerated)
  by UserPrincipalName
| where MFA_Requests >= threshold
| extend Alert = strcat("MFA Fatigue: ", MFA_Requests, " challenges in 1h")
| project
    TimeGenerated = LastRequest,
    UserPrincipalName,
    MFA_Requests,
    SourceIPs,
    Apps,
    Alert
| order by MFA_Requests desc
```

### Sample Rule — Global Admin Escalation

```kql
// Rule 07: Global Admin Privilege Escalation
// Alert when Global Admin role is assigned — highest severity
// MITRE: T1098 - Account Manipulation
// Severity: Critical

AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName in ("Add member to role", "Add eligible member to role")
| where Result == "success"
| mv-expand TargetResources
| where TargetResources.type == "User"
| extend
    TargetUser = tostring(TargetResources.userPrincipalName),
    RoleAdded = tostring(parse_json(tostring(TargetResources.modifiedProperties))
                  [0].newValue)
| where RoleAdded has "Global Administrator"
| extend
    Actor = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress)
| project
    TimeGenerated, Actor, ActorIP, TargetUser, RoleAdded
| order by TimeGenerated desc
```

### Sample Rule — Password Spray

```kql
// Rule 06: Azure AD Password Spray
// Detect spray pattern: many users, few attempts each, from single or few IPs
// MITRE: T1110.003 - Password Spraying
// Severity: High

let lookback = 1h;
let max_attempts_per_user = 3;
let min_users_targeted = 20;

SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType != "0"  // failures only
| summarize
    AttemptCount = count(),
    Users = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 50)
  by IPAddress
| where Users >= min_users_targeted
| where (AttemptCount / Users) <= max_attempts_per_user
| extend SprayScore = round(todouble(Users) / max_of(AttemptCount, 1) * 100, 1)
| order by Users desc
```

---

## Detection Queries Reference

### Azure AD Audit Log — Key Security Events

```kql
// All privileged role assignments in 30 days
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "role"
| where Result == "success"
| mv-expand TargetResources
| extend
    Target = tostring(TargetResources.userPrincipalName),
    Role = tostring(parse_json(tostring(
        TargetResources.modifiedProperties))[0].newValue),
    Actor = tostring(InitiatedBy.user.userPrincipalName)
| where Role has_any ("Administrator", "Owner", "Privileged")
| project TimeGenerated, Actor, Target, Role
| order by TimeGenerated desc
```

```kql
// Service principals with newly added credentials (potential backdoor)
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in (
    "Add service principal credentials",
    "Update application - Certificates and secrets management"
  )
| where Result == "success"
| extend
    SPName = tostring(TargetResources[0].displayName),
    Actor = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, SPName, Actor, ActorIP
| order by TimeGenerated desc
```

---

## Interview Skills Gained

**Q: What is KQL and how does it differ from SQL?**
> KQL (Kusto Query Language) is a read-only query language designed for time-series log analysis in Azure Data Explorer and Sentinel. Unlike SQL, KQL uses a pipe `|` operator to chain transformations. It natively handles time series with `make-series`, has built-in ML functions like `series_decompose_anomalies`, and is optimized for log analytics workloads rather than relational data.

**Q: How would you detect a business email compromise in Azure?**
> I'd look for: (1) inbox forwarding rules created to external addresses — `OfficeActivity` where `Operation == "New-InboxRule"` and the rule forwards externally; (2) sign-in from new country followed by mass email access; (3) sign-in with legacy auth from an IP that has never been seen for that user; (4) bulk deletion of sent items or recovery of deleted items; (5) OAuth app consent granted to an unfamiliar application.

**Q: What is MFA fatigue and how do you detect it in Sentinel?**
> MFA fatigue is an attack where the adversary has stolen credentials and continuously sends MFA push notifications hoping the user accepts one to make it stop. Detect it by querying `AADNonInteractiveUserSignInLogs` for result codes 50074/50076 (MFA required) and alerting when a single user receives more than 10-15 push notifications within an hour.

---

## GitHub Project Structure

```
azure-sentinel-detection/
├── README.md
├── rules/
│   ├── 01-impossible-travel.kql
│   ├── 02-mfa-fatigue.kql
│   ├── 03-service-principal-secret-added.kql
│   ├── ...
│   └── 20-unified-audit-log-disabled.kql
├── arm-templates/
│   └── analytics-rules-deploy.json
├── workbooks/
│   └── identity-threats-workbook.json
├── playbooks/
│   └── mfa-fatigue-response.json
└── docs/
    ├── architecture.png
    ├── mitre-mapping.md
    └── rule-descriptions.md
```

### Screenshots Required

1. Sentinel workspace with at least 3 analytics rules visible
2. A KQL query result showing actual data (use the 30-day free trial)
3. An incident created from one of your analytics rules
4. MITRE ATT&CK coverage matrix for your 20 rules

---

## Submission Checklist

- [ ] 20 KQL rules committed to `rules/` folder, each with MITRE mapping in a header comment
- [ ] At least 5 rules tested in a live Sentinel workspace (free trial)
- [ ] ARM template for deploying all rules programmatically
- [ ] README explains each rule, detection logic, and recommended response
- [ ] Screenshots: workspace, incidents, query results
- [ ] MITRE ATT&CK coverage table in `docs/mitre-mapping.md`

---

## Links

→ Full project: [projects/06-azure-sentinel-detection/](../../projects/06-azure-sentinel-detection/)
→ Next: [Week 07 — GitHub Supply Chain Security](../week-07/README.md)
