# Week 04 — CloudTrail, Logging Architecture & Threat Visibility

**Phase 1: Foundations | Leads to Project: 05-cloudtrail-threat-hunting**

---

## Learning Objectives

By the end of this week you will be able to:

- Configure AWS CloudTrail for multi-region, multi-account coverage with integrity validation
- Set up CloudWatch log groups, metric filters, and alarms for critical security events
- Query CloudTrail logs with CloudWatch Logs Insights in real time
- Create an Athena table over CloudTrail S3 logs and run threat hunting SQL
- Understand what CloudTrail does NOT log (data events, management vs data plane gap)
- Detect logging gaps and disabled trails — a common attacker technique

---

## Daily Breakdown

| Day | Focus | Time |
|-----|-------|------|
| Mon | CloudTrail architecture — management events, data events, trail types, integrity validation | 2 hrs |
| Tue | CloudWatch Logs — log groups, metric filters, alarms, subscription filters | 2 hrs |
| Wed | AWS Athena setup — create CloudTrail table using SerDe, first queries | 2 hrs |
| Thu | Write CloudWatch Insights queries for 5 critical security events | 2 hrs |
| Fri | Write 8 Athena hunting queries, build Python query runner | 2 hrs |
| Sat | Document findings, build query library, push to GitHub | 3 hrs |
| Sun | Review session with mentor, prep Week 5 | 1 hr |

---

## Topics Covered

### CloudTrail Fundamentals

CloudTrail records **who did what, when, and from where** across your AWS account. Every API call is an event.

**Trail types:**
- **Management events** — control plane: `CreateBucket`, `RunInstances`, `AttachRolePolicy`. Free tier: first trail free.
- **Data events** — data plane: `S3:GetObject`, `Lambda:Invoke`, `DynamoDB:GetItem`. Additional cost but critical for investigation.
- **Insights events** — anomaly detection on API call rates. Useful for detecting unusual bursts.

**Critical trail configuration:**
```
✓ Multi-region trail (catches activity in all regions)
✓ Include global services (IAM, STS, CloudFront)
✓ Log file integrity validation enabled
✓ CloudWatch Logs integration (real-time alerting)
✓ S3 server-side encryption (SSE-KMS)
✓ S3 access logging on the trail bucket
✓ MFA delete on the trail bucket
```

**What attackers do to CloudTrail:**
- `DeleteTrail` — removes all future logging
- `StopLogging` — pauses the trail
- `UpdateTrail` — removes S3/CW delivery or integrity validation
- `PutEventSelectors` — removes data event logging
- Creating resources in regions where no trail exists

### CloudWatch Logs Architecture

```
CloudTrail → CloudWatch Log Group → Metric Filter → Alarm → SNS → Alert
```

**Key metric filters for security:**

| Filter Name | Pattern | What It Detects |
|-------------|---------|-----------------|
| RootAccountUsage | `{ $.userIdentity.type = "Root" }` | Root API calls |
| UnauthorizedAPICalls | `{ $.errorCode = "AccessDenied" }` | Permission failures |
| ConsoleLoginFailures | `{ $.eventName = "ConsoleLogin" && $.errorMessage = "Failed*" }` | Brute force |
| CloudTrailChanges | `{ $.eventName = "StopLogging" }` | Log tampering |
| SecurityGroupChanges | `{ $.eventName = "AuthorizeSecurityGroupIngress" }` | Firewall changes |

### Athena Setup for CloudTrail

CloudTrail logs are stored in S3 as gzipped JSON files. Athena reads them directly using the CloudTrail Hive SerDe.

---

## Instructor Mentoring Guidance

**Week 4 builds the investigative foundation.** Every future project depends on students being able to query CloudTrail. Emphasize that investigation speed is a competitive advantage — a security engineer who can write Athena SQL in real time during an incident is worth 3x one who cannot.

**Common mistakes:**
- Students use CloudTrail console search instead of Athena for bulk analysis — console is rate-limited and impractical for large investigations
- Forgetting to partition the Athena table (costs 10x more without partitions)
- Not understanding the 15-minute delay between API call and CloudTrail delivery to S3

**Mentoring session agenda (60 min):**
1. (10 min) Live demo: delete a trail, show what happens in Athena — gap in visibility
2. (20 min) Pair on Athena query — show PARTITION BY, LIMIT, date filtering
3. (20 min) Build a metric filter together in console, trigger alarm
4. (10 min) Discuss: "If an attacker gets your CloudTrail access key, what can they do to blind you? How do you defend against it?"

---

## Hands-on Lab

### Lab 1: Create a Multi-Region Trail with Integrity

```bash
# Create a dedicated S3 bucket for CloudTrail
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="cloudtrail-logs-${ACCOUNT_ID}-$(date +%s)"

aws s3api create-bucket \
  --bucket "$BUCKET_NAME" \
  --region us-east-1

# Block all public access
aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,\
BlockPublicPolicy=true,RestrictPublicBuckets=true

# Apply CloudTrail bucket policy (required for CloudTrail to write to it)
cat > trail-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${BUCKET_NAME}"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/AWSLogs/${ACCOUNT_ID}/*",
      "Condition": {
        "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" }
      }
    }
  ]
}
EOF
aws s3api put-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --policy file://trail-bucket-policy.json

# Create the trail
aws cloudtrail create-trail \
  --name security-trail \
  --s3-bucket-name "$BUCKET_NAME" \
  --is-multi-region-trail \
  --include-global-service-events \
  --enable-log-file-validation

# Start logging
aws cloudtrail start-logging --name security-trail

# Verify
aws cloudtrail get-trail-status --name security-trail \
  --query '{Logging:IsLogging,Latest:LatestDeliveryTime}'
```

### Lab 2: Validate Log File Integrity

```bash
# After 15 minutes, validate that logs haven't been tampered with
aws cloudtrail validate-logs \
  --trail-arn "arn:aws:cloudtrail:us-east-1:${ACCOUNT_ID}:trail/security-trail" \
  --start-time "2024-01-01T00:00:00Z" \
  --verbose

# Expected output: "No invalid log files found"
```

### Lab 3: CloudWatch Metric Filter for Root Account Usage

```bash
# Create the log group first (CloudTrail → CloudWatch integration)
aws logs create-log-group --log-group-name /aws/cloudtrail/security-events

# Create metric filter for root account usage
aws logs put-metric-filter \
  --log-group-name /aws/cloudtrail/security-events \
  --filter-name RootAccountUsage \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations \
    metricName=RootAccountUsageCount,\
metricNamespace=CloudTrailMetrics,\
metricValue=1

# Create alarm
aws cloudwatch put-metric-alarm \
  --alarm-name RootAccountUsage \
  --alarm-description "Alert on root account API usage" \
  --metric-name RootAccountUsageCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching
```

### Lab 4: Athena Table Creation

```sql
-- Create the CloudTrail Athena table
-- Run this in the Athena console, replace YOUR_BUCKET and ACCOUNT_ID

CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_logs (
    eventVersion STRING,
    userIdentity STRUCT<
        type: STRING,
        principalId: STRING,
        arn: STRING,
        accountId: STRING,
        invokedBy: STRING,
        accessKeyId: STRING,
        userName: STRING,
        sessionContext: STRUCT<
            sessionIssuer: STRUCT<
                type: STRING,
                principalId: STRING,
                arn: STRING,
                accountId: STRING,
                userName: STRING
            >,
            attributes: STRUCT<
                mfaAuthenticated: STRING,
                creationDate: STRING
            >
        >
    >,
    eventTime STRING,
    eventSource STRING,
    eventName STRING,
    awsRegion STRING,
    sourceIPAddress STRING,
    userAgent STRING,
    errorCode STRING,
    errorMessage STRING,
    requestParameters STRING,
    responseElements STRING,
    additionalEventData STRING,
    requestId STRING,
    eventId STRING,
    resources ARRAY<STRUCT<arn: STRING, accountId: STRING, type: STRING>>,
    eventType STRING,
    apiVersion STRING,
    readOnly STRING,
    recipientAccountId STRING,
    sharedEventID STRING,
    vpcEndpointId STRING
)
COMMENT 'CloudTrail logs'
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://YOUR_BUCKET/AWSLogs/ACCOUNT_ID/CloudTrail/';
```

---

## Weekly Assignment — CloudTrail Query Library

Build a library of 10 essential security detection queries in both CloudWatch Logs Insights and Athena SQL, and a Python wrapper that runs them automatically.

### Core Security Queries to Implement

**CloudWatch Logs Insights (real-time — last 24h window):**

```
# 1. Root account usage
fields @timestamp, eventName, sourceIPAddress, userAgent
| filter userIdentity.type = "Root"
| sort @timestamp desc
| limit 100
```

```
# 2. Console login without MFA
fields @timestamp, userIdentity.userName, sourceIPAddress, userAgent
| filter eventName = "ConsoleLogin"
  and responseElements.ConsoleLogin = "Success"
  and additionalEventData.MFAUsed = "No"
| sort @timestamp desc
```

```
# 3. Brute force — 5+ failed auth per source IP
fields @timestamp, sourceIPAddress, userIdentity.userName, errorCode
| filter errorCode in ["Client.UnauthorizedOperation", "AccessDenied",
                        "AuthFailure", "InvalidClientTokenId"]
| stats count() as failures by sourceIPAddress, userIdentity.userName
| sort failures desc
| filter failures >= 5
```

```
# 4. CloudTrail tampering (StopLogging / DeleteTrail)
fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter eventName in ["StopLogging", "DeleteTrail", "UpdateTrail",
                        "PutEventSelectors", "DeleteFlowLogs"]
| sort @timestamp desc
```

```
# 5. New IAM users or access keys created
fields @timestamp, userIdentity.arn, eventName
| filter eventName in ["CreateUser", "CreateAccessKey", "CreateLoginProfile"]
| sort @timestamp desc
```

**Athena SQL (historical investigation):**

```sql
-- 6. Impossible travel: same user, >2 source IPs within 1 hour
WITH login_events AS (
    SELECT
        userIdentity.userName AS username,
        sourceIPAddress,
        from_iso8601_timestamp(eventTime) AS event_ts
    FROM cloudtrail_logs
    WHERE eventName = 'ConsoleLogin'
      AND responseElements LIKE '%Success%'
      AND eventTime > date_format(date_add('day', -7, now()),
                                  '%Y-%m-%dT%H:%i:%sZ')
)
SELECT
    a.username,
    a.sourceIPAddress AS ip_1,
    b.sourceIPAddress AS ip_2,
    a.event_ts AS time_1,
    b.event_ts AS time_2,
    date_diff('minute', a.event_ts, b.event_ts) AS minutes_between
FROM login_events a
JOIN login_events b
    ON a.username = b.username
    AND a.sourceIPAddress != b.sourceIPAddress
    AND abs(date_diff('minute', a.event_ts, b.event_ts)) < 60
ORDER BY minutes_between ASC
LIMIT 50;
```

```sql
-- 7. S3 mass download (data exfiltration indicator)
SELECT
    userIdentity.arn,
    sourceIPAddress,
    count(*) AS get_count,
    date_trunc('hour', from_iso8601_timestamp(eventTime)) AS hour_bucket
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND eventTime > date_format(date_add('day', -1, now()), '%Y-%m-%dT%H:%i:%sZ')
GROUP BY 1, 2, 4
HAVING count(*) > 100
ORDER BY get_count DESC;
```

```sql
-- 8. API calls from Tor exit nodes / known malicious IPs
-- (build a lookup table in Athena from threat intel feeds)
SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress, awsRegion
FROM cloudtrail_logs
WHERE sourceIPAddress IN (
    SELECT ip FROM tor_exit_nodes  -- external table
)
AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ');
```

```sql
-- 9. Enumeration burst: >50 Describe/List calls in 5 minutes
SELECT
    userIdentity.arn AS identity,
    sourceIPAddress,
    date_trunc('minute', from_iso8601_timestamp(eventTime)) AS minute_bucket,
    count(*) AS api_calls
FROM cloudtrail_logs
WHERE eventName LIKE 'Describe%' OR eventName LIKE 'List%' OR eventName LIKE 'Get%'
  AND eventTime > date_format(date_add('day', -1, now()), '%Y-%m-%dT%H:%i:%sZ')
GROUP BY 1, 2, 3
HAVING count(*) > 50
ORDER BY api_calls DESC;
```

```sql
-- 10. EC2 instance metadata credential usage from unusual regions
SELECT
    eventTime,
    userIdentity.arn,
    userIdentity.sessionContext.sessionIssuer.arn AS role_arn,
    awsRegion,
    sourceIPAddress,
    eventName
FROM cloudtrail_logs
WHERE userIdentity.type = 'AssumedRole'
  AND userIdentity.sessionContext.sessionIssuer.type = 'Role'
  AND awsRegion NOT IN ('us-east-1', 'us-west-2', 'eu-west-1')
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC
LIMIT 100;
```

---

## Interview Skills Gained

**Q: What is the difference between management events and data events in CloudTrail?**
> Management events record control plane operations — creating/deleting/modifying AWS resources (IAM, EC2, S3). Data events record data plane access — reading/writing objects inside resources (S3 GetObject, Lambda Invoke). Data events are turned off by default and cost extra but are essential for investigating data breaches.

**Q: How would you detect if an attacker disabled CloudTrail?**
> The `StopLogging`, `DeleteTrail`, and `UpdateTrail` CloudTrail events are themselves logged (in the brief window before deletion). Create a CloudWatch metric filter on these events and alarm immediately. Also ship logs to an immutable, cross-account S3 bucket with MFA delete enabled, so an attacker in the primary account cannot erase historical logs.

**Q: You're investigating a suspected breach. What's your first move with CloudTrail?**
> First, open Athena (or CloudWatch Insights for recent data), find the compromised identity (user/role ARN), and timeline all their API calls sorted by time. Then pivot to unusual `eventName` values, IPs outside company egress, and any privilege escalation events like `CreateUser`, `AttachRolePolicy`, `UpdateAssumeRolePolicy`.

---

## Submission Checklist

- [ ] CloudTrail trail configured multi-region with integrity validation
- [ ] 5 CloudWatch metric filters created and documented
- [ ] Athena table created and test queries run successfully
- [ ] 10 queries committed to `queries/` folder (5 Insights, 5 Athena)
- [ ] Python query runner script working for at least 3 queries
- [ ] README explains the logging architecture with a diagram
- [ ] Screenshots: trail status, Athena results, CloudWatch alarms in console

---

## Links

→ Project this feeds: [projects/05-cloudtrail-threat-hunting/](../../projects/05-cloudtrail-threat-hunting/)
→ Next: [Week 05 — IAM Privilege Escalation Paths](../week-05/README.md)
