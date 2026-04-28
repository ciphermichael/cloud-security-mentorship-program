-- ============================================================
-- CloudTrail Threat Hunting — Athena SQL Queries
-- Project: 05-cloudtrail-threat-hunting
-- Assumes table created per STEPS.md
-- ============================================================

-- ── Hunt 1: Root account usage ────────────────────────────────────────────────
SELECT
    eventTime, eventName, sourceIPAddress, userAgent, awsRegion
FROM cloudtrail_logs
WHERE userIdentity.type = 'Root'
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC
LIMIT 100;


-- ── Hunt 2: Console logins without MFA ───────────────────────────────────────
SELECT
    eventTime,
    userIdentity.userName                                        AS username,
    sourceIPAddress,
    userAgent,
    json_extract_scalar(additionalEventData, '$.MFAUsed')        AS mfa_used
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND json_extract_scalar(responseElements, '$.ConsoleLogin') = 'Success'
  AND json_extract_scalar(additionalEventData, '$.MFAUsed') = 'No'
  AND eventTime > date_format(date_add('day', -30, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC;


-- ── Hunt 3: Brute force — 5+ failed auths from same IP ───────────────────────
SELECT
    sourceIPAddress,
    userIdentity.userName                   AS username,
    count(*)                                AS failures,
    min(eventTime)                          AS first_attempt,
    max(eventTime)                          AS last_attempt
FROM cloudtrail_logs
WHERE errorCode IN (
    'Client.UnauthorizedOperation',
    'AccessDenied',
    'AuthFailure',
    'InvalidClientTokenId'
)
  AND eventTime > date_format(date_add('day', -1, now()), '%Y-%m-%dT%H:%i:%sZ')
GROUP BY 1, 2
HAVING count(*) >= 5
ORDER BY failures DESC;


-- ── Hunt 4: S3 mass download — exfiltration indicator ────────────────────────
SELECT
    userIdentity.arn                        AS identity,
    sourceIPAddress,
    json_extract_scalar(requestParameters, '$.bucketName') AS bucket,
    count(*)                                AS get_count,
    date_trunc('hour', from_iso8601_timestamp(eventTime)) AS hour_bucket
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND eventTime > date_format(date_add('day', -1, now()), '%Y-%m-%dT%H:%i:%sZ')
GROUP BY 1, 2, 3, 4
HAVING count(*) > 100
ORDER BY get_count DESC;


-- ── Hunt 5: New IAM users created ────────────────────────────────────────────
SELECT
    eventTime,
    userIdentity.arn                                AS actor,
    json_extract_scalar(requestParameters, '$.userName') AS new_user,
    sourceIPAddress,
    awsRegion
FROM cloudtrail_logs
WHERE eventName = 'CreateUser'
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC;


-- ── Hunt 6: CloudTrail tampering ──────────────────────────────────────────────
SELECT
    eventTime, eventName, userIdentity.arn, sourceIPAddress, awsRegion
FROM cloudtrail_logs
WHERE eventName IN (
    'StopLogging', 'DeleteTrail', 'UpdateTrail',
    'PutEventSelectors', 'DeleteFlowLogs'
)
  AND eventTime > date_format(date_add('day', -30, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC;


-- ── Hunt 7: Impossible travel (same user, 2 IPs within 1 hour) ───────────────
WITH logins AS (
    SELECT
        userIdentity.userName              AS username,
        sourceIPAddress,
        from_iso8601_timestamp(eventTime)  AS ts
    FROM cloudtrail_logs
    WHERE eventName = 'ConsoleLogin'
      AND json_extract_scalar(responseElements, '$.ConsoleLogin') = 'Success'
      AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
)
SELECT
    a.username,
    a.sourceIPAddress                     AS ip_1,
    b.sourceIPAddress                     AS ip_2,
    a.ts                                  AS time_1,
    b.ts                                  AS time_2,
    date_diff('minute', a.ts, b.ts)       AS minutes_apart
FROM logins a
JOIN logins b
    ON  a.username = b.username
    AND a.sourceIPAddress != b.sourceIPAddress
    AND abs(date_diff('minute', a.ts, b.ts)) < 60
ORDER BY minutes_apart ASC
LIMIT 50;


-- ── Hunt 8: API enumeration burst (50+ Describe/List/Get in 5 min) ────────────
SELECT
    userIdentity.arn                       AS identity,
    sourceIPAddress,
    date_trunc('minute', from_iso8601_timestamp(eventTime)) AS minute_bucket,
    count(*)                               AS api_calls
FROM cloudtrail_logs
WHERE (eventName LIKE 'Describe%'
    OR eventName LIKE 'List%'
    OR eventName LIKE 'Get%')
  AND eventTime > date_format(date_add('day', -1, now()), '%Y-%m-%dT%H:%i:%sZ')
GROUP BY 1, 2, 3
HAVING count(*) >= 50
ORDER BY api_calls DESC;


-- ── Hunt 9: AssumeRole cross-account ─────────────────────────────────────────
SELECT
    eventTime,
    userIdentity.arn                                            AS caller,
    json_extract_scalar(requestParameters, '$.roleArn')         AS target_role,
    sourceIPAddress,
    awsRegion
FROM cloudtrail_logs
WHERE eventName = 'AssumeRole'
  AND NOT json_extract_scalar(requestParameters, '$.roleArn')
          LIKE '%YOUR-ACCOUNT-ID%'
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC
LIMIT 100;


-- ── Hunt 10: Secrets Manager / SSM access ────────────────────────────────────
SELECT
    eventTime,
    userIdentity.arn,
    eventName,
    eventSource,
    sourceIPAddress,
    json_extract_scalar(requestParameters, '$.secretId') AS secret_id
FROM cloudtrail_logs
WHERE eventSource IN ('secretsmanager.amazonaws.com', 'ssm.amazonaws.com')
  AND eventName IN (
    'GetSecretValue', 'DescribeSecret',
    'GetParameter', 'GetParameters', 'GetParametersByPath'
  )
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC;
