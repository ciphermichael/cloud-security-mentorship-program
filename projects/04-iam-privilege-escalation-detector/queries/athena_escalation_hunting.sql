-- ============================================================
-- IAM Privilege Escalation — Athena Hunting Queries
-- Project: 04-iam-privilege-escalation-detector
-- Run these against your CloudTrail Athena table
-- ============================================================

-- ── Query 1: All escalation events (last 7 days) ──────────────────────────────
SELECT
    eventTime,
    eventName,
    userIdentity.arn                                              AS actor_arn,
    userIdentity.type                                             AS actor_type,
    sourceIPAddress,
    awsRegion,
    json_extract_scalar(requestParameters, '$.roleName')          AS target_role,
    json_extract_scalar(requestParameters, '$.userName')          AS target_user,
    json_extract_scalar(requestParameters, '$.policyArn')         AS policy_arn
FROM cloudtrail_logs
WHERE eventName IN (
    'CreatePolicyVersion',
    'SetDefaultPolicyVersion',
    'UpdateAssumeRolePolicy',
    'AttachUserPolicy',
    'AttachRolePolicy',
    'AttachGroupPolicy',
    'PutUserPolicy',
    'PutRolePolicy',
    'AddUserToGroup',
    'CreateAccessKey',
    'CreateLoginProfile',
    'UpdateLoginProfile',
    'CreateUser'
)
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC;


-- ── Query 2: Two-step escalation chain (CreatePolicyVersion → SetDefault) ────
-- Detects Path 1: actor creates admin version then immediately sets as default
WITH escalation AS (
    SELECT
        userIdentity.arn                          AS actor,
        eventName,
        from_iso8601_timestamp(eventTime)         AS ts
    FROM cloudtrail_logs
    WHERE eventName IN ('CreatePolicyVersion', 'SetDefaultPolicyVersion')
      AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
)
SELECT
    a.actor,
    a.ts                                AS create_version_time,
    b.ts                                AS set_default_time,
    date_diff('second', a.ts, b.ts)    AS seconds_between
FROM escalation a
JOIN escalation b
    ON  a.actor = b.actor
    AND a.eventName = 'CreatePolicyVersion'
    AND b.eventName = 'SetDefaultPolicyVersion'
    AND date_diff('minute', a.ts, b.ts) BETWEEN 0 AND 30
ORDER BY seconds_between ASC;


-- ── Query 3: PassRole + service creation (Path 14 & 15) ──────────────────────
-- Detects iam:PassRole followed by EC2/Lambda/Glue creation within 10 minutes
WITH pass_roles AS (
    SELECT
        userIdentity.arn                          AS actor,
        from_iso8601_timestamp(eventTime)         AS ts
    FROM cloudtrail_logs
    WHERE eventName = 'PassRole'
      AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
),
service_creates AS (
    SELECT
        userIdentity.arn                          AS actor,
        eventName,
        from_iso8601_timestamp(eventTime)         AS ts
    FROM cloudtrail_logs
    WHERE eventName IN (
        'RunInstances', 'CreateFunction20150331',
        'CreateJob', 'StartGlueSession'
    )
      AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
)
SELECT
    p.actor,
    p.ts                                AS pass_role_time,
    s.eventName                         AS service_create_event,
    s.ts                                AS service_create_time,
    date_diff('minute', p.ts, s.ts)    AS minutes_between
FROM pass_roles p
JOIN service_creates s
    ON  p.actor = s.actor
    AND date_diff('minute', p.ts, s.ts) BETWEEN 0 AND 10
ORDER BY minutes_between;


-- ── Query 4: Access key created for a different user (Path 11) ───────────────
SELECT
    eventTime,
    userIdentity.arn                                              AS actor,
    json_extract_scalar(requestParameters, '$.userName')          AS key_created_for,
    sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'CreateAccessKey'
  AND userIdentity.arn NOT LIKE '%' || json_extract_scalar(requestParameters, '$.userName')
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC;


-- ── Query 5: AdministratorAccess policy attachments ──────────────────────────
SELECT
    eventTime,
    userIdentity.arn                                              AS actor,
    eventName,
    json_extract_scalar(requestParameters, '$.policyArn')         AS policy_arn,
    json_extract_scalar(requestParameters, '$.userName')          AS target_user,
    json_extract_scalar(requestParameters, '$.roleName')          AS target_role,
    sourceIPAddress
FROM cloudtrail_logs
WHERE eventName IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy')
  AND json_extract_scalar(requestParameters, '$.policyArn')
      LIKE '%AdministratorAccess%'
  AND eventTime > date_format(date_add('day', -30, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC;


-- ── Query 6: Escalation activity outside business hours ──────────────────────
SELECT
    eventTime,
    eventName,
    userIdentity.arn  AS actor,
    sourceIPAddress,
    hour(from_iso8601_timestamp(eventTime))  AS utc_hour
FROM cloudtrail_logs
WHERE eventName IN (
    'CreatePolicyVersion', 'AttachUserPolicy', 'AttachRolePolicy',
    'CreateAccessKey', 'UpdateLoginProfile', 'CreateUser'
)
  AND hour(from_iso8601_timestamp(eventTime)) NOT BETWEEN 8 AND 18
  AND eventTime > date_format(date_add('day', -7, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventTime DESC;
