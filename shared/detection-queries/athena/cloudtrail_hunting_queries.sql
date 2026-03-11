-- =============================================================================
-- AWS Athena SQL — CloudTrail Threat Hunting Queries
-- Cloud Security Mentorship Programme
-- Prerequisites:
--   1. CloudTrail enabled and delivering to S3
--   2. Athena table created over the S3 bucket
--   3. Run CREATE TABLE query below first
-- =============================================================================


-- ─── SETUP: Create Athena table over CloudTrail logs ─────────────────────────
-- Run this ONCE to create the table. Replace YOUR_BUCKET and ACCOUNT_ID.

CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_logs (
    eventVersion        STRING,
    userIdentity        STRUCT<
                            type:STRING, principalId:STRING, arn:STRING,
                            accountId:STRING, invokedBy:STRING, accessKeyId:STRING,
                            userName:STRING,
                            sessionContext:STRUCT<
                                attributes:STRUCT<mfaAuthenticated:STRING, creationDate:STRING>,
                                sessionIssuer:STRUCT<type:STRING, principalId:STRING,
                                    arn:STRING, accountId:STRING, userName:STRING>>>,
    eventTime           STRING,
    eventSource         STRING,
    eventName           STRING,
    awsRegion           STRING,
    sourceIPAddress     STRING,
    userAgent           STRING,
    errorCode           STRING,
    errorMessage        STRING,
    requestParameters   STRING,
    responseElements    STRING,
    additionalEventData STRING,
    requestId           STRING,
    eventId             STRING,
    resources           ARRAY<STRUCT<ARN:STRING, accountId:STRING, type:STRING>>,
    eventType           STRING,
    apiVersion          STRING,
    readOnly            STRING,
    recipientAccountId  STRING,
    serviceEventDetails STRING,
    sharedEventID       STRING,
    vpcEndpointId       STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://YOUR_BUCKET/AWSLogs/ACCOUNT_ID/CloudTrail/'
TBLPROPERTIES ('classification'='cloudtrail');


-- ─── QUERY 1: Compromised API Key — Wide Enumeration ─────────────────────────
-- Detects credentials accessing many services rapidly (reconnaissance indicator)

SELECT
    useridentity.arn                             AS actor_arn,
    useridentity.accesskeyid                     AS access_key,
    sourceipaddress                              AS source_ip,
    useragent                                    AS user_agent,
    COUNT(*)                                     AS total_api_calls,
    COUNT(DISTINCT eventsource)                  AS services_accessed,
    COUNT(DISTINCT awsregion)                    AS regions_used,
    MIN(eventtime)                               AS first_seen,
    MAX(eventtime)                               AS last_seen,
    ARRAY_AGG(DISTINCT eventsource)              AS services_list
FROM   cloudtrail_logs
WHERE  eventtime >= DATE_FORMAT(NOW() - INTERVAL '24' HOUR, '%Y-%m-%dT%H:%i:%sZ')
  AND  errorcode IS NULL
  AND  useridentity.type = 'IAMUser'
  AND  eventsource != 'sts.amazonaws.com'
GROUP BY 1,2,3,4
HAVING services_accessed > 5
   AND total_api_calls   > 50
ORDER BY services_accessed DESC, total_api_calls DESC
LIMIT 50;


-- ─── QUERY 2: Root Account API Activity ──────────────────────────────────────
-- Any root API call should generate immediate alert

SELECT
    eventtime          AS event_time,
    eventname          AS event_name,
    eventsource        AS event_source,
    awsregion          AS region,
    sourceipaddress    AS source_ip,
    useragent          AS user_agent,
    errorcode          AS error,
    requestparameters  AS request_params
FROM   cloudtrail_logs
WHERE  eventtime >= DATE_FORMAT(NOW() - INTERVAL '7' DAY, '%Y-%m-%dT%H:%i:%sZ')
  AND  useridentity.type = 'Root'
  AND  eventtype = 'AwsApiCall'
ORDER BY eventtime DESC
LIMIT 100;


-- ─── QUERY 3: IAM Privilege Escalation Hunt ──────────────────────────────────
-- All high-risk IAM events with actor context

SELECT
    eventtime                AS event_time,
    eventname                AS event_name,
    awsregion                AS region,
    useridentity.arn         AS actor_arn,
    useridentity.type        AS actor_type,
    useridentity.accesskeyid AS access_key,
    sourceipaddress          AS source_ip,
    useragent                AS user_agent,
    requestparameters        AS request_params,
    errorcode                AS error_code
FROM   cloudtrail_logs
WHERE  eventtime >= DATE_FORMAT(NOW() - INTERVAL '24' HOUR, '%Y-%m-%dT%H:%i:%sZ')
  AND  eventsource = 'iam.amazonaws.com'
  AND  eventname IN (
           'CreatePolicyVersion', 'SetDefaultPolicyVersion',
           'AttachUserPolicy',    'AttachRolePolicy',
           'PutUserPolicy',       'PutRolePolicy',
           'CreateAccessKey',     'UpdateLoginProfile',
           'AddUserToGroup',      'CreateRole',
           'CreateUser'
       )
  AND  errorcode IS NULL
  AND  useridentity.type != 'Root'
ORDER BY eventtime DESC;


-- ─── QUERY 4: S3 Mass GetObject — Data Exfiltration ─────────────────────────
-- Detect users/keys downloading unusually large numbers of objects

SELECT
    useridentity.arn      AS actor_arn,
    useridentity.accesskeyid AS access_key,
    sourceipaddress        AS source_ip,
    json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
    COUNT(*)               AS object_downloads,
    MIN(eventtime)         AS first_download,
    MAX(eventtime)         AS last_download
FROM   cloudtrail_logs
WHERE  eventtime >= DATE_FORMAT(NOW() - INTERVAL '24' HOUR, '%Y-%m-%dT%H:%i:%sZ')
  AND  eventsource = 's3.amazonaws.com'
  AND  eventname = 'GetObject'
  AND  errorcode IS NULL
GROUP BY 1,2,3,4
HAVING COUNT(*) > 200
ORDER BY object_downloads DESC
LIMIT 25;


-- ─── QUERY 5: CloudTrail Tampering Hunt ──────────────────────────────────────
-- Detect attempts to disable or delete CloudTrail (cover-tracks behaviour)

SELECT
    eventtime          AS event_time,
    eventname          AS event_name,
    awsregion          AS region,
    useridentity.arn   AS actor_arn,
    sourceipaddress    AS source_ip,
    requestparameters  AS request_params
FROM   cloudtrail_logs
WHERE  eventtime >= DATE_FORMAT(NOW() - INTERVAL '7' DAY, '%Y-%m-%dT%H:%i:%sZ')
  AND  eventsource = 'cloudtrail.amazonaws.com'
  AND  eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail',
                     'PutEventSelectors', 'DeleteEventDataStore')
ORDER BY eventtime DESC;


-- ─── QUERY 6: Console Logins from Unknown IPs ────────────────────────────────
-- Track all console logins and identify unusual source IPs

SELECT
    eventtime                  AS login_time,
    awsregion                  AS region,
    useridentity.arn           AS user_arn,
    useridentity.username      AS username,
    sourceipaddress            AS source_ip,
    useragent                  AS browser,
    json_extract_scalar(responseelements, '$.ConsoleLogin') AS result,
    json_extract_scalar(additionaleventdata, '$.MFAUsed')   AS mfa_used
FROM   cloudtrail_logs
WHERE  eventtime >= DATE_FORMAT(NOW() - INTERVAL '7' DAY, '%Y-%m-%dT%H:%i:%sZ')
  AND  eventname = 'ConsoleLogin'
ORDER BY eventtime DESC
LIMIT 200;


-- ─── QUERY 7: EC2 Instances Launched in Unusual Regions ──────────────────────
-- Crypto miners often use regions where the victim doesn't operate

SELECT
    eventtime          AS event_time,
    awsregion          AS region,
    useridentity.arn   AS actor_arn,
    sourceipaddress    AS source_ip,
    json_extract_scalar(requestparameters, '$.instanceType') AS instance_type,
    requestparameters  AS request_params
FROM   cloudtrail_logs
WHERE  eventtime >= DATE_FORMAT(NOW() - INTERVAL '24' HOUR, '%Y-%m-%dT%H:%i:%sZ')
  AND  eventsource = 'ec2.amazonaws.com'
  AND  eventname = 'RunInstances'
  AND  errorcode IS NULL
  AND  awsregion NOT IN ('us-east-1', 'us-west-2', 'eu-west-1')  -- adjust to your normal regions
ORDER BY eventtime DESC;


-- ─── QUERY 8: New IAM Access Keys Created (Persistence Hunt) ─────────────────

SELECT
    eventtime                        AS event_time,
    useridentity.arn                 AS actor_arn,
    json_extract_scalar(requestparameters, '$.userName')  AS target_user,
    json_extract_scalar(responseelements, '$.accessKey.accessKeyId') AS new_key_id,
    sourceipaddress                  AS source_ip,
    -- Flag cross-user key creation
    CASE
        WHEN useridentity.username != json_extract_scalar(requestparameters, '$.userName')
        THEN 'CROSS_USER_ESCALATION'
        ELSE 'self_rotation'
    END                              AS escalation_indicator
FROM   cloudtrail_logs
WHERE  eventtime >= DATE_FORMAT(NOW() - INTERVAL '24' HOUR, '%Y-%m-%dT%H:%i:%sZ')
  AND  eventsource = 'iam.amazonaws.com'
  AND  eventname = 'CreateAccessKey'
  AND  errorcode IS NULL
ORDER BY event_time DESC;


-- ─── QUERY 9: STS AssumeRole Chains — Lateral Movement ──────────────────────
-- Track role assumption chains — attackers hop through roles

SELECT
    useridentity.arn                                              AS from_principal,
    json_extract_scalar(requestparameters, '$.roleArn')           AS assumed_role,
    json_extract_scalar(requestparameters, '$.roleSessionName')   AS session_name,
    awsregion                                                     AS region,
    sourceipaddress                                               AS source_ip,
    eventtime                                                     AS event_time,
    COUNT(*) OVER (PARTITION BY useridentity.arn
                   ORDER BY eventtime
                   ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS cumulative_assumptions
FROM   cloudtrail_logs
WHERE  eventtime >= DATE_FORMAT(NOW() - INTERVAL '1' HOUR, '%Y-%m-%dT%H:%i:%sZ')
  AND  eventsource = 'sts.amazonaws.com'
  AND  eventname = 'AssumeRole'
  AND  errorcode IS NULL
ORDER BY from_principal, event_time;


-- ─── QUERY 10: Complete Attacker Timeline Reconstruction ─────────────────────
-- Given a known malicious ARN, reconstruct the full attack timeline

-- Replace 'arn:aws:iam::123456789012:user/suspicious-user' with actual ARN

SELECT
    eventtime          AS event_time,
    eventname          AS event_name,
    eventsource        AS service,
    awsregion          AS region,
    sourceipaddress    AS source_ip,
    useragent          AS user_agent,
    errorcode          AS error,
    requestparameters  AS request_details
FROM   cloudtrail_logs
WHERE  eventtime >= DATE_FORMAT(NOW() - INTERVAL '7' DAY, '%Y-%m-%dT%H:%i:%sZ')
  AND  (
        useridentity.arn  = 'arn:aws:iam::123456789012:user/suspicious-user'
     OR useridentity.accesskeyid = 'AKIAIOSFODNN7EXAMPLE'
  )
ORDER BY eventtime ASC;
