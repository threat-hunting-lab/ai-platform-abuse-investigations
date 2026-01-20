-- 0002_02_new_asn_after_failures.sql
-- Find first-time (for that account) ASN success sign-ins shortly after a failure burst.

WITH failures AS (
  SELECT
    org_id,
    account_id,
    to_timestamp(floor(epoch(ts) / 600) * 600) AS bucket_start,
    count(*) AS failures_in_10m,
    min(ts) AS first_fail_ts,
    max(ts) AS last_fail_ts,
    any_value(ip) AS sample_fail_ip,
    any_value(asn) AS sample_fail_asn
  FROM identity_events
  WHERE event_type = 'auth.signin'
    AND outcome = 'failure'
  GROUP BY 1,2,3
),
bursts AS (
  SELECT *
  FROM failures
  WHERE failures_in_10m >= 6
),
success_signins AS (
  SELECT
    ts,
    org_id,
    account_id,
    ip,
    asn,
    device_fingerprint,
    user_agent,
    campaign_id,
    is_attack
  FROM identity_events
  WHERE event_type = 'auth.signin'
    AND outcome = 'success'
),
first_seen_success_asn AS (
  SELECT
    org_id,
    account_id,
    asn,
    min(ts) AS first_success_ts
  FROM success_signins
  GROUP BY 1,2,3
),
new_asn_success AS (
  SELECT
    s.*
  FROM success_signins s
  JOIN first_seen_success_asn f
    ON f.org_id = s.org_id
   AND f.account_id = s.account_id
   AND f.asn = s.asn
   AND f.first_success_ts = s.ts
)
SELECT
  b.org_id,
  b.account_id,
  b.bucket_start,
  b.failures_in_10m,
  b.first_fail_ts,
  b.last_fail_ts,
  b.sample_fail_ip,
  b.sample_fail_asn,
  s.ts AS success_ts,
  s.ip AS success_ip,
  s.asn AS success_asn,
  s.device_fingerprint,
  s.user_agent,
  s.campaign_id,
  s.is_attack
FROM bursts b
JOIN new_asn_success s
  ON s.org_id = b.org_id
 AND s.account_id = b.account_id
 AND s.ts BETWEEN b.last_fail_ts AND (b.last_fail_ts + INTERVAL '60 minutes')
 AND s.asn IS NOT NULL
ORDER BY b.failures_in_10m DESC, s.ts ASC;
