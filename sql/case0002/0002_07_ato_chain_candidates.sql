-- 0002_07_ato_chain_candidates.sql
-- Roll up the ATO chain into one row per account (burst -> new ASN success -> MFA add -> mailbox rule / OAuth grant).

WITH failure_bursts AS (
  SELECT
    org_id,
    account_id,
    to_timestamp(floor(epoch(ts) / 600) * 600) AS bucket_start,
    count(*) AS failures_in_10m,
    min(ts) AS first_fail_ts,
    max(ts) AS last_fail_ts
  FROM identity_events
  WHERE event_type = 'auth.signin'
    AND outcome = 'failure'
  GROUP BY 1,2,3
  HAVING count(*) >= 6
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
  SELECT org_id, account_id, asn, min(ts) AS first_success_ts
  FROM success_signins
  GROUP BY 1,2,3
),
new_asn_success AS (
  SELECT s.*
  FROM success_signins s
  JOIN first_seen_success_asn f
    ON f.org_id = s.org_id
   AND f.account_id = s.account_id
   AND f.asn = s.asn
   AND f.first_success_ts = s.ts
),
burst_to_new_asn AS (
  SELECT
    b.org_id,
    b.account_id,
    b.bucket_start,
    b.failures_in_10m,
    b.first_fail_ts,
    b.last_fail_ts,
    s.ts AS new_asn_success_ts,
    s.ip AS new_asn_success_ip,
    s.asn AS new_asn_success_asn,
    s.device_fingerprint,
    s.user_agent,
    s.campaign_id,
    s.is_attack
  FROM failure_bursts b
  JOIN new_asn_success s
    ON s.org_id = b.org_id
   AND s.account_id = b.account_id
   AND s.ts BETWEEN b.last_fail_ts AND (b.last_fail_ts + INTERVAL '60 minutes')
),
mfa_add AS (
  SELECT
    org_id,
    account_id,
    min(ts) AS mfa_add_ts
  FROM identity_events
  WHERE event_type = 'auth.mfa.add'
  GROUP BY 1,2
),
mailbox_rule AS (
  SELECT
    org_id,
    account_id,
    min(ts) AS mailbox_rule_ts
  FROM identity_events
  WHERE event_type = 'mailbox.rule.create'
  GROUP BY 1,2
),
oauth_grant AS (
  SELECT
    org_id,
    account_id,
    min(ts) AS oauth_grant_ts
  FROM identity_events
  WHERE event_type = 'oauth.consent.grant'
  GROUP BY 1,2
),
per_acct AS (
  SELECT
    x.org_id,
    x.account_id,

    max(x.failures_in_10m) AS failures_in_10m,
    min(x.first_fail_ts) AS first_fail_ts,
    max(x.last_fail_ts) AS last_fail_ts,

    min(x.new_asn_success_ts) AS new_asn_success_ts,
    any_value(x.new_asn_success_ip) AS new_asn_success_ip,
    any_value(x.new_asn_success_asn) AS new_asn_success_asn,

    any_value(x.device_fingerprint) AS device_fingerprint,
    any_value(x.user_agent) AS user_agent,

    max(coalesce(x.is_attack, false)) AS is_attack,
    any_value(x.campaign_id) AS campaign_id
  FROM burst_to_new_asn x
  GROUP BY 1,2
)
SELECT
  p.*,
  m.mfa_add_ts,
  mb.mailbox_rule_ts,
  og.oauth_grant_ts,

  (m.mfa_add_ts IS NOT NULL)::INT AS has_mfa_add,
  (mb.mailbox_rule_ts IS NOT NULL)::INT AS has_mailbox_rule,
  (og.oauth_grant_ts IS NOT NULL)::INT AS has_oauth_grant,

  (
    10
    + 20
    + (CASE WHEN m.mfa_add_ts IS NOT NULL THEN 30 ELSE 0 END)
    + (CASE WHEN mb.mailbox_rule_ts IS NOT NULL THEN 30 ELSE 0 END)
    + (CASE WHEN og.oauth_grant_ts IS NOT NULL THEN 25 ELSE 0 END)
  ) AS risk_score
FROM per_acct p
LEFT JOIN mfa_add m
  ON m.org_id = p.org_id AND m.account_id = p.account_id
LEFT JOIN mailbox_rule mb
  ON mb.org_id = p.org_id AND mb.account_id = p.account_id
LEFT JOIN oauth_grant og
  ON og.org_id = p.org_id AND og.account_id = p.account_id
ORDER BY risk_score DESC, failures_in_10m DESC, new_asn_success_ts ASC;
