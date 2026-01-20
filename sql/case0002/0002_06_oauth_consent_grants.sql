-- 0002_06_oauth_consent_grants.sql
-- OAuth consent grants (often used to persist access) with recent successful sign-in context.

WITH grants AS (
  SELECT
    ts AS grant_ts,
    org_id,
    account_id,
    ip AS grant_ip,
    asn AS grant_asn,
    device_fingerprint,
    user_agent,
    campaign_id,
    is_attack
  FROM identity_events
  WHERE event_type = 'oauth.consent.grant'
),
recent_success AS (
  SELECT
    ts AS success_ts,
    org_id,
    account_id,
    ip AS success_ip,
    asn AS success_asn
  FROM identity_events
  WHERE event_type = 'auth.signin'
    AND outcome = 'success'
)
SELECT
  g.org_id,
  g.account_id,
  g.grant_ts,
  g.grant_ip,
  g.grant_asn,
  g.device_fingerprint,
  g.user_agent,
  s.success_ts,
  s.success_ip,
  s.success_asn,
  g.campaign_id,
  g.is_attack
FROM grants g
LEFT JOIN recent_success s
  ON s.org_id = g.org_id
 AND s.account_id = g.account_id
 AND s.success_ts BETWEEN (g.grant_ts - INTERVAL '30 minutes') AND g.grant_ts
ORDER BY g.grant_ts DESC;
