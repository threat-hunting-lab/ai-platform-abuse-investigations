-- 0002_03_mfa_device_adds.sql

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
WHERE event_type = 'auth.mfa.add'
ORDER BY ts DESC;
