-- 0002_04_mailbox_rule_creations.sql

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
WHERE event_type = 'mailbox.rule.create'
ORDER BY ts DESC;
