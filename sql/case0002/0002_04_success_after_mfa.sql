-- CASE-0002: First success sign-in after an MFA device add (possible persistence)

WITH mfa_add AS (
  SELECT
    org_id,
    account_id,
    ts AS mfa_ts,
    ip AS mfa_ip,
    asn AS mfa_asn,
    device_fingerprint AS mfa_device,
    campaign_id,
    is_attack
  FROM identity_events
  WHERE event_type = 'auth.mfa.add'
),
success AS (
  SELECT
    org_id,
    account_id,
    ts AS success_ts,
    ip AS success_ip,
    asn AS success_asn,
    device_fingerprint AS success_device
  FROM identity_events
  WHERE event_type = 'auth.signin' AND outcome = 'success'
),
paired AS (
  SELECT
    m.org_id,
    m.account_id,
    m.mfa_ts,
    s.success_ts,
    m.mfa_ip,
    m.mfa_asn,
    m.mfa_device,
    s.success_ip,
    s.success_asn,
    s.success_device,
    datediff('minute', m.mfa_ts, s.success_ts) AS minutes_after_mfa,
    m.campaign_id,
    m.is_attack,
    row_number() OVER (PARTITION BY m.org_id, m.account_id, m.mfa_ts ORDER BY s.success_ts) AS rn
  FROM mfa_add m
  JOIN success s
    ON s.org_id = m.org_id
   AND s.account_id = m.account_id
   AND s.success_ts BETWEEN m.mfa_ts AND (m.mfa_ts + INTERVAL '4 hours')
)
SELECT
  org_id,
  account_id,
  mfa_ts,
  success_ts,
  minutes_after_mfa,
  mfa_ip,
  mfa_asn,
  mfa_device,
  success_ip,
  success_asn,
  success_device,
  campaign_id,
  is_attack
FROM paired
WHERE rn = 1
ORDER BY minutes_after_mfa ASC, success_ts DESC, org_id, account_id;
