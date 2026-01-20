-- 0002_99_ato_rollup.sql
-- Simple per-account rollup score from chain steps (self-contained)

WITH per_acct AS (
  SELECT
    org_id,
    account_id,
    max(CASE WHEN event_type='auth.signin' AND outcome='failure' THEN 1 ELSE 0 END) AS has_failures,
    max(CASE WHEN event_type='auth.signin' AND outcome='success' THEN 1 ELSE 0 END) AS has_success,
    max(CASE WHEN event_type='auth.mfa.add' THEN 1 ELSE 0 END) AS has_mfa_add,
    max(CASE WHEN event_type='mailbox.rule.create' THEN 1 ELSE 0 END) AS has_mailbox_rule,
    max(CASE WHEN event_type='oauth.consent.grant' THEN 1 ELSE 0 END) AS has_oauth_grant
  FROM identity_events
  GROUP BY 1,2
)
SELECT
  *,
  (has_mfa_add*30
   + has_mailbox_rule*25
   + has_oauth_grant*20
   + has_failures*10
   + has_success*5) AS risk_score
FROM per_acct
ORDER BY risk_score DESC, org_id, account_id;
