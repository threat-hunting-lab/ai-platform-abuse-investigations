-- Rate limit events summary: infra-level vs account-level enforcement.
SELECT
  CASE
    WHEN account_id = '' THEN 'infra'
    ELSE 'account'
  END AS scope,
  enforcement_action,
  COUNT(*) AS events,
  COUNT(DISTINCT asn) AS asns,
  COUNT(DISTINCT account_id) AS accounts
FROM rate_limit_events
GROUP BY 1,2
ORDER BY events DESC;
