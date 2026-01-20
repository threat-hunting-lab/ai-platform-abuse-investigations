-- Device fingerprint reuse across accounts and orgs (signals shared automation).
SELECT
  r.device_fingerprint,
  d.is_headless,
  d.browser_family,
  d.os_family,
  COUNT(DISTINCT r.account_id) AS distinct_accounts,
  COUNT(DISTINCT r.org_id) AS distinct_orgs,
  COUNT(*) AS requests
FROM llm_requests r
LEFT JOIN devices d USING (device_fingerprint)
GROUP BY 1,2,3,4
HAVING COUNT(DISTINCT r.account_id) >= 5
ORDER BY distinct_orgs DESC, distinct_accounts DESC, requests DESC
LIMIT 300;
