-- 0003_99_rollup.sql
-- Summary + optional precision/recall evaluation (if is_malicious present)

WITH summary AS (
  SELECT
    COUNT(*) AS total_dns_events,
    COUNT(DISTINCT base_domain) AS distinct_domains,
    COUNT(DISTINCT account_id) AS distinct_accounts,
    SUM(CASE WHEN score > 0 THEN 1 ELSE 0 END) AS flagged_events,
    SUM(CASE WHEN is_malicious THEN 1 ELSE 0 END) AS malicious_events,
    SUM(CASE WHEN score > 0 AND is_malicious THEN 1 ELSE 0 END) AS true_positives,
    SUM(CASE WHEN score > 0 AND NOT is_malicious THEN 1 ELSE 0 END) AS false_positives,
    SUM(CASE WHEN score = 0 AND is_malicious THEN 1 ELSE 0 END) AS false_negatives
  FROM dns_events
),
metrics AS (
  SELECT
    *,
    CASE 
      WHEN (true_positives + false_positives) > 0 
      THEN ROUND(CAST(true_positives AS DOUBLE) / (true_positives + false_positives), 3)
      ELSE NULL
    END AS precision,
    CASE
      WHEN (true_positives + false_negatives) > 0
      THEN ROUND(CAST(true_positives AS DOUBLE) / (true_positives + false_negatives), 3)
      ELSE NULL
    END AS recall
  FROM summary
)
SELECT * FROM metrics;
