-- 0003_04_heuristic_breakdown.sql
-- Histogram: how often each heuristic fired + score distribution

WITH flag_counts AS (
  SELECT
    'suspicious_tld' AS heuristic,
    SUM(CASE WHEN suspicious_tld THEN 1 ELSE 0 END) AS trigger_count
  FROM dns_events
  UNION ALL
  SELECT
    'keyword_hit',
    SUM(CASE WHEN keyword_hit THEN 1 ELSE 0 END)
  FROM dns_events
  UNION ALL
  SELECT
    'high_entropy',
    SUM(CASE WHEN high_entropy THEN 1 ELSE 0 END)
  FROM dns_events
  UNION ALL
  SELECT
    'rare_domain',
    SUM(CASE WHEN rare_domain THEN 1 ELSE 0 END)
  FROM dns_events
),
score_dist AS (
  SELECT
    score,
    COUNT(*) AS event_count,
    COUNT(DISTINCT account_id) AS account_count
  FROM dns_events
  GROUP BY score
)
SELECT * FROM flag_counts
UNION ALL
SELECT 
  'SCORE_DIST_' || CAST(score AS VARCHAR) AS heuristic,
  event_count AS trigger_count
FROM score_dist
ORDER BY heuristic;
