-- 0005_02_off_hours_model_access.sql
-- Detect anomalous off-hours access to model weight repositories
-- Signal: Employees who suddenly begin accessing critical repos outside business hours
--         may be staging data for exfiltration when fewer eyes are watching.

WITH hourly_access AS (
    SELECT
        employee_id,
        team,
        repository_id,
        sensitivity,
        timestamp,
        EXTRACT(HOUR FROM timestamp) AS access_hour,
        EXTRACT(DOW FROM timestamp) AS day_of_week,
        -- Define off-hours: before 8am, after 7pm, or weekends
        CASE
            WHEN EXTRACT(DOW FROM timestamp) IN (0, 6) THEN TRUE
            WHEN EXTRACT(HOUR FROM timestamp) < 8 OR EXTRACT(HOUR FROM timestamp) >= 19 THEN TRUE
            ELSE FALSE
        END AS is_off_hours,
        bytes_transferred,
        is_malicious,
        campaign_id
    FROM read_parquet('${DATA}/model_repo_access.parquet')
    WHERE sensitivity IN ('critical', 'high')
),

employee_off_hours_pattern AS (
    SELECT
        employee_id,
        team,
        DATE_TRUNC('week', timestamp) AS week_start,
        COUNT(*) AS total_sensitive_accesses,
        COUNT(*) FILTER (WHERE is_off_hours) AS off_hours_accesses,
        ROUND(COUNT(*) FILTER (WHERE is_off_hours) * 100.0 / NULLIF(COUNT(*), 0), 1) AS off_hours_pct,
        SUM(bytes_transferred) AS total_bytes,
        SUM(bytes_transferred) FILTER (WHERE is_off_hours) AS off_hours_bytes,
        COUNT(DISTINCT repository_id) AS distinct_repos,
        ARRAY_AGG(DISTINCT repository_id) FILTER (WHERE is_off_hours) AS off_hours_repos,
        BOOL_OR(is_malicious) AS is_malicious
    FROM hourly_access
    GROUP BY employee_id, team, DATE_TRUNC('week', timestamp)
)

SELECT
    employee_id,
    team,
    week_start,
    total_sensitive_accesses,
    off_hours_accesses,
    off_hours_pct,
    ROUND(total_bytes / 1e9, 2) AS total_gb,
    ROUND(off_hours_bytes / 1e9, 2) AS off_hours_gb,
    distinct_repos,
    off_hours_repos,
    CASE
        WHEN off_hours_pct >= 60 AND off_hours_accesses >= 5 THEN 'critical'
        WHEN off_hours_pct >= 40 AND off_hours_accesses >= 3 THEN 'high'
        WHEN off_hours_pct >= 25 AND off_hours_accesses >= 2 THEN 'medium'
        ELSE 'low'
    END AS risk_level,
    is_malicious
FROM employee_off_hours_pattern
WHERE off_hours_accesses >= 2
  AND off_hours_pct >= 20
ORDER BY off_hours_pct DESC, off_hours_bytes DESC;
