-- 0005_03_volume_anomaly_detection.sql
-- Detect employees whose download volumes spike far above their personal baseline
-- Signal: A departing insider who normally downloads <1GB/day suddenly pulling 10-50GB+
--         indicates systematic data hoarding prior to exfiltration.

WITH daily_volumes AS (
    SELECT
        employee_id,
        team,
        DATE_TRUNC('day', timestamp) AS access_date,
        SUM(bytes_transferred) AS daily_bytes,
        COUNT(*) AS daily_events,
        COUNT(DISTINCT repository_id) AS daily_repos,
        BOOL_OR(is_malicious) AS is_malicious
    FROM read_parquet('${DATA}/model_repo_access.parquet')
    WHERE action IN ('file_download', 'git_clone')
    GROUP BY employee_id, team, DATE_TRUNC('day', timestamp)
),

employee_baselines AS (
    -- Calculate each employee's baseline using the first 2 weeks (before most campaigns start)
    SELECT
        employee_id,
        AVG(daily_bytes) AS avg_daily_bytes,
        STDDEV(daily_bytes) AS stddev_daily_bytes,
        PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY daily_bytes) AS median_daily_bytes,
        MAX(daily_bytes) AS max_daily_bytes,
        COUNT(*) AS baseline_days
    FROM daily_volumes
    WHERE access_date < DATE '2025-11-12'  -- First 11 days as baseline
    GROUP BY employee_id
    HAVING COUNT(*) >= 3  -- Need at least 3 days for baseline
),

scored_days AS (
    SELECT
        dv.employee_id,
        dv.team,
        dv.access_date,
        ROUND(dv.daily_bytes / 1e9, 3) AS daily_gb,
        dv.daily_events,
        dv.daily_repos,
        ROUND(b.avg_daily_bytes / 1e9, 3) AS baseline_avg_gb,
        ROUND(b.median_daily_bytes / 1e9, 3) AS baseline_median_gb,
        -- Z-score: how many standard deviations above baseline
        CASE
            WHEN b.stddev_daily_bytes > 0
            THEN ROUND((dv.daily_bytes - b.avg_daily_bytes) / b.stddev_daily_bytes, 2)
            ELSE 0
        END AS z_score,
        -- Multiplier vs baseline
        CASE
            WHEN b.avg_daily_bytes > 0
            THEN ROUND(dv.daily_bytes / b.avg_daily_bytes, 1)
            ELSE 0
        END AS baseline_multiplier,
        dv.is_malicious
    FROM daily_volumes dv
    JOIN employee_baselines b ON dv.employee_id = b.employee_id
    WHERE dv.access_date >= DATE '2025-11-12'  -- Only score post-baseline period
)

SELECT
    employee_id,
    team,
    access_date,
    daily_gb,
    daily_events,
    daily_repos,
    baseline_avg_gb,
    baseline_median_gb,
    z_score,
    baseline_multiplier,
    CASE
        WHEN z_score >= 5 OR baseline_multiplier >= 20 THEN 'critical'
        WHEN z_score >= 3 OR baseline_multiplier >= 10 THEN 'high'
        WHEN z_score >= 2 OR baseline_multiplier >= 5 THEN 'medium'
        ELSE 'low'
    END AS risk_level,
    is_malicious
FROM scored_days
WHERE z_score >= 2 OR baseline_multiplier >= 5
ORDER BY z_score DESC, daily_gb DESC;
