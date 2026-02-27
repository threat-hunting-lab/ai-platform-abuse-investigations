-- 0005_04_repo_breadth_anomaly.sql
-- Detect employees accessing an unusually wide breadth of repositories
-- Signal: An insider preparing to leave often broadens their access pattern,
--         touching repos across multiple teams/projects they don't normally work with.
--         This "shopping" behavior is distinct from depth (volume) anomalies.

WITH weekly_breadth AS (
    SELECT
        employee_id,
        team,
        DATE_TRUNC('week', timestamp) AS week_start,
        COUNT(DISTINCT repository_id) AS distinct_repos,
        COUNT(DISTINCT sensitivity) AS distinct_sensitivity_levels,
        ARRAY_AGG(DISTINCT repository_id) AS repos_list,
        ARRAY_AGG(DISTINCT sensitivity) AS sensitivity_levels,
        COUNT(*) AS total_events,
        BOOL_OR(is_malicious) AS is_malicious
    FROM read_parquet('${DATA}/model_repo_access.parquet')
    GROUP BY employee_id, team, DATE_TRUNC('week', timestamp)
),

employee_breadth_baseline AS (
    SELECT
        employee_id,
        AVG(distinct_repos) AS avg_weekly_repos,
        STDDEV(distinct_repos) AS stddev_weekly_repos,
        MAX(distinct_repos) AS max_weekly_repos
    FROM weekly_breadth
    WHERE week_start < DATE '2025-11-10'  -- Baseline period
    GROUP BY employee_id
    HAVING COUNT(*) >= 1
),

scored_weeks AS (
    SELECT
        wb.employee_id,
        wb.team,
        wb.week_start,
        wb.distinct_repos,
        wb.distinct_sensitivity_levels,
        wb.repos_list,
        wb.total_events,
        b.avg_weekly_repos,
        b.max_weekly_repos,
        -- Breadth expansion ratio
        CASE
            WHEN b.avg_weekly_repos > 0
            THEN ROUND(wb.distinct_repos / b.avg_weekly_repos, 1)
            ELSE wb.distinct_repos
        END AS breadth_multiplier,
        -- New repos this week (not in baseline max)
        wb.distinct_repos - COALESCE(b.max_weekly_repos, 0) AS new_repos_above_max,
        wb.is_malicious
    FROM weekly_breadth wb
    LEFT JOIN employee_breadth_baseline b ON wb.employee_id = b.employee_id
    WHERE wb.week_start >= DATE '2025-11-10'
)

SELECT
    employee_id,
    team,
    week_start,
    distinct_repos,
    distinct_sensitivity_levels,
    repos_list,
    total_events,
    ROUND(avg_weekly_repos, 1) AS baseline_avg_repos,
    breadth_multiplier,
    new_repos_above_max,
    CASE
        WHEN breadth_multiplier >= 4 AND distinct_sensitivity_levels >= 3 THEN 'critical'
        WHEN breadth_multiplier >= 3 OR new_repos_above_max >= 3 THEN 'high'
        WHEN breadth_multiplier >= 2 OR new_repos_above_max >= 2 THEN 'medium'
        ELSE 'low'
    END AS risk_level,
    is_malicious
FROM scored_weeks
WHERE breadth_multiplier >= 2 OR new_repos_above_max >= 2
ORDER BY breadth_multiplier DESC, distinct_repos DESC;
