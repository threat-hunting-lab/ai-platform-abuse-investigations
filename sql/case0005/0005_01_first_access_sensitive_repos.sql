-- 0005_01_first_access_sensitive_repos.sql
-- Detect employees accessing high/critical sensitivity repositories for the first time
-- Signal: First-time access to sensitive repos is a leading indicator of insider recon,
--         especially when an employee has no prior history with that repository.

WITH employee_repo_history AS (
    -- Establish each employee's first access to each repo
    SELECT
        employee_id,
        team,
        repository_id,
        sensitivity,
        MIN(timestamp) AS first_access_ts,
        COUNT(*) AS total_accesses
    FROM read_parquet('${DATA}/model_repo_access.parquet')
    GROUP BY employee_id, team, repository_id, sensitivity
),

first_access_to_sensitive AS (
    SELECT
        employee_id,
        team,
        repository_id,
        sensitivity,
        first_access_ts,
        total_accesses,
        -- Flag repos that are high/critical sensitivity
        CASE
            WHEN sensitivity = 'critical' THEN 3
            WHEN sensitivity = 'high' THEN 2
            ELSE 1
        END AS sensitivity_score
    FROM employee_repo_history
    WHERE sensitivity IN ('critical', 'high')
),

employee_new_repo_velocity AS (
    -- How many new sensitive repos did each employee first access per week?
    SELECT
        employee_id,
        team,
        DATE_TRUNC('week', first_access_ts) AS week_start,
        COUNT(DISTINCT repository_id) AS new_sensitive_repos_this_week,
        SUM(sensitivity_score) AS cumulative_sensitivity_score,
        ARRAY_AGG(DISTINCT repository_id) AS repos_accessed
    FROM first_access_to_sensitive
    GROUP BY employee_id, team, DATE_TRUNC('week', first_access_ts)
)

SELECT
    v.employee_id,
    v.team,
    v.week_start,
    v.new_sensitive_repos_this_week,
    v.cumulative_sensitivity_score,
    v.repos_accessed,
    -- Risk scoring: more new sensitive repos in a week = higher risk
    CASE
        WHEN v.new_sensitive_repos_this_week >= 4 AND v.cumulative_sensitivity_score >= 8 THEN 'critical'
        WHEN v.new_sensitive_repos_this_week >= 3 THEN 'high'
        WHEN v.new_sensitive_repos_this_week >= 2 THEN 'medium'
        ELSE 'low'
    END AS risk_level,
    -- Ground truth join for evaluation
    COALESCE(gt.is_malicious, FALSE) AS is_malicious
FROM employee_new_repo_velocity v
LEFT JOIN (
    SELECT DISTINCT employee_id, TRUE AS is_malicious
    FROM read_parquet('${DATA}/model_repo_access.parquet')
    WHERE is_malicious = TRUE
) gt ON v.employee_id = gt.employee_id
WHERE v.new_sensitive_repos_this_week >= 2
ORDER BY v.cumulative_sensitivity_score DESC, v.new_sensitive_repos_this_week DESC;
