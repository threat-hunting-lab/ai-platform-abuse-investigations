-- 0005_06_correlated_exfil_chain.sql
-- Multi-signal correlation: combine repo access anomalies, volume spikes,
-- off-hours sessions, and personal cloud uploads into a unified risk score
-- Signal: Any single indicator may have innocent explanations. The combination of
--         new-repo access + volume spike + off-hours pattern + personal cloud upload
--         creates a high-confidence exfiltration chain detection.

WITH -- Signal 1: First-time access to sensitive repos
signal_new_repos AS (
    SELECT
        employee_id,
        COUNT(DISTINCT repository_id) AS new_sensitive_repos,
        SUM(CASE WHEN sensitivity = 'critical' THEN 3 WHEN sensitivity = 'high' THEN 2 ELSE 1 END) AS sensitivity_score
    FROM (
        SELECT
            employee_id,
            repository_id,
            sensitivity,
            MIN(timestamp) AS first_access
        FROM read_parquet('${DATA}/model_repo_access.parquet')
        WHERE sensitivity IN ('critical', 'high')
        GROUP BY employee_id, repository_id, sensitivity
        HAVING MIN(timestamp) >= TIMESTAMP '2025-11-10'  -- New access in investigation window
    )
    GROUP BY employee_id
),

-- Signal 2: Download volume anomaly (post-baseline)
signal_volume AS (
    SELECT
        employee_id,
        SUM(bytes_transferred) AS total_download_bytes,
        ROUND(SUM(bytes_transferred) / 1e9, 2) AS total_download_gb,
        COUNT(*) AS download_events,
        COUNT(DISTINCT DATE_TRUNC('day', timestamp)) AS active_download_days
    FROM read_parquet('${DATA}/model_repo_access.parquet')
    WHERE action IN ('file_download', 'git_clone')
      AND timestamp >= TIMESTAMP '2025-11-12'
      AND sensitivity IN ('critical', 'high')
    GROUP BY employee_id
),

-- Signal 3: Off-hours session anomaly
signal_off_hours AS (
    SELECT
        employee_id,
        COUNT(*) AS total_sessions,
        COUNT(*) FILTER (WHERE is_off_hours) AS off_hours_sessions,
        ROUND(COUNT(*) FILTER (WHERE is_off_hours) * 100.0 / NULLIF(COUNT(*), 0), 1) AS off_hours_pct,
        SUM(duration_minutes) FILTER (WHERE is_off_hours) AS off_hours_total_minutes
    FROM read_parquet('${DATA}/auth_sessions.parquet')
    WHERE timestamp >= TIMESTAMP '2025-11-12'
    GROUP BY employee_id
),

-- Signal 4: Personal cloud uploads
signal_personal_uploads AS (
    SELECT
        employee_id,
        COUNT(*) AS personal_upload_count,
        SUM(file_size_bytes) AS personal_upload_bytes,
        ROUND(SUM(file_size_bytes) / 1e9, 2) AS personal_upload_gb,
        COUNT(*) FILTER (WHERE file_extension IN ('.bin', '.safetensors', '.pt', '.ckpt', '.tar.gz')) AS model_file_uploads,
        ARRAY_AGG(DISTINCT destination) AS upload_destinations
    FROM read_parquet('${DATA}/file_transfers.parquet')
    WHERE is_personal_destination = TRUE
      AND transfer_type = 'upload'
    GROUP BY employee_id
),

-- Combine all signals
combined AS (
    SELECT
        e.employee_id,
        e.team,
        -- Signal scores (0-3 each)
        CASE
            WHEN COALESCE(nr.new_sensitive_repos, 0) >= 4 THEN 3
            WHEN COALESCE(nr.new_sensitive_repos, 0) >= 2 THEN 2
            WHEN COALESCE(nr.new_sensitive_repos, 0) >= 1 THEN 1
            ELSE 0
        END AS new_repo_score,
        CASE
            WHEN COALESCE(sv.total_download_gb, 0) >= 50 THEN 3
            WHEN COALESCE(sv.total_download_gb, 0) >= 10 THEN 2
            WHEN COALESCE(sv.total_download_gb, 0) >= 2 THEN 1
            ELSE 0
        END AS volume_score,
        CASE
            WHEN COALESCE(soh.off_hours_pct, 0) >= 50 THEN 3
            WHEN COALESCE(soh.off_hours_pct, 0) >= 30 THEN 2
            WHEN COALESCE(soh.off_hours_pct, 0) >= 15 THEN 1
            ELSE 0
        END AS off_hours_score,
        CASE
            WHEN COALESCE(spu.model_file_uploads, 0) >= 3 THEN 3
            WHEN COALESCE(spu.personal_upload_gb, 0) >= 5 THEN 3
            WHEN COALESCE(spu.personal_upload_count, 0) >= 3 THEN 2
            WHEN COALESCE(spu.personal_upload_count, 0) >= 1 THEN 1
            ELSE 0
        END AS personal_upload_score,
        -- Raw metrics for investigation
        COALESCE(nr.new_sensitive_repos, 0) AS new_sensitive_repos,
        COALESCE(nr.sensitivity_score, 0) AS sensitivity_score,
        COALESCE(sv.total_download_gb, 0) AS download_gb,
        COALESCE(sv.download_events, 0) AS download_events,
        COALESCE(soh.off_hours_sessions, 0) AS off_hours_sessions,
        COALESCE(soh.off_hours_pct, 0) AS off_hours_pct,
        COALESCE(spu.personal_upload_count, 0) AS personal_uploads,
        COALESCE(spu.personal_upload_gb, 0) AS personal_upload_gb,
        COALESCE(spu.model_file_uploads, 0) AS model_file_uploads,
        spu.upload_destinations
    FROM (
        SELECT DISTINCT employee_id, team
        FROM read_parquet('${DATA}/model_repo_access.parquet')
    ) e
    LEFT JOIN signal_new_repos nr ON e.employee_id = nr.employee_id
    LEFT JOIN signal_volume sv ON e.employee_id = sv.employee_id
    LEFT JOIN signal_off_hours soh ON e.employee_id = soh.employee_id
    LEFT JOIN signal_personal_uploads spu ON e.employee_id = spu.employee_id
),

scored AS (
    SELECT
        *,
        new_repo_score + volume_score + off_hours_score + personal_upload_score AS composite_score,
        -- Count how many distinct signal types fired
        (CASE WHEN new_repo_score > 0 THEN 1 ELSE 0 END +
         CASE WHEN volume_score > 0 THEN 1 ELSE 0 END +
         CASE WHEN off_hours_score > 0 THEN 1 ELSE 0 END +
         CASE WHEN personal_upload_score > 0 THEN 1 ELSE 0 END) AS signals_fired
    FROM combined
)

SELECT
    s.employee_id,
    s.team,
    s.composite_score,
    s.signals_fired,
    s.new_repo_score,
    s.volume_score,
    s.off_hours_score,
    s.personal_upload_score,
    s.new_sensitive_repos,
    s.download_gb,
    s.download_events,
    s.off_hours_sessions,
    s.off_hours_pct,
    s.personal_uploads,
    s.personal_upload_gb,
    s.model_file_uploads,
    s.upload_destinations,
    CASE
        WHEN s.composite_score >= 9 AND s.signals_fired >= 3 THEN 'critical'
        WHEN s.composite_score >= 6 AND s.signals_fired >= 2 THEN 'high'
        WHEN s.composite_score >= 4 THEN 'medium'
        ELSE 'low'
    END AS risk_level,
    -- Ground truth for evaluation
    COALESCE(gt.is_malicious, FALSE) AS is_malicious,
    gt.campaign_id
FROM scored s
LEFT JOIN (
    SELECT DISTINCT employee_id, TRUE AS is_malicious, campaign_id
    FROM read_parquet('${DATA}/model_repo_access.parquet')
    WHERE is_malicious = TRUE
) gt ON s.employee_id = gt.employee_id
WHERE s.composite_score >= 3
ORDER BY s.composite_score DESC, s.signals_fired DESC;
