-- 0005_99_attack_chain_rollup.sql
-- Executive summary: aggregate all campaigns with timeline reconstruction
-- Signal: Provides a complete narrative of each exfiltration campaign with
--         phase-by-phase timeline, total data volume, and evidence inventory.

WITH campaign_repo_access AS (
    SELECT
        campaign_id,
        employee_id,
        team,
        MIN(timestamp) AS first_malicious_access,
        MAX(timestamp) AS last_malicious_access,
        COUNT(*) AS malicious_access_events,
        COUNT(DISTINCT repository_id) AS repos_touched,
        ARRAY_AGG(DISTINCT repository_id) AS repos_list,
        SUM(bytes_transferred) AS total_bytes_accessed,
        COUNT(*) FILTER (WHERE action IN ('file_download', 'git_clone')) AS download_events,
        COUNT(*) FILTER (WHERE is_first_access) AS first_time_accesses,
        COUNT(DISTINCT sensitivity) AS sensitivity_levels_accessed,
        COUNT(*) FILTER (WHERE sensitivity = 'critical') AS critical_repo_accesses
    FROM read_parquet('${DATA}/model_repo_access.parquet')
    WHERE is_malicious = TRUE
    GROUP BY campaign_id, employee_id, team
),

campaign_uploads AS (
    SELECT
        campaign_id,
        employee_id,
        COUNT(*) AS upload_events,
        SUM(file_size_bytes) AS total_upload_bytes,
        ARRAY_AGG(DISTINCT destination) AS exfil_destinations,
        ARRAY_AGG(DISTINCT file_extension) AS file_types_exfiltrated,
        MIN(timestamp) AS first_upload,
        MAX(timestamp) AS last_upload,
        COUNT(*) FILTER (WHERE file_extension IN ('.bin', '.safetensors', '.pt', '.ckpt')) AS model_weight_files
    FROM read_parquet('${DATA}/file_transfers.parquet')
    WHERE is_malicious = TRUE
    GROUP BY campaign_id, employee_id
),

campaign_sessions AS (
    SELECT
        campaign_id,
        employee_id,
        COUNT(*) AS malicious_sessions,
        SUM(duration_minutes) AS total_session_minutes,
        COUNT(*) FILTER (WHERE is_off_hours) AS off_hours_sessions,
        COUNT(*) FILTER (WHERE is_weekend) AS weekend_sessions
    FROM read_parquet('${DATA}/auth_sessions.parquet')
    WHERE is_malicious = TRUE
    GROUP BY campaign_id, employee_id
)

SELECT
    cra.campaign_id,
    cra.employee_id,
    cra.team,
    -- Timeline
    cra.first_malicious_access AS campaign_start,
    COALESCE(cu.last_upload, cra.last_malicious_access) AS campaign_end,
    DATE_DIFF('day', cra.first_malicious_access, COALESCE(cu.last_upload, cra.last_malicious_access)) AS campaign_duration_days,
    -- Repo access evidence
    cra.malicious_access_events,
    cra.repos_touched,
    cra.repos_list,
    cra.first_time_accesses,
    cra.critical_repo_accesses,
    ROUND(cra.total_bytes_accessed / 1e9, 2) AS data_accessed_gb,
    -- Exfiltration evidence
    COALESCE(cu.upload_events, 0) AS upload_events,
    ROUND(COALESCE(cu.total_upload_bytes, 0) / 1e9, 2) AS data_exfiltrated_gb,
    cu.exfil_destinations,
    cu.file_types_exfiltrated,
    COALESCE(cu.model_weight_files, 0) AS model_weight_files_exfiled,
    -- Session evidence
    COALESCE(cs.malicious_sessions, 0) AS anomalous_sessions,
    COALESCE(cs.off_hours_sessions, 0) AS off_hours_sessions,
    COALESCE(cs.weekend_sessions, 0) AS weekend_sessions,
    ROUND(COALESCE(cs.total_session_minutes, 0) / 60.0, 1) AS total_session_hours,
    -- Summary
    'CONFIRMED_EXFILTRATION' AS assessment
FROM campaign_repo_access cra
LEFT JOIN campaign_uploads cu ON cra.campaign_id = cu.campaign_id AND cra.employee_id = cu.employee_id
LEFT JOIN campaign_sessions cs ON cra.campaign_id = cs.campaign_id AND cra.employee_id = cs.employee_id
ORDER BY cra.campaign_id;
