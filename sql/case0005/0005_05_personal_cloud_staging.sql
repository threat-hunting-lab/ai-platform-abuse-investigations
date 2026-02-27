-- 0005_05_personal_cloud_staging.sql
-- Detect uploads to personal cloud storage destinations, especially large files
-- Signal: Employees staging proprietary data (model weights, training configs) to
--         personal Google Drive, Dropbox, OneDrive, or similar services is a
--         high-confidence exfiltration indicator, especially for model-weight-sized files.

WITH personal_uploads AS (
    SELECT
        employee_id,
        team,
        timestamp,
        file_size_bytes,
        file_extension,
        destination,
        source_ip,
        is_malicious,
        campaign_id,
        -- Classify file type
        CASE
            WHEN file_extension IN ('.bin', '.safetensors', '.pt', '.ckpt') THEN 'model_weights'
            WHEN file_extension IN ('.tar.gz', '.zip', '.7z') THEN 'archive'
            WHEN file_extension IN ('.yaml', '.json', '.py') THEN 'config_code'
            WHEN file_extension IN ('.parquet', '.csv', '.jsonl') THEN 'dataset'
            ELSE 'other'
        END AS file_category
    FROM read_parquet('${DATA}/file_transfers.parquet')
    WHERE is_personal_destination = TRUE
      AND transfer_type = 'upload'
),

employee_upload_summary AS (
    SELECT
        employee_id,
        team,
        DATE_TRUNC('day', timestamp) AS upload_date,
        COUNT(*) AS upload_count,
        SUM(file_size_bytes) AS total_bytes,
        COUNT(*) FILTER (WHERE file_category = 'model_weights') AS model_weight_uploads,
        COUNT(*) FILTER (WHERE file_category = 'archive') AS archive_uploads,
        SUM(file_size_bytes) FILTER (WHERE file_category = 'model_weights') AS model_weight_bytes,
        ARRAY_AGG(DISTINCT destination) AS destinations_used,
        ARRAY_AGG(DISTINCT file_extension) AS file_types,
        -- Off-hours uploads
        COUNT(*) FILTER (
            WHERE EXTRACT(HOUR FROM timestamp) < 8
               OR EXTRACT(HOUR FROM timestamp) >= 19
               OR EXTRACT(DOW FROM timestamp) IN (0, 6)
        ) AS off_hours_uploads,
        BOOL_OR(is_malicious) AS is_malicious
    FROM personal_uploads
    GROUP BY employee_id, team, DATE_TRUNC('day', timestamp)
)

SELECT
    employee_id,
    team,
    upload_date,
    upload_count,
    ROUND(total_bytes / 1e9, 2) AS total_gb,
    model_weight_uploads,
    archive_uploads,
    ROUND(model_weight_bytes / 1e9, 2) AS model_weight_gb,
    destinations_used,
    file_types,
    off_hours_uploads,
    CASE
        WHEN model_weight_uploads >= 1 AND total_bytes > 1e9 THEN 'critical'
        WHEN total_bytes > 5e8 AND off_hours_uploads >= 1 THEN 'high'
        WHEN upload_count >= 3 THEN 'medium'
        ELSE 'low'
    END AS risk_level,
    is_malicious
FROM employee_upload_summary
ORDER BY total_bytes DESC, model_weight_uploads DESC;
