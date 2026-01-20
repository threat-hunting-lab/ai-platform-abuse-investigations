from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import duckdb


# Core dimensions required by all cases
CORE_DIMS = ["enrichment_ip", "accounts", "orgs", "devices"]

# Case-specific fact tables
CASE_0001_REQUIRED = CORE_DIMS + ["llm_requests", "moderation_events"]
CASE_0002_REQUIRED = CORE_DIMS + ["identity_events"]


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_name(p: Path) -> str:
    # Turn "01_first_seen_hosting_asn.sql" -> "01_first_seen_hosting_asn"
    return re.sub(r"[^a-zA-Z0-9_\-]+", "_", p.stem)


def discover_parquet_tables(data_dir: Path) -> Dict[str, Path]:
    """
    Map parquet filenames to DuckDB table names:
      llm_requests.parquet -> llm_requests
      enrichment_ip.parquet -> enrichment_ip
      moderation_events.parquet -> moderation_events
      etc.
    """
    tables: Dict[str, Path] = {}
    for fp in sorted(data_dir.glob("*.parquet")):
        tables[fp.stem] = fp
    return tables


def load_parquet_to_duckdb(con: duckdb.DuckDBPyConnection, table: str, parquet_path: Path) -> None:
    # Use DuckDB's parquet scan; create a table
    con.execute(f"CREATE OR REPLACE TABLE {table} AS SELECT * FROM read_parquet('{parquet_path.as_posix()}');")


def discover_sql_files(sql_dir: Path) -> List[Path]:
    # sorted by filename so 01_, 02_... run in order
    return sorted([p for p in sql_dir.glob("*.sql") if p.is_file()])


def export_query_to_csv(
    con: duckdb.DuckDBPyConnection,
    sql_path: Path,
    out_csv: Path,
) -> Tuple[int, List[str]]:
    """
    Runs SQL and exports to CSV.
    Returns (row_count, column_names).
    """
    sql = sql_path.read_text(encoding="utf-8").strip()
    if not sql:
        # empty sql file -> export empty
        out_csv.write_text("", encoding="utf-8")
        return (0, [])

    # Execute and fetch
    rel = con.sql(sql)
    df = rel.df()  # small enough for exported artifacts; you can swap to rel.arrow() later
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_csv, index=False)
    return (len(df), list(df.columns))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--duckdb", required=True, help="Path to duckdb file (e.g., ai_abuse.duckdb)")
    ap.add_argument("--data", required=True, help="Directory containing parquet outputs (e.g., datasets/output)")
    ap.add_argument("--sql", required=True, help="SQL directory (e.g., sql/case0001, sql/case0002)")
    ap.add_argument("--case-dir", required=True, help="Case dir (e.g., case_studies/CASE-0001-coordinated-influence)")
    ap.add_argument("--strict", action="store_true", help="Fail if required tables are missing")
    args = ap.parse_args()

    db_path = Path(args.duckdb).resolve()
    data_dir = Path(args.data).resolve()
    sql_dir = Path(args.sql).resolve()
    case_dir = Path(args.case_dir).resolve()

    artifacts_dir = case_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    if not data_dir.exists():
        raise FileNotFoundError(f"data dir does not exist: {data_dir}")

    parquet_tables = discover_parquet_tables(data_dir)

    # Connect
    con = duckdb.connect(str(db_path))
    con.execute("PRAGMA threads=4;")

    # Load parquet tables
    loaded_tables: List[str] = []
    for tname, fpath in parquet_tables.items():
        load_parquet_to_duckdb(con, tname, fpath)
        loaded_tables.append(tname)

    # Determine required tables based on SQL directory (case-aware)
    if "case0002" in str(sql_dir).lower():
        required_tables = CASE_0002_REQUIRED
    else:
        required_tables = CASE_0001_REQUIRED
    
    # Sanity checks
    missing_required = [t for t in required_tables if t not in loaded_tables]
    if missing_required and args.strict:
        raise RuntimeError(f"Missing required parquet tables: {missing_required}. Found: {loaded_tables}")

    # Also create helpful views if optional tables absent (so SQL can still run)
    if "sessions" not in loaded_tables:
        con.execute("CREATE OR REPLACE VIEW sessions AS SELECT NULL::VARCHAR AS session_id, NULL::VARCHAR AS account_id, NULL::VARCHAR AS org_id, NULL::TIMESTAMP AS start_ts, NULL::VARCHAR AS auth_strength WHERE 1=0;")
    if "rate_limit_events" not in loaded_tables:
        con.execute("CREATE OR REPLACE VIEW rate_limit_events AS SELECT NULL::TIMESTAMP AS ts, NULL::BIGINT AS asn, NULL::VARCHAR AS account_id, NULL::VARCHAR AS enforcement_action, NULL::INT AS window_seconds, NULL::INT AS threshold, NULL::INT AS observed WHERE 1=0;")
    if "osint_observations" not in loaded_tables:
        con.execute("CREATE OR REPLACE VIEW osint_observations AS SELECT NULL::VARCHAR AS content_cluster_id, NULL::VARCHAR AS platform_bucket, NULL::TIMESTAMP AS ts, NULL::INT AS observed_volume, NULL::VARCHAR AS confidence_bucket, NULL::VARCHAR AS notes WHERE 1=0;")

    # Collect row counts for findings.json
    table_row_counts: Dict[str, int] = {}
    for t in loaded_tables:
        try:
            n = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            table_row_counts[t] = int(n)
        except Exception:
            table_row_counts[t] = -1

    # Run SQL files
    sql_files = discover_sql_files(sql_dir)
    if not sql_files:
        # List available case folders as a hint
        sql_parent = sql_dir.parent if sql_dir.name.startswith("case") else sql_dir
        case_folders = sorted([d.name for d in sql_parent.glob("case*") if d.is_dir()])
        hint = f"\nAvailable SQL directories: {', '.join(case_folders)}" if case_folders else ""
        raise FileNotFoundError(f"No SQL files found in {sql_dir}{hint}")

    artifacts: List[Dict] = []
    errors: List[Dict] = []

    for sql_path in sql_files:
        base = safe_name(sql_path)
        out_csv = artifacts_dir / f"{base}.csv"
        try:
            row_count, cols = export_query_to_csv(con, sql_path, out_csv)
            artifacts.append({
                "sql_file": str(sql_path.relative_to(Path.cwd())) if sql_path.is_absolute() else str(sql_path),
                "artifact_csv": str(out_csv.relative_to(case_dir)),
                "rows": row_count,
                "columns": cols,
            })
            print(f"[query] {sql_path.name} -> {out_csv.name} ({row_count} rows)")
        except Exception as e:
            errors.append({
                "sql_file": sql_path.name,
                "error": repr(e),
            })
            print(f"[query][ERROR] {sql_path.name}: {e}")

    # Write findings.json
    findings = {
        "case_id": case_dir.name,
        "generated_at_utc": utcnow_iso(),
        "duckdb_path": str(db_path),
        "data_dir": str(data_dir),
        "tables_row_counts": table_row_counts,
        "artifacts": artifacts,
        "errors": errors,
    }

    (case_dir / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[findings] wrote {case_dir / 'findings.json'}")
    if errors:
        print(f"[findings] completed with {len(errors)} SQL errors (see findings.json)")

    con.close()


if __name__ == "__main__":
    main()
