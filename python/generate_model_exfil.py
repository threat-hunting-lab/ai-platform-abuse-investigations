"""
CASE-0005: Model Weight Exfiltration via Insider Access
Synthetic telemetry generator

Generates three Parquet tables:
  - model_repo_access.parquet   : Repository access events (clone, pull, download)
  - file_transfers.parquet      : File download/upload events with sizes and destinations
  - auth_sessions.parquet       : Authentication sessions with timing and location

Ground truth labels:
  - is_malicious (bool)         : Whether this event is part of an exfiltration campaign
  - campaign_id (str|null)      : Which campaign this event belongs to
"""

import argparse
import hashlib
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import yaml


# ── helpers ──────────────────────────────────────────────────────────────────

def ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def random_ts(start: datetime, end: datetime) -> datetime:
    delta = (end - start).total_seconds()
    return start + timedelta(seconds=random.random() * delta)


def business_hours_ts(day: datetime) -> datetime:
    """Return a timestamp during business hours (9am-6pm) on the given day."""
    hour = random.randint(9, 17)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=second)


def off_hours_ts(day: datetime) -> datetime:
    """Return a timestamp outside business hours on the given day."""
    if random.random() < 0.5:
        hour = random.randint(0, 7)  # early morning
    else:
        hour = random.randint(19, 23)  # evening/night
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=second)


def generate_employee_id(team: str, index: int) -> str:
    return f"emp-{team[:3]}-{index:04d}"


def generate_ip(internal: bool = True) -> str:
    if internal:
        return f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return f"{random.randint(40, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


CLOUD_DESTINATIONS = [
    "personal-gdrive", "personal-dropbox", "personal-onedrive",
    "personal-icloud", "personal-mega", "personal-box"
]

CORPORATE_DESTINATIONS = [
    "corp-s3-backup", "corp-gcs-archive", "corp-artifact-registry",
    "internal-jupyter", "internal-notebook-server"
]

USER_AGENTS = [
    "git/2.43.0", "git-lfs/3.4.0", "dvc/3.30.1",
    "python-requests/2.31.0", "curl/8.4.0", "aws-cli/2.15.0",
    "gcloud/456.0.0", "hub-cli/0.24.0"
]


# ── employee population ─────────────────────────────────────────────────────

def build_employees(cfg: dict) -> list[dict]:
    employees = []
    for team_cfg in cfg["population"]["teams"]:
        team_name = team_cfg["name"]
        repo_access = team_cfg["repo_access"]
        for i in range(team_cfg["size"]):
            emp_id = generate_employee_id(team_name, i)
            employees.append({
                "employee_id": emp_id,
                "team": team_name,
                "authorized_repos": repo_access,
                "email": f"{emp_id}@company.internal",
                "typical_daily_downloads_gb": round(random.uniform(0.01, 1.0), 2),
                "work_start_hour": random.randint(8, 10),
                "work_end_hour": random.randint(17, 19),
            })
    return employees


# ── malicious actors ─────────────────────────────────────────────────────────

def select_malicious_actors(employees: list[dict], cfg: dict) -> dict:
    """Select employees to be malicious actors based on campaign configs."""
    actors = {}
    for campaign in cfg["campaigns"]:
        team = campaign["actor_team"]
        team_employees = [e for e in employees if e["team"] == team]
        selected = random.sample(team_employees, campaign["actor_count"])
        for emp in selected:
            actors[emp["employee_id"]] = {
                "campaign_id": campaign["id"],
                "campaign": campaign,
                "employee": emp,
            }
    return actors


# ── repository metadata ─────────────────────────────────────────────────────

def build_repo_metadata(cfg: dict) -> dict:
    repos = {}
    for sensitivity, repo_list in cfg["repositories"].items():
        for repo in repo_list:
            repos[repo["id"]] = {
                "sensitivity": repo.get("sensitivity", sensitivity),
                "avg_file_size_gb": repo["avg_file_size_gb"],
                "description": repo["description"],
            }
    return repos


# ── generate model_repo_access ───────────────────────────────────────────────

def generate_repo_access(employees, actors, repos, cfg) -> pd.DataFrame:
    start = datetime.fromisoformat(cfg["time_window"]["start"].replace("Z", "+00:00")).replace(tzinfo=None)
    end = datetime.fromisoformat(cfg["time_window"]["end"].replace("Z", "+00:00")).replace(tzinfo=None)
    days = (end - start).days
    records = []

    access_actions = ["git_clone", "git_pull", "file_download", "browse", "api_read"]

    # ── benign access ──
    for emp in employees:
        if emp["employee_id"] in actors:
            continue  # handle separately
        for day_offset in range(days):
            day = start + timedelta(days=day_offset)
            if day.weekday() >= 5 and random.random() < 0.85:
                continue  # most skip weekends

            num_accesses = random.randint(0, 6)
            for _ in range(num_accesses):
                repo_id = random.choice(emp["authorized_repos"])
                event_ts = business_hours_ts(day) if random.random() < 0.85 else off_hours_ts(day)
                repo_meta = repos.get(repo_id, {})

                records.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts(event_ts),
                    "employee_id": emp["employee_id"],
                    "team": emp["team"],
                    "repository_id": repo_id,
                    "sensitivity": repo_meta.get("sensitivity", "low"),
                    "action": random.choice(access_actions),
                    "bytes_transferred": int(random.uniform(1_000, repo_meta.get("avg_file_size_gb", 0.1) * 0.01 * 1e9)),
                    "source_ip": generate_ip(internal=True),
                    "user_agent": random.choice(USER_AGENTS),
                    "is_first_access": False,
                    "is_malicious": False,
                    "campaign_id": None,
                })

    # ── malicious access ──
    all_repo_ids = list(repos.keys())
    for actor_id, actor_info in actors.items():
        emp = actor_info["employee"]
        campaign = actor_info["campaign"]
        campaign_id = campaign["id"]
        timeline = campaign["timeline"]

        recon_start = datetime.fromisoformat(timeline["reconnaissance_start"])
        escalation_start = datetime.fromisoformat(timeline["escalation_start"])
        staging_start = datetime.fromisoformat(timeline["staging_start"])
        final_exfil = datetime.fromisoformat(timeline["final_exfil"])

        # Phase 1: Normal access (before recon) — blends with benign
        for day_offset in range((recon_start - start).days):
            day = start + timedelta(days=day_offset)
            if day.weekday() >= 5:
                continue
            for _ in range(random.randint(1, 4)):
                repo_id = random.choice(emp["authorized_repos"])
                event_ts = business_hours_ts(day)
                repo_meta = repos.get(repo_id, {})
                records.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts(event_ts),
                    "employee_id": actor_id,
                    "team": emp["team"],
                    "repository_id": repo_id,
                    "sensitivity": repo_meta.get("sensitivity", "low"),
                    "action": random.choice(access_actions),
                    "bytes_transferred": int(random.uniform(1_000, 50_000_000)),
                    "source_ip": generate_ip(internal=True),
                    "user_agent": random.choice(USER_AGENTS),
                    "is_first_access": False,
                    "is_malicious": False,
                    "campaign_id": None,
                })

        # Phase 2: Reconnaissance — browsing repos outside normal scope
        unauthorized_repos = [r for r in all_repo_ids if r not in emp["authorized_repos"]]
        sensitive_repos = [r for r in all_repo_ids if repos[r]["sensitivity"] in ("critical", "high")]
        target_repos = list(set(unauthorized_repos + sensitive_repos))

        for day_offset in range((escalation_start - recon_start).days):
            day = recon_start + timedelta(days=day_offset)
            # Browse 1-3 new repos per day
            for _ in range(random.randint(1, 3)):
                repo_id = random.choice(target_repos)
                event_ts = business_hours_ts(day) if random.random() < 0.6 else off_hours_ts(day)
                repo_meta = repos.get(repo_id, {})
                records.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts(event_ts),
                    "employee_id": actor_id,
                    "team": emp["team"],
                    "repository_id": repo_id,
                    "sensitivity": repo_meta.get("sensitivity", "low"),
                    "action": "browse",
                    "bytes_transferred": int(random.uniform(1_000, 5_000_000)),
                    "source_ip": generate_ip(internal=True),
                    "user_agent": random.choice(USER_AGENTS),
                    "is_first_access": True,
                    "is_malicious": True,
                    "campaign_id": campaign_id,
                })

        # Phase 3: Escalation — downloading model weights and configs
        for day_offset in range((staging_start - escalation_start).days):
            day = escalation_start + timedelta(days=day_offset)
            # Heavy downloads, often off-hours
            for _ in range(random.randint(3, 8)):
                repo_id = random.choice(sensitive_repos)
                event_ts = off_hours_ts(day) if random.random() < 0.7 else business_hours_ts(day)
                repo_meta = repos.get(repo_id, {})
                # Large downloads — full model shards
                bytes_xfer = int(repo_meta.get("avg_file_size_gb", 1) * random.uniform(0.1, 0.5) * 1e9)
                records.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts(event_ts),
                    "employee_id": actor_id,
                    "team": emp["team"],
                    "repository_id": repo_id,
                    "sensitivity": repo_meta.get("sensitivity", "high"),
                    "action": random.choice(["file_download", "git_clone"]),
                    "bytes_transferred": bytes_xfer,
                    "source_ip": generate_ip(internal=True),
                    "user_agent": random.choice(USER_AGENTS),
                    "is_first_access": False,
                    "is_malicious": True,
                    "campaign_id": campaign_id,
                })

        # Phase 4: Final exfiltration — massive last-day downloads
        for _ in range(random.randint(8, 15)):
            repo_id = random.choice(sensitive_repos)
            event_ts = off_hours_ts(final_exfil)
            repo_meta = repos.get(repo_id, {})
            bytes_xfer = int(repo_meta.get("avg_file_size_gb", 1) * random.uniform(0.3, 1.0) * 1e9)
            records.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": ts(event_ts),
                "employee_id": actor_id,
                "team": emp["team"],
                "repository_id": repo_id,
                "sensitivity": repo_meta.get("sensitivity", "high"),
                "action": "file_download",
                "bytes_transferred": bytes_xfer,
                "source_ip": generate_ip(internal=True),
                "user_agent": random.choice(USER_AGENTS),
                "is_first_access": False,
                "is_malicious": True,
                "campaign_id": campaign_id,
            })

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


# ── generate file_transfers ──────────────────────────────────────────────────

def generate_file_transfers(employees, actors, repos, cfg) -> pd.DataFrame:
    start = datetime.fromisoformat(cfg["time_window"]["start"].replace("Z", "+00:00")).replace(tzinfo=None)
    end = datetime.fromisoformat(cfg["time_window"]["end"].replace("Z", "+00:00")).replace(tzinfo=None)
    days = (end - start).days
    records = []

    transfer_types = ["download", "upload"]

    # ── benign transfers ──
    for emp in employees:
        if emp["employee_id"] in actors:
            continue
        for day_offset in range(days):
            day = start + timedelta(days=day_offset)
            if day.weekday() >= 5 and random.random() < 0.8:
                continue

            num_transfers = random.randint(0, 4)
            for _ in range(num_transfers):
                event_ts = business_hours_ts(day)
                transfer_type = "download" if random.random() < 0.8 else "upload"
                destination = random.choice(CORPORATE_DESTINATIONS) if transfer_type == "upload" else "local-workstation"
                file_size = int(random.uniform(1_000, 500_000_000))  # up to 500MB

                records.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts(event_ts),
                    "employee_id": emp["employee_id"],
                    "team": emp["team"],
                    "transfer_type": transfer_type,
                    "file_size_bytes": file_size,
                    "file_extension": random.choice([".py", ".json", ".yaml", ".ipynb", ".md", ".csv", ".parquet"]),
                    "destination": destination,
                    "source_repo": random.choice(emp["authorized_repos"]) if transfer_type == "download" else None,
                    "source_ip": generate_ip(internal=True),
                    "is_personal_destination": False,
                    "is_malicious": False,
                    "campaign_id": None,
                })

    # ── malicious transfers ──
    for actor_id, actor_info in actors.items():
        emp = actor_info["employee"]
        campaign = actor_info["campaign"]
        campaign_id = campaign["id"]
        timeline = campaign["timeline"]

        staging_start = datetime.fromisoformat(timeline["staging_start"])
        final_exfil = datetime.fromisoformat(timeline["final_exfil"])

        # Normal transfers before staging
        for day_offset in range((staging_start - start).days):
            day = start + timedelta(days=day_offset)
            if day.weekday() >= 5:
                continue
            for _ in range(random.randint(0, 3)):
                event_ts = business_hours_ts(day)
                records.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts(event_ts),
                    "employee_id": actor_id,
                    "team": emp["team"],
                    "transfer_type": "download",
                    "file_size_bytes": int(random.uniform(1_000, 100_000_000)),
                    "file_extension": random.choice([".py", ".json", ".yaml"]),
                    "destination": "local-workstation",
                    "source_repo": random.choice(emp["authorized_repos"]),
                    "source_ip": generate_ip(internal=True),
                    "is_personal_destination": False,
                    "is_malicious": False,
                    "campaign_id": None,
                })

        # Staging: uploads to personal cloud
        for day_offset in range((final_exfil - staging_start).days + 1):
            day = staging_start + timedelta(days=day_offset)
            num_uploads = random.randint(2, 6)
            for _ in range(num_uploads):
                event_ts = off_hours_ts(day)
                personal_dest = random.choice(CLOUD_DESTINATIONS)
                # Model weight chunks — large files
                file_size = int(random.uniform(500_000_000, 10_000_000_000))  # 500MB - 10GB
                records.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts(event_ts),
                    "employee_id": actor_id,
                    "team": emp["team"],
                    "transfer_type": "upload",
                    "file_size_bytes": file_size,
                    "file_extension": random.choice([".bin", ".safetensors", ".pt", ".ckpt", ".tar.gz"]),
                    "destination": personal_dest,
                    "source_repo": None,
                    "source_ip": generate_ip(internal=random.random() < 0.4),
                    "is_personal_destination": True,
                    "is_malicious": True,
                    "campaign_id": campaign_id,
                })

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


# ── generate auth_sessions ───────────────────────────────────────────────────

def generate_auth_sessions(employees, actors, cfg) -> pd.DataFrame:
    start = datetime.fromisoformat(cfg["time_window"]["start"].replace("Z", "+00:00")).replace(tzinfo=None)
    end = datetime.fromisoformat(cfg["time_window"]["end"].replace("Z", "+00:00")).replace(tzinfo=None)
    days = (end - start).days
    records = []

    auth_methods = ["sso", "mfa_push", "mfa_totp", "hardware_key"]

    # ── benign sessions ──
    for emp in employees:
        if emp["employee_id"] in actors:
            continue
        for day_offset in range(days):
            day = start + timedelta(days=day_offset)
            if day.weekday() >= 5 and random.random() < 0.7:
                continue

            # 1-3 sessions per day
            for _ in range(random.randint(1, 3)):
                event_ts = business_hours_ts(day)
                duration_hours = random.uniform(1, 9)
                records.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts(event_ts),
                    "employee_id": emp["employee_id"],
                    "team": emp["team"],
                    "session_type": "interactive",
                    "auth_method": random.choice(auth_methods),
                    "source_ip": generate_ip(internal=True),
                    "duration_minutes": int(duration_hours * 60),
                    "is_off_hours": False,
                    "is_weekend": day.weekday() >= 5,
                    "is_malicious": False,
                    "campaign_id": None,
                })

    # ── malicious sessions (off-hours access patterns) ──
    for actor_id, actor_info in actors.items():
        emp = actor_info["employee"]
        campaign = actor_info["campaign"]
        campaign_id = campaign["id"]
        timeline = campaign["timeline"]

        escalation_start = datetime.fromisoformat(timeline["escalation_start"])
        final_exfil = datetime.fromisoformat(timeline["final_exfil"])

        # Normal sessions before escalation
        for day_offset in range((escalation_start - start).days):
            day = start + timedelta(days=day_offset)
            if day.weekday() >= 5 and random.random() < 0.7:
                continue
            for _ in range(random.randint(1, 2)):
                event_ts = business_hours_ts(day)
                records.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts(event_ts),
                    "employee_id": actor_id,
                    "team": emp["team"],
                    "session_type": "interactive",
                    "auth_method": random.choice(auth_methods),
                    "source_ip": generate_ip(internal=True),
                    "duration_minutes": int(random.uniform(60, 480)),
                    "is_off_hours": False,
                    "is_weekend": day.weekday() >= 5,
                    "is_malicious": False,
                    "campaign_id": None,
                })

        # Anomalous sessions — off-hours, long duration, external IPs
        for day_offset in range((final_exfil - escalation_start).days + 1):
            day = escalation_start + timedelta(days=day_offset)
            # Multiple off-hours sessions
            for _ in range(random.randint(1, 3)):
                event_ts = off_hours_ts(day)
                use_external_ip = random.random() < 0.4
                records.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts(event_ts),
                    "employee_id": actor_id,
                    "team": emp["team"],
                    "session_type": "interactive",
                    "auth_method": random.choice(auth_methods),
                    "source_ip": generate_ip(internal=not use_external_ip),
                    "duration_minutes": int(random.uniform(120, 720)),  # 2-12 hours
                    "is_off_hours": True,
                    "is_weekend": day.weekday() >= 5,
                    "is_malicious": True,
                    "campaign_id": campaign_id,
                })

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate CASE-0005 synthetic telemetry")
    parser.add_argument("--config", required=True, help="Path to case0005.yaml")
    parser.add_argument("--out", required=True, help="Output directory for Parquet files")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Building employee population ({cfg['population']['total_employees']} employees)...")
    employees = build_employees(cfg)

    print("[*] Building repository metadata...")
    repos = build_repo_metadata(cfg)

    print(f"[*] Selecting malicious actors ({len(cfg['campaigns'])} campaigns)...")
    actors = select_malicious_actors(employees, cfg)
    for actor_id, info in actors.items():
        print(f"    → {actor_id} ({info['campaign_id']}): {info['campaign']['description']}")

    print("[*] Generating model_repo_access events...")
    repo_access_df = generate_repo_access(employees, actors, repos, cfg)
    repo_access_df.to_parquet(out_dir / "model_repo_access.parquet", index=False)
    print(f"    → {len(repo_access_df):,} events ({repo_access_df['is_malicious'].sum():,} malicious)")

    print("[*] Generating file_transfers events...")
    transfers_df = generate_file_transfers(employees, actors, repos, cfg)
    transfers_df.to_parquet(out_dir / "file_transfers.parquet", index=False)
    print(f"    → {len(transfers_df):,} events ({transfers_df['is_malicious'].sum():,} malicious)")

    print("[*] Generating auth_sessions events...")
    auth_df = generate_auth_sessions(employees, actors, cfg)
    auth_df.to_parquet(out_dir / "auth_sessions.parquet", index=False)
    print(f"    → {len(auth_df):,} events ({auth_df['is_malicious'].sum():,} malicious)")

    print(f"\n[✓] All datasets written to {out_dir}/")
    print(f"    Total events: {len(repo_access_df) + len(transfers_df) + len(auth_df):,}")


if __name__ == "__main__":
    main()
