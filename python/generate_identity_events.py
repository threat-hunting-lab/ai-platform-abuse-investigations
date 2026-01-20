# python\generate_identity_events.py
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import yaml


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Path to YAML config (e.g., configs/case0002.yaml)")
    ap.add_argument("--data", required=True, help="Directory containing parquet outputs (e.g., datasets/output_case0002)")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    data_dir = Path(args.data)

    if not cfg_path.exists():
        raise FileNotFoundError(f"config not found: {cfg_path}")
    if not data_dir.exists():
        raise FileNotFoundError(f"data dir not found: {data_dir}")

    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    idcfg = cfg.get("identity_events", {}) or {}
    if not bool(idcfg.get("enabled", True)):
        print("[identity_events] disabled by config")
        return 0

    gen_seed = int((cfg.get("generation", {}) or {}).get("seed", 0))
    rng = np.random.default_rng(gen_seed + 2002)

    # Inputs
    accounts_path = data_dir / "accounts.parquet"
    sessions_path = data_dir / "sessions.parquet"
    enrich_path = data_dir / "enrichment_ip.parquet"
    if not accounts_path.exists():
        raise FileNotFoundError(f"missing: {accounts_path}")
    if not sessions_path.exists():
        raise FileNotFoundError(f"missing: {sessions_path}")
    if not enrich_path.exists():
        raise FileNotFoundError(f"missing: {enrich_path}")

    accounts = pd.read_parquet(accounts_path)
    sessions = pd.read_parquet(sessions_path)
    enrich = pd.read_parquet(enrich_path)

    # Basic sanity
    required_accounts = {"account_id", "org_id"}
    required_sessions = {"account_id", "org_id", "ip", "asn", "device_fingerprint", "start_ts"}
    missing_a = required_accounts - set(accounts.columns)
    missing_s = required_sessions - set(sessions.columns)
    if missing_a:
        raise ValueError(f"accounts missing columns: {sorted(missing_a)}")
    if missing_s:
        raise ValueError(f"sessions missing columns: {sorted(missing_s)}")

    # Normalize types
    accounts["account_id"] = accounts["account_id"].astype("string")
    accounts["org_id"] = accounts["org_id"].astype("string")

    sessions["account_id"] = sessions["account_id"].astype("string")
    sessions["org_id"] = sessions["org_id"].astype("string")
    sessions["ip"] = sessions["ip"].astype("string")
    sessions["device_fingerprint"] = sessions["device_fingerprint"].astype("string")
    sessions["start_ts"] = pd.to_datetime(sessions["start_ts"], utc=True, errors="coerce")
    sessions = sessions.dropna(subset=["start_ts", "account_id", "org_id", "ip", "asn", "device_fingerprint"])

    # Enrichment columns are "nice to have" — create empty defaults if absent (fixes your crash)
    if "asn" in enrich.columns:
        enrich["asn"] = pd.to_numeric(enrich["asn"], errors="coerce").astype("Int64")
    else:
        # If it's missing entirely, create it so downstream merges don't explode.
        enrich["asn"] = pd.Series(pd.array([pd.NA] * len(enrich), dtype="Int64"))

    for col in ["ip", "asn_type", "provider_category", "provider_brand_bucket"]:
        if col not in enrich.columns:
            enrich[col] = ""
        enrich[col] = enrich[col].astype("string")

    # Parameters used by the generator
    compromised_fraction = float(idcfg.get("compromised_fraction", 0.003))
    fb = idcfg.get("failure_burst", {}) or {}
    failure_min = int(fb.get("min_failures", 6))
    failure_max = int(fb.get("max_failures", 18))
    failure_min = max(1, failure_min)
    failure_max = max(failure_min, failure_max)

    # Choose compromised accounts
    unique_accounts = accounts[["org_id", "account_id"]].drop_duplicates()
    n_total = len(unique_accounts)
    n_comp = int(max(1, round(n_total * compromised_fraction)))
    n_comp = min(n_comp, n_total)
    comp = unique_accounts.sample(n=n_comp, random_state=int(rng.integers(0, 2**31 - 1)))

    # Precompute candidate "attack origins" from enrichment: bias to hosting/vpn when available
    # If those fields are blank, we still use the pool.
    enrich_pool = enrich.copy()
    enrich_pool = enrich_pool.dropna(subset=["ip", "asn"])
    enrich_pool = enrich_pool[enrich_pool["ip"].astype(str).str.len() > 0]
    if len(enrich_pool) == 0:
        raise ValueError("enrichment_ip has no usable rows (ip/asn)")

    # Prefer hosting/vpn-ish if present
    preferred = enrich_pool[
        enrich_pool["provider_category"].isin(["hosting", "vpn", "cloud", "edge"])
        | enrich_pool["asn_type"].isin(["hosting", "vpn", "cloud"])
    ]
    pool = preferred if len(preferred) >= 50 else enrich_pool

    # Build events
    events = []
    campaign_id = "ato_case0002"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36"

    # Add baseline “benign” signins from existing sessions (optional but keeps the table realistic)
    # We treat each session start as a success auth.signin.
    base = sessions[["start_ts", "org_id", "account_id", "ip", "asn", "device_fingerprint"]].copy()
    base.rename(columns={"start_ts": "ts"}, inplace=True)
    base["user_agent"] = ua
    base["event_type"] = "auth.signin"
    base["outcome"] = "success"
    base["campaign_id"] = ""
    base["is_attack"] = False
    events.append(base)

    # For each compromised account, anchor to an existing real session timestamp for that account if possible.
    for row in comp.itertuples(index=False):
        org_id = str(row.org_id)
        account_id = str(row.account_id)

        acct_sessions = sessions[(sessions["org_id"] == org_id) & (sessions["account_id"] == account_id)]
        if len(acct_sessions) == 0:
            # fallback: any session
            acct_sessions = sessions

        # pick an anchor session and re-use its device fingerprint (keeps it "B-lite" realistic)
        anchor_s = acct_sessions.sample(n=1, random_state=int(rng.integers(0, 2**31 - 1))).iloc[0]
        anchor_ts = pd.to_datetime(anchor_s["start_ts"], utc=True)
        device_fp = str(anchor_s["device_fingerprint"])

        # pick an attack origin (new IP/ASN) from pool
        cand = pool
        attack_origin = cand.sample(n=1, random_state=int(rng.integers(0, 2**31 - 1))).iloc[0]
        attack_ip = str(attack_origin["ip"])
        attack_asn = int(attack_origin["asn"])

        # failure burst leading into the success
        n_fail = int(rng.integers(failure_min, failure_max + 1))
        fail_offsets_min = np.sort(rng.integers(1, 10, size=n_fail))  # within 10 minutes pre-anchor
        fail_ts = [anchor_ts - pd.Timedelta(minutes=int(x)) for x in fail_offsets_min]

        fail_df = pd.DataFrame(
            {
                "ts": fail_ts,
                "org_id": org_id,
                "account_id": account_id,
                "ip": attack_ip,
                "asn": attack_asn,
                "device_fingerprint": device_fp,
                "user_agent": ua,
                "event_type": "auth.signin",
                "outcome": "failure",
                "campaign_id": campaign_id,
                "is_attack": True,
            }
        )

        # success from the new origin
        success_df = pd.DataFrame(
            [
                {
                    "ts": anchor_ts,
                    "org_id": org_id,
                    "account_id": account_id,
                    "ip": attack_ip,
                    "asn": attack_asn,
                    "device_fingerprint": device_fp,
                    "user_agent": ua,
                    "event_type": "auth.signin",
                    "outcome": "success",
                    "campaign_id": campaign_id,
                    "is_attack": True,
                }
            ]
        )

        # follow-on events (common ATO persistence / abuse actions)
        mfa_df = pd.DataFrame(
            [
                {
                    "ts": anchor_ts + pd.Timedelta(minutes=2),
                    "org_id": org_id,
                    "account_id": account_id,
                    "ip": attack_ip,
                    "asn": attack_asn,
                    "device_fingerprint": device_fp,
                    "user_agent": ua,
                    "event_type": "auth.mfa.add",
                    "outcome": "",
                    "campaign_id": campaign_id,
                    "is_attack": True,
                }
            ]
        )

        success2_df = pd.DataFrame(
            [
                {
                    "ts": anchor_ts + pd.Timedelta(minutes=10),
                    "org_id": org_id,
                    "account_id": account_id,
                    "ip": attack_ip,
                    "asn": attack_asn,
                    "device_fingerprint": device_fp,
                    "user_agent": ua,
                    "event_type": "auth.signin",
                    "outcome": "success",
                    "campaign_id": campaign_id,
                    "is_attack": True,
                }
            ]
        )

        mailbox_df = pd.DataFrame(
            [
                {
                    "ts": anchor_ts + pd.Timedelta(minutes=18),
                    "org_id": org_id,
                    "account_id": account_id,
                    "ip": attack_ip,
                    "asn": attack_asn,
                    "device_fingerprint": device_fp,
                    "user_agent": ua,
                    "event_type": "mailbox.rule.create",
                    "outcome": "",
                    "campaign_id": campaign_id,
                    "is_attack": True,
                }
            ]
        )

        oauth_df = pd.DataFrame(
            [
                {
                    "ts": anchor_ts + pd.Timedelta(minutes=25),
                    "org_id": org_id,
                    "account_id": account_id,
                    "ip": attack_ip,
                    "asn": attack_asn,
                    "device_fingerprint": device_fp,
                    "user_agent": ua,
                    "event_type": "oauth.consent.grant",
                    "outcome": "",
                    "campaign_id": campaign_id,
                    "is_attack": True,
                }
            ]
        )

        events.extend([fail_df, success_df, mfa_df, success2_df, mailbox_df, oauth_df])

    out = pd.concat(events, ignore_index=True)

    # Enforce UTC timestamps
    out["ts"] = pd.to_datetime(out["ts"], utc=True, errors="coerce")
    out = out.dropna(subset=["ts", "org_id", "account_id"])

    out_path = data_dir / "identity_events.parquet"
    out.to_parquet(out_path, index=False)

    meta = {
        "rows": int(len(out)),
        "compromised_fraction": compromised_fraction,
        "compromised_accounts": int(n_comp),
        "seed": gen_seed + 2002,
        "output": str(out_path),
    }
    (data_dir / "_identity_events_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[identity_events] wrote: {out_path} (rows={len(out)})")
    print(f"[identity_events] meta:  {data_dir / '_identity_events_meta.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
