# python\generate_dns_events.py
"""
Generate synthetic DNS events for CASE-0003.

Applies dns_triage.py heuristics (suspicious TLD, keyword hit, entropy, rarity)
as structured columns for SQL-friendly detection queries.
"""

import argparse
import json
import math
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import yaml


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy for a string (from dns_triage.py)"""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def get_base_domain(fqdn: str) -> str | None:
    """
    Extract base domain: last two labels for normal domains.
    e.g. 'a.b.c.google.com' -> 'google.com'
    Returns None for IPs, empty, or single-label hosts.
    """
    if not isinstance(fqdn, str):
        return None
    
    fqdn = fqdn.strip().strip(".").lower()
    if not fqdn or "." not in fqdn:
        return None
    
    parts = fqdn.split(".")
    if len(parts) < 2:
        return None
    
    return ".".join(parts[-2:])


def has_keyword(domain: str, keywords: list) -> bool:
    """Check if domain contains any keyword indicators"""
    if not isinstance(domain, str):
        return False
    d = domain.lower()
    return any(k in d for k in keywords)


def score_domain(base_domain: str, tld: str, suspicious_tlds: set, keyword_indicators: list, entropy_threshold: float, weights: dict) -> dict:
    """
    Apply all heuristics to a domain and return flags + score.
    NOTE: rare_domain computed in 2nd pass, so not included here.
    """
    suspicious_tld = tld in suspicious_tlds
    keyword_hit = has_keyword(base_domain, keyword_indicators)
    
    # Entropy: remove dots before computing
    domain_no_dots = base_domain.replace(".", "")
    entropy = shannon_entropy(domain_no_dots)
    high_entropy = entropy > entropy_threshold
    
    # Compute partial score (rare_domain added later)
    score = (
        int(suspicious_tld) * weights.get("suspicious_tld", 2) +
        int(keyword_hit) * weights.get("keyword_hit", 3) +
        int(high_entropy) * weights.get("high_entropy", 1)
    )
    
    return {
        "suspicious_tld": suspicious_tld,
        "keyword_hit": keyword_hit,
        "high_entropy": high_entropy,
        "entropy": entropy,
        "score_partial": score,
    }


def generate_benign_dns(accounts_df, devices_df, config, rng):
    """Generate baseline benign DNS queries"""
    dns_cfg = config.get("dns_events", {})
    query_range = dns_cfg.get("benign_queries_per_account", [80, 400])
    benign_noise_rate = float(dns_cfg.get("benign_noise_rate", 0.10))
    
    suspicious_tlds = set(dns_cfg.get("suspicious_tlds", []))
    keyword_indicators = list(dns_cfg.get("keyword_indicators", []))
    entropy_threshold = float(dns_cfg.get("entropy_threshold", 3.5))
    weights = dns_cfg.get("score_weights", {})
    
    # Common benign domains
    benign_domains = [
        "google.com", "microsoft.com", "amazon.com", "apple.com",
        "facebook.com", "twitter.com", "linkedin.com", "github.com",
        "stackoverflow.com", "wikipedia.org", "youtube.com", "netflix.com",
        "cloudflare.com", "aws.amazon.com", "azure.microsoft.com",
    ]
    
    time_start = pd.to_datetime(config["generation"]["time_range_utc"]["start"], utc=True)
    time_end = pd.to_datetime(config["generation"]["time_range_utc"]["end"], utc=True)
    time_span_seconds = int((time_end - time_start).total_seconds())
    
    events = []
    
    for _, acct in accounts_df.iterrows():
        account_id = acct["account_id"]
        org_id = acct["org_id"]
        
        # Pick a primary device for this account
        device_fp = rng.choice(devices_df["device_fingerprint"].values)
        
        # Number of benign queries for this account
        n_queries = int(rng.integers(query_range[0], query_range[1] + 1))
        
        for _ in range(n_queries):
            # Timestamp
            ts = time_start + pd.Timedelta(seconds=int(rng.integers(0, time_span_seconds)))
            
            # Pick a benign domain
            base_domain = rng.choice(benign_domains)
            
            # Sometimes add subdomain
            if rng.random() < 0.3:
                subdomain = rng.choice(["www", "mail", "api", "cdn", "app", "portal"])
                host_raw = f"{subdomain}.{base_domain}"
            else:
                host_raw = base_domain
            
            tld = base_domain.split(".")[-1]
            
            # Apply heuristics
            flags = score_domain(base_domain, tld, suspicious_tlds, keyword_indicators, entropy_threshold, weights)
            
            # Benign noise: 10% trigger 1-2 heuristics randomly (false positive simulation)
            if rng.random() < benign_noise_rate:
                # Randomly flip 1-2 flags
                noise_flags = rng.choice(["suspicious_tld", "keyword_hit", "high_entropy"], size=rng.integers(1, 3), replace=False)
                for f in noise_flags:
                    if f in flags:
                        flags[f] = True
                # Recalculate score
                flags["score_partial"] = (
                    int(flags["suspicious_tld"]) * weights.get("suspicious_tld", 2) +
                    int(flags["keyword_hit"]) * weights.get("keyword_hit", 3) +
                    int(flags["high_entropy"]) * weights.get("high_entropy", 1)
                )
            
            events.append({
                "ts": ts,
                "org_id": org_id,
                "account_id": account_id,
                "device_fingerprint": device_fp,
                "host_raw": host_raw,
                "base_domain": base_domain,
                "tld": tld,
                "parent_domain": "",  # Will be filled in chain generation
                "suspicious_tld": flags["suspicious_tld"],
                "keyword_hit": flags["keyword_hit"],
                "high_entropy": flags["high_entropy"],
                "rare_domain": False,  # Will be computed in 2nd pass
                "score": flags["score_partial"],  # Will be updated after rare_domain
                "is_malicious": False,
            })
    
    return events


def generate_malicious_dns(accounts_df, devices_df, config, rng):
    """Generate malicious DNS queries with ground truth"""
    dns_cfg = config.get("dns_events", {})
    malicious_fraction = float(dns_cfg.get("malicious_fraction", 0.005))
    
    suspicious_tlds = set(dns_cfg.get("suspicious_tlds", []))
    keyword_indicators = list(dns_cfg.get("keyword_indicators", []))
    entropy_threshold = float(dns_cfg.get("entropy_threshold", 3.5))
    weights = dns_cfg.get("score_weights", {})
    
    time_start = pd.to_datetime(config["generation"]["time_range_utc"]["start"], utc=True)
    time_end = pd.to_datetime(config["generation"]["time_range_utc"]["end"], utc=True)
    time_span_seconds = int((time_end - time_start).total_seconds())
    
    # Estimate total benign events to determine malicious count
    avg_benign_per_account = np.mean(dns_cfg.get("benign_queries_per_account", [80, 400]))
    total_benign = int(len(accounts_df) * avg_benign_per_account)
    n_malicious = int(total_benign * malicious_fraction)
    
    events = []
    
    # Malicious domain generation patterns
    malicious_tlds = [t for t in suspicious_tlds if rng.random() < 0.7][:10]  # Focus on subset
    malicious_keywords = [k for k in keyword_indicators if rng.random() < 0.6][:8]
    
    for _ in range(n_malicious):
        # Pick random account
        acct = accounts_df.sample(n=1, random_state=int(rng.integers(0, 2**31 - 1))).iloc[0]
        account_id = acct["account_id"]
        org_id = acct["org_id"]
        
        device_fp = rng.choice(devices_df["device_fingerprint"].values)
        
        ts = time_start + pd.Timedelta(seconds=int(rng.integers(0, time_span_seconds)))
        
        # Generate malicious domain
        # Pattern: <keyword>-<random>.<suspicious_tld>
        keyword = rng.choice(malicious_keywords) if malicious_keywords else "secure"
        random_part = "".join(rng.choice(list("abcdefghijklmnopqrstuvwxyz0123456789")) for _ in range(rng.integers(8, 16)))
        tld = rng.choice(malicious_tlds) if malicious_tlds else "xyz"
        
        base_domain = f"{keyword}-{random_part}.{tld}"
        
        # Sometimes add subdomain
        if rng.random() < 0.4:
            subdomain = rng.choice(["login", "verify", "secure", "auth", "portal"])
            host_raw = f"{subdomain}.{base_domain}"
        else:
            host_raw = base_domain
        
        # Apply heuristics (should score high)
        flags = score_domain(base_domain, tld, suspicious_tlds, keyword_indicators, entropy_threshold, weights)
        
        events.append({
            "ts": ts,
            "org_id": org_id,
            "account_id": account_id,
            "device_fingerprint": device_fp,
            "host_raw": host_raw,
            "base_domain": base_domain,
            "tld": tld,
            "parent_domain": "",
            "suspicious_tld": flags["suspicious_tld"],
            "keyword_hit": flags["keyword_hit"],
            "high_entropy": flags["high_entropy"],
            "rare_domain": False,
            "score": flags["score_partial"],
            "is_malicious": True,
        })
    
    return events


def add_parent_domain_edges(events_df, config, rng):
    """
    Add parent_domain edges with coherence constraints:
    - Same account_id + device_fingerprint
    - Time-ordered (parent earlier than child)
    - Depth limited by max_chain_len
    """
    dns_cfg = config.get("dns_events", {})
    chain_prob = float(dns_cfg.get("chain_prob", 0.15))
    max_chain_len = int(dns_cfg.get("max_chain_len", 3))
    
    # Initialize parent_domain column
    events_df["parent_domain"] = ""
    
    # Group by account_id + device_fingerprint
    for (acct, dev), group in events_df.groupby(["account_id", "device_fingerprint"]):
        # Sort by time within group, keep ORIGINAL indices
        group_sorted = group.sort_values("ts")
        indices = group_sorted.index.tolist()
        domains = group_sorted["base_domain"].tolist()
        
        # Create chains using original indices
        for i in range(1, len(indices)):
            if rng.random() < chain_prob:
                # Parent must be earlier (depth limited)
                lookback = min(max_chain_len, i)
                parent_offset = int(rng.integers(1, lookback + 1))
                parent_idx = indices[i - parent_offset]
                parent_domain = domains[i - parent_offset]
                
                # Assign using original index
                events_df.at[indices[i], "parent_domain"] = parent_domain
    
    return events_df


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Path to YAML config (e.g., configs/case0003.yaml)")
    ap.add_argument("--data", required=True, help="Directory containing parquet outputs (e.g., datasets/output_case0003)")
    args = ap.parse_args()
    
    cfg_path = Path(args.config)
    data_dir = Path(args.data)
    
    if not cfg_path.exists():
        raise FileNotFoundError(f"config not found: {cfg_path}")
    if not data_dir.exists():
        raise FileNotFoundError(f"data dir not found: {data_dir}")
    
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    dns_cfg = cfg.get("dns_events", {}) or {}
    
    if not bool(dns_cfg.get("enabled", True)):
        print("[dns_events] disabled by config")
        return 0
    
    gen_seed = int((cfg.get("generation", {}) or {}).get("seed", 0))
    rng = np.random.default_rng(gen_seed + 3003)  # Unique seed offset for DNS
    
    # Load accounts and devices
    accounts_path = data_dir / "accounts.parquet"
    devices_path = data_dir / "devices.parquet"
    
    if not accounts_path.exists():
        raise FileNotFoundError(f"missing: {accounts_path}")
    if not devices_path.exists():
        raise FileNotFoundError(f"missing: {devices_path}")
    
    accounts = pd.read_parquet(accounts_path)
    devices = pd.read_parquet(devices_path)
    
    print(f"[dns_events] Loaded {len(accounts)} accounts, {len(devices)} devices")
    
    # PASS 1: Generate all events (benign + malicious)
    print("[dns_events] Generating benign DNS events...")
    benign_events = generate_benign_dns(accounts, devices, cfg, rng)
    
    print("[dns_events] Generating malicious DNS events...")
    malicious_events = generate_malicious_dns(accounts, devices, cfg, rng)
    
    # Combine
    all_events = benign_events + malicious_events
    df = pd.DataFrame(all_events)
    
    print(f"[dns_events] Generated {len(df)} total DNS events ({len(malicious_events)} malicious)")
    
    # PASS 2: Compute base_domain counts and set rare_domain flag
    print("[dns_events] Computing rare_domain flags (2-pass)...")
    domain_counts = df.groupby("base_domain").size().to_dict()
    rare_threshold = int(dns_cfg.get("rare_domain_threshold", 5))
    
    df["rare_domain"] = df["base_domain"].map(
        lambda d: domain_counts.get(d, 0) <= rare_threshold
    )
    
    # Update score with rare_domain weight
    rare_weight = dns_cfg.get("score_weights", {}).get("rare_domain", 1)
    df["score"] = df["score"] + df["rare_domain"].astype(int) * rare_weight
    
    # Add parent_domain edges (coherent chains)
    print("[dns_events] Adding parent_domain chains...")
    df = add_parent_domain_edges(df, cfg, rng)
    
    # Ensure UTC timestamps
    df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce")
    df = df.dropna(subset=["ts", "org_id", "account_id", "base_domain"])
    
    # Sort by timestamp for better query performance
    df = df.sort_values("ts").reset_index(drop=True)
    
    # Write output
    out_path = data_dir / "dns_events.parquet"
    df.to_parquet(out_path, index=False)
    
    # Write metadata
    meta = {
        "rows": int(len(df)),
        "malicious_fraction": float(dns_cfg.get("malicious_fraction", 0.005)),
        "malicious_events": int(df["is_malicious"].sum()),
        "benign_events": int((~df["is_malicious"]).sum()),
        "rare_domains": int(df["rare_domain"].sum()),
        "chains": int((df["parent_domain"] != "").sum()),
        "seed": gen_seed + 3003,
        "output": str(out_path),
    }
    (data_dir / "_dns_events_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    
    print(f"[dns_events] wrote: {out_path} (rows={len(df)})")
    print(f"[dns_events] meta:  {data_dir / '_dns_events_meta.json'}")
    print(f"[dns_events] Malicious: {meta['malicious_events']}, Chains: {meta['chains']}, Rare domains: {meta['rare_domains']}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
