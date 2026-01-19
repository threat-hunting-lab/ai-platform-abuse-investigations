#!/usr/bin/env python3
"""
Generate synthetic telemetry for CASE-0001 using a YAML config.

Writes parquet tables into datasets/output/ (or config output_dir):
- orgs.parquet
- accounts.parquet
- devices.parquet
- enrichment_ip.parquet
- sessions.parquet (optional)
- llm_requests.parquet
- moderation_events.parquet
- rate_limit_events.parquet (optional)
- osint_observations.parquet (optional)

No pandas required.
"""

from __future__ import annotations

import argparse
import math
import os
import random
import string
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml
import pyarrow as pa
import pyarrow.parquet as pq


# ----------------------------
# Utilities
# ----------------------------

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def parse_utc(ts: str) -> datetime:
    # Expect ISO like 2025-12-01T00:00:00Z
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)

def choose_weighted(rng: random.Random, weights: Dict[str, float]) -> str:
    keys = list(weights.keys())
    vals = [float(weights[k]) for k in keys]
    total = sum(vals)
    if total <= 0:
        return keys[0]
    x = rng.random() * total
    c = 0.0
    for k, w in zip(keys, vals):
        c += w
        if x <= c:
            return k
    return keys[-1]

def sample_int(rng: random.Random, lo_hi: Tuple[int, int]) -> int:
    lo, hi = int(lo_hi[0]), int(lo_hi[1])
    if hi < lo:
        lo, hi = hi, lo
    return rng.randint(lo, hi)

def rand_token(rng: random.Random, n: int = 10) -> str:
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def write_parquet(path: Path, table: pa.Table) -> None:
    ensure_dir(path.parent)
    pq.write_table(table, path)

def write_parquet_batches(path: Path, schema: pa.Schema, batches: Iterable[pa.RecordBatch], compression: str = "zstd") -> None:
    ensure_dir(path.parent)
    with pq.ParquetWriter(path, schema=schema, compression=compression) as writer:
        for batch in batches:
            writer.write_batch(batch)


# ----------------------------
# Core generation
# ----------------------------

@dataclass
class CampaignPlan:
    enabled: bool
    share_of_rows: float
    org_ids: List[str]
    account_ids: List[str]
    # Focused infra buckets
    focus_provider_buckets: List[str]
    provider_focus_strength: float
    asn_type_probs: Dict[str, float]
    # Similarity focus
    focus_cluster_ids: List[str]
    focus_template_ids: List[str]
    template_reuse_rate: float
    # Timing waves
    waves: List[Dict[str, Any]]
    bucket_minutes: int
    # Coordination & automation
    device_reuse_rate: float
    suspicious_device_bias: float  # probability to pick from suspicious device pool
    # Language probs
    lang_probs: Dict[str, float]
    ui_lang_probs: Dict[str, float]


def build_dimension_tables(cfg: Dict[str, Any], rng: random.Random) -> Dict[str, pa.Table]:
    """Create orgs, accounts, devices, enrichment_ip, (optional) sessions/osint dims."""
    out: Dict[str, pa.Table] = {}

    # ---- orgs ----
    org_count = int(cfg["entities"]["orgs"]["count"])
    org_prefix = cfg["entities"]["orgs"].get("id_prefix", "org_")
    size_dist = cfg["entities"]["orgs"]["size_distribution"]

    org_ids: List[str] = [f"{org_prefix}{i:04d}" for i in range(1, org_count + 1)]
    org_sizes: List[str] = [choose_weighted(rng, size_dist) for _ in range(org_count)]

    orgs = pa.table({
        "org_id": org_ids,
        "org_size_tier": org_sizes,
    })
    out["orgs"] = orgs

    # ---- accounts ----
    acct_count = int(cfg["entities"]["accounts"]["count"])
    acct_prefix = cfg["entities"]["accounts"].get("id_prefix", "acct_")
    per_org = cfg["entities"]["accounts"]["accounts_per_org"]

    # Allocate more accounts to larger orgs
    orgs_small = [o for o, s in zip(org_ids, org_sizes) if s == "small"]
    orgs_med = [o for o, s in zip(org_ids, org_sizes) if s == "medium"]
    orgs_large = [o for o, s in zip(org_ids, org_sizes) if s == "large"]

    def allocate_accounts(org_list: List[str], lo_hi: Tuple[int, int], remaining: int, bucket: List[Tuple[str, int]]) -> int:
        for o in org_list:
            if remaining <= 0:
                return 0
            n = min(sample_int(rng, lo_hi), remaining)
            bucket.append((o, n))
            remaining -= n
        return remaining

    allocations: List[Tuple[str, int]] = []
    remaining = acct_count
    remaining = allocate_accounts(orgs_small, tuple(per_org["small_range"]), remaining, allocations)
    remaining = allocate_accounts(orgs_med, tuple(per_org["medium_range"]), remaining, allocations)
    remaining = allocate_accounts(orgs_large, tuple(per_org["large_range"]), remaining, allocations)

    # If still remaining due to small org pool, distribute uniformly
    while remaining > 0:
        o = rng.choice(org_ids)
        allocations.append((o, 1))
        remaining -= 1

    account_ids: List[str] = []
    account_orgs: List[str] = []
    is_paid: List[bool] = []
    created_at: List[datetime] = []

    t0 = parse_utc(cfg["generation"]["time_range_utc"]["start"])
    # make created_at within 180 days prior to t0
    for idx, (org, n) in enumerate(allocations):
        for _ in range(n):
            account_ids.append(f"{acct_prefix}{len(account_ids)+1:06d}")
            account_orgs.append(org)
            is_paid.append(rng.random() < 0.22)  # simple; can be config-driven later
            created_at.append(t0 - timedelta(days=rng.randint(0, 180), hours=rng.randint(0, 23), minutes=rng.randint(0, 59)))

    accounts = pa.table({
        "account_id": account_ids,
        "org_id": account_orgs,
        "is_paid": is_paid,
        "created_at": pa.array(created_at, type=pa.timestamp("us", tz="UTC")),
    })
    out["accounts"] = accounts

    # ---- devices ----
    dev_count = int(cfg["entities"]["devices"]["count"])
    dev_prefix = cfg["entities"]["devices"].get("id_prefix", "dev_")

    mix = cfg["entities"]["devices"]["mix"]
    suspicious_traits = cfg["entities"]["devices"]["suspicious_device_traits"]

    device_ids: List[str] = [f"{dev_prefix}{i:06d}" for i in range(1, dev_count + 1)]
    is_suspicious: List[bool] = [rng.random() < float(mix.get("suspicious", 0.1)) for _ in range(dev_count)]

    browser_families = ["chrome", "firefox", "safari", "edge", "headless"]
    os_families = ["windows", "macos", "linux", "android", "ios"]

    is_headless: List[bool] = []
    browser_family: List[str] = []
    os_family: List[str] = []
    has_webdriver: List[bool] = []
    low_entropy_ua: List[bool] = []

    for susp in is_suspicious:
        if susp:
            is_headless.append(rng.random() < float(suspicious_traits.get("headless_rate", 0.55)))
            browser_family.append("headless" if is_headless[-1] else rng.choice(browser_families[:-1]))
            os_family.append(rng.choice(os_families))
            has_webdriver.append(rng.random() < float(suspicious_traits.get("webdriver_rate", 0.40)))
            low_entropy_ua.append(rng.random() < float(suspicious_traits.get("low_entropy_ua_rate", 0.35)))
        else:
            is_headless.append(False)
            browser_family.append(rng.choice(browser_families[:-1]))
            os_family.append(rng.choice(os_families))
            has_webdriver.append(False)
            low_entropy_ua.append(False)

    devices = pa.table({
        "device_fingerprint": device_ids,
        "is_headless": is_headless,
        "browser_family": browser_family,
        "os_family": os_family,
        "has_webdriver": has_webdriver,
        "low_entropy_ua": low_entropy_ua,
        "is_suspicious_device": is_suspicious,
    })
    out["devices"] = devices

    # ---- enrichment_ip (ASN dimension) ----
    infra = cfg["infra"]
    asn_pool_sizes = infra["asn_pool_sizes"]
    provider_brand = infra["provider_brand_buckets"]

    # ASN id space (integers)
    asn_rows: List[Dict[str, Any]] = []
    asn_base = 65000

    def gen_asn_type_rows(asn_type: str, count: int) -> None:
        nonlocal asn_base
        # Map asn_type -> provider_category choices
        if asn_type == "residential":
            categories = ["residential_isp"]
        elif asn_type == "corporate":
            categories = ["enterprise_egress"]
        elif asn_type == "hosting":
            categories = ["cloud_datacenter", "vps_hosting"]
        else:
            categories = ["vpn_service"]

        for _ in range(int(count)):
            asn_base += 1
            provider_category = rng.choice(categories)
            bucket = rng.choice(provider_brand[provider_category])
            # create a stable-ish synthetic IP prefix per ASN (not real)
            ip = f"198.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
            asn_rows.append({
                "asn": asn_base,
                "ip": ip,
                "asn_type": asn_type,
                "provider_category": provider_category,
                "provider_brand_bucket": bucket,
            })

    for asn_type, count in asn_pool_sizes.items():
        gen_asn_type_rows(asn_type, int(count))

    enrichment_ip = pa.Table.from_pylist(asn_rows)
    out["enrichment_ip"] = enrichment_ip

    # Optional sessions / osint placeholders will be created later if enabled
    return out


def build_campaign_plan(cfg: Dict[str, Any], rng: random.Random, dims: Dict[str, pa.Table]) -> CampaignPlan:
    campaigns = cfg.get("campaigns", [])
    if not campaigns:
        return CampaignPlan(False, 0.0, [], [], [], 0.0, {}, [], [], 0.0, [], 15, 0.0, 0.0, {}, {})

    c0 = campaigns[0]
    enabled = bool(c0.get("enabled", True))
    share = float(c0.get("share_of_rows", 0.0))

    org_ids = dims["orgs"]["org_id"].to_pylist()
    account_ids = dims["accounts"]["account_id"].to_pylist()

    # choose orgs/accounts touched by campaign
    org_min = int(c0["coordination"]["orgs_touched_min"])
    org_max = int(c0["coordination"]["orgs_touched_max"])
    acct_min = int(c0["coordination"]["accounts_touched_min"])
    acct_max = int(c0["coordination"]["accounts_touched_max"])

    touched_orgs = rng.sample(org_ids, k=min(len(org_ids), rng.randint(org_min, org_max)))
    touched_accounts = rng.sample(account_ids, k=min(len(account_ids), rng.randint(acct_min, acct_max)))

    infra_bias = c0["infra_bias"]
    focus_provider = list(infra_bias.get("provider_bucket_focus", []))
    focus_strength = float(infra_bias.get("provider_focus_strength", 0.8))
    asn_type_probs = dict(infra_bias.get("asn_type_probs", {}))

    similarity = c0["similarity"]
    # We’ll pick focused cluster/template IDs from generator-created pools later
    focus_top_k = int(similarity.get("focus_top_k_clusters", 3))
    template_reuse_rate = float(similarity.get("template_reuse_rate", 0.7))

    timing = c0["timing"]
    bucket_minutes = int(timing.get("bucket_minutes", 15))
    waves = list(timing.get("waves", []))

    device_reuse = float(c0["coordination"].get("device_reuse_rate", 0.2))
    suspicious_device_bias = 0.65  # campaign leans suspicious more often

    lang_probs = dict(c0.get("target_languages_primary_probs", {}))
    ui_lang_probs = dict(c0.get("target_ui_languages_probs", {}))

    # placeholders for focus clusters/templates, filled after pools are created
    return CampaignPlan(
        enabled=enabled,
        share_of_rows=share,
        org_ids=touched_orgs,
        account_ids=touched_accounts,
        focus_provider_buckets=focus_provider,
        provider_focus_strength=focus_strength,
        asn_type_probs=asn_type_probs,
        focus_cluster_ids=[],
        focus_template_ids=[],
        template_reuse_rate=template_reuse_rate,
        waves=waves,
        bucket_minutes=bucket_minutes,
        device_reuse_rate=device_reuse,
        suspicious_device_bias=suspicious_device_bias,
        lang_probs=lang_probs,
        ui_lang_probs=ui_lang_probs,
    )


def pick_ts_for_request(
    rng: random.Random,
    start: datetime,
    end: datetime,
    is_campaign: bool,
    plan: CampaignPlan,
    wave_base: datetime
) -> datetime:
    """Campaign traffic is concentrated into wave windows; baseline is uniform."""
    span_seconds = max(1, int((end - start).total_seconds()))

    if not is_campaign or not plan.enabled or not plan.waves:
        return start + timedelta(seconds=rng.randint(0, span_seconds - 1))

    # With high probability, place in a wave window
    if rng.random() < 0.80:
        wave = rng.choice(plan.waves)
        offset_h = float(wave["start_offset_hours"])
        dur_m = int(wave["duration_minutes"])
        wave_start = start + timedelta(hours=offset_h)
        wave_end = min(end, wave_start + timedelta(minutes=dur_m))
        if wave_end <= wave_start:
            return start + timedelta(seconds=rng.randint(0, span_seconds - 1))
        wspan = int((wave_end - wave_start).total_seconds())
        return wave_start + timedelta(seconds=rng.randint(0, max(1, wspan) - 1))

    # Otherwise, random time across the whole window
    return start + timedelta(seconds=rng.randint(0, span_seconds - 1))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Path to YAML config (e.g., configs/case0001.yaml)")
    ap.add_argument("--out", default=None, help="Output dir override (default from config generation.output_dir)")
    ap.add_argument("--rows", type=int, default=None, help="Row override for llm_requests (default from config generation.total_rows)")
    args = ap.parse_args()

    cfg_path = Path(args.config).resolve()
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))

    seed = int(cfg["generation"]["seed"])
    rng = random.Random(seed)

    out_dir = Path(args.out or cfg["generation"]["output_dir"]).resolve()
    ensure_dir(out_dir)

    total_rows = int(args.rows or cfg["generation"]["total_rows"])
    start = parse_utc(cfg["generation"]["time_range_utc"]["start"])
    end = parse_utc(cfg["generation"]["time_range_utc"]["end"])

    # 1) dimension tables
    dims = build_dimension_tables(cfg, rng)
    for name, table in dims.items():
        write_parquet(out_dir / f"{name}.parquet", table)

    # Pools for lookups
    org_ids = dims["orgs"]["org_id"].to_pylist()
    account_ids = dims["accounts"]["account_id"].to_pylist()
    account_org_map = dict(zip(dims["accounts"]["account_id"].to_pylist(), dims["accounts"]["org_id"].to_pylist()))

    device_ids = dims["devices"]["device_fingerprint"].to_pylist()
    suspicious_device_ids = [
        d for d, s in zip(dims["devices"]["device_fingerprint"].to_pylist(), dims["devices"]["is_suspicious_device"].to_pylist()) if s
    ] or device_ids

    enr = dims["enrichment_ip"]
    asns = enr["asn"].to_pylist()
    asn_type = enr["asn_type"].to_pylist()
    provider_cat = enr["provider_category"].to_pylist()
    provider_bucket = enr["provider_brand_bucket"].to_pylist()

    # index by asn_type and provider bucket for concentrated sampling
    by_asn_type: Dict[str, List[int]] = {}
    by_provider_bucket: Dict[str, List[int]] = {}
    for a, t, pb in zip(asns, asn_type, provider_bucket):
        by_asn_type.setdefault(t, []).append(a)
        by_provider_bucket.setdefault(pb, []).append(a)

    # 2) campaign plan (filled with focus clusters/templates)
    plan = build_campaign_plan(cfg, rng, dims)

    # Content pools
    content_cfg = cfg["content"]
    cluster_count = int(content_cfg["content_clusters"]["count"])
    cluster_prefix = content_cfg["content_clusters"].get("id_prefix", "CT-")
    cluster_ids = [f"{cluster_prefix}{i:02d}" for i in range(1, cluster_count + 1)]

    tmpl_count = int(content_cfg["templates"]["count"])
    tmpl_prefix = content_cfg["templates"].get("id_prefix", "T-")
    template_ids = [f"{tmpl_prefix}{i:02d}" for i in range(1, tmpl_count + 1)]

    # campaign focuses on top K clusters; pick K at random from cluster pool
    if plan.enabled:
        k = min(int(cfg["campaigns"][0]["similarity"].get("focus_top_k_clusters", 3)), len(cluster_ids))
        plan.focus_cluster_ids = rng.sample(cluster_ids, k=k)
        plan.focus_template_ids = template_ids[:]  # templates exist across langs; reuse controlled by rate

    # Language pools
    lang_fields = cfg["telemetry_schema"]["language_fields"]
    baseline_lang_probs = dict(lang_fields["baseline_primary_language_probs"])
    baseline_ui_probs = dict(lang_fields["baseline_ui_language_probs"])
    topic_buckets = list(cfg["content"]["topic_buckets"])
    baseline_topic_probs = dict(cfg["content"]["baseline_topic_probs"])

    model_probs = dict(cfg["models"]["baseline_model_probs"])
    model_names = list(cfg["models"]["model_names"])
    endpoints = ["chat", "completions", "tools"]

    # Moderation probs
    mod = cfg["moderation"]
    base_action = dict(mod["baseline_action_probs"])
    camp_action = dict(mod["campaign_action_probs"])
    policy_tags = ["benign", "suspicious_coordination", "automation_suspected", "policy_attention"]
    policy_scores = ["low", "med", "high"]

    # Rate limit config
    rl_cfg = cfg.get("rate_limits", {})
    rl_enabled = bool(rl_cfg.get("enabled", False))
    rl_base_prob = float(rl_cfg.get("baseline_rate_limit_prob", 0.0))
    rl_camp_prob = float(rl_cfg.get("campaign_rate_limit_prob", 0.0))
    rl_actions = list(rl_cfg.get("enforcement_actions", ["throttle", "temporary_block"]))
    rl_action_probs = dict(rl_cfg.get("enforcement_action_probs", {"throttle": 0.8, "temporary_block": 0.2}))

    # Sessions / OSINT
    sess_enabled = bool(cfg.get("sessions", {}).get("enabled", False))
    osint_enabled = bool(cfg.get("osint", {}).get("enabled", False))

    # 3) generate fact tables in batches (so 1M rows stays smooth)
    batch_size = 100_000
    batches = math.ceil(total_rows / batch_size)

    llm_schema = pa.schema([
        ("request_id", pa.string()),
        ("ts", pa.timestamp("us", tz="UTC")),
        ("org_id", pa.string()),
        ("account_id", pa.string()),
        ("device_fingerprint", pa.string()),
        ("ip", pa.string()),
        ("asn", pa.int64()),
        ("endpoint", pa.string()),
        ("model", pa.string()),
        ("prompt_tokens", pa.int32()),
        ("output_tokens", pa.int32()),
        ("language", pa.string()),
        ("ui_language", pa.string()),
        ("topic_bucket", pa.string()),
        ("template_hash", pa.string()),
        ("content_cluster_id", pa.string()),
        ("is_automation_suspected", pa.bool_()),
    ])

    mod_schema = pa.schema([
        ("request_id", pa.string()),
        ("ts", pa.timestamp("us", tz="UTC")),
        ("policy_action", pa.string()),
        ("policy_tag", pa.string()),
        ("policy_score", pa.string()),
    ])

    rl_schema = pa.schema([
        ("ts", pa.timestamp("us", tz="UTC")),
        ("asn", pa.int64()),
        ("account_id", pa.string()),  # '' means infra scope
        ("enforcement_action", pa.string()),
        ("window_seconds", pa.int32()),
        ("threshold", pa.int32()),
        ("observed", pa.int32()),
    ])

    # session schema is optional and light
    sess_schema = pa.schema([
        ("session_id", pa.string()),
        ("account_id", pa.string()),
        ("org_id", pa.string()),
        ("start_ts", pa.timestamp("us", tz="UTC")),
        ("auth_strength", pa.string()),
    ])

    osint_schema = pa.schema([
        ("content_cluster_id", pa.string()),
        ("platform_bucket", pa.string()),
        ("ts", pa.timestamp("us", tz="UTC")),
        ("observed_volume", pa.int32()),
        ("confidence_bucket", pa.string()),
        ("notes", pa.string()),
    ])

    # Writers
    llm_path = out_dir / "llm_requests.parquet"
    mod_path = out_dir / "moderation_events.parquet"
    rl_path = out_dir / "rate_limit_events.parquet"
    sess_path = out_dir / "sessions.parquet"
    osint_path = out_dir / "osint_observations.parquet"

    # Create session ids if enabled (small table, per-account-ish)
    if sess_enabled:
        auth_strengths = ["low", "medium", "strong"]
        sess_rows = []
        # 1 session for ~55% of accounts, plus some extra for campaign accounts
        for acct in account_ids:
            if rng.random() < 0.55 or (plan.enabled and acct in plan.account_ids and rng.random() < 0.80):
                sid = f"sess_{uuid.uuid4().hex[:16]}"
                org = account_org_map.get(acct, rng.choice(org_ids))
                s_ts = start - timedelta(hours=rng.randint(0, 24), minutes=rng.randint(0, 59))
                sess_rows.append({
                    "session_id": sid,
                    "account_id": acct,
                    "org_id": org,
                    "start_ts": s_ts,
                    "auth_strength": rng.choice(auth_strengths),
                })
        write_parquet(sess_path, pa.Table.from_pylist(sess_rows).cast(sess_schema))

    # Create OSINT obs if enabled (small, keyed to content clusters)
    if osint_enabled:
        os_cfg = cfg["osint"]
        platforms = list(os_cfg.get("platform_buckets", ["social_a", "forum_a"]))
        conf_probs = dict(os_cfg.get("confidence_probs", {"low": 0.6, "medium": 0.3, "high": 0.1}))
        obs_rate = float(os_cfg.get("observation_rate_per_cluster", 0.35))

        os_rows = []
        for cid in cluster_ids:
            if rng.random() < obs_rate:
                os_rows.append({
                    "content_cluster_id": cid,
                    "platform_bucket": rng.choice(platforms),
                    "ts": start + timedelta(hours=rng.randint(0, int((end - start).total_seconds() // 3600))),
                    "observed_volume": rng.randint(20, 700),
                    "confidence_bucket": choose_weighted(rng, conf_probs),
                    "notes": "Synthetic non-sensitive corroboration keyed to content_cluster_id.",
                })
        write_parquet(osint_path, pa.Table.from_pylist(os_rows).cast(osint_schema))

    # Helper: pick an ASN with campaign concentration
    infra_baseline_probs = dict(cfg["infra"]["baseline_asn_type_probs"])

    def pick_asn(is_campaign: bool) -> Tuple[int, str]:
        if is_campaign and plan.enabled:
            # choose ASN type based on campaign bias
            t = choose_weighted(rng, plan.asn_type_probs or {"hosting": 0.6, "vpn": 0.3, "residential": 0.1})
            # concentrate into focus provider buckets sometimes
            if plan.focus_provider_buckets and rng.random() < plan.provider_focus_strength:
                pb = rng.choice(plan.focus_provider_buckets)
                cand = by_provider_bucket.get(pb, [])
                if cand:
                    return rng.choice(cand), t
            cand = by_asn_type.get(t, [])
            if cand:
                return rng.choice(cand), t
        # baseline
        t = choose_weighted(rng, infra_baseline_probs)
        cand = by_asn_type.get(t, [])
        if cand:
            return rng.choice(cand), t
        return rng.choice(asns), "residential"

    # batch generators
    def llm_batches() -> Iterable[pa.RecordBatch]:
        for b in range(batches):
            n = batch_size if b < batches - 1 else (total_rows - batch_size * (batches - 1))

            req_id: List[str] = []
            ts: List[datetime] = []
            org: List[str] = []
            acct: List[str] = []
            dev: List[str] = []
            ip: List[str] = []
            asn_col: List[int] = []
            endpoint: List[str] = []
            model: List[str] = []
            ptoks: List[int] = []
            otoks: List[int] = []
            lang: List[str] = []
            ui_lang: List[str] = []
            topic: List[str] = []
            template_hash: List[str] = []
            cluster: List[str] = []
            auto_flag: List[bool] = []

            for _ in range(n):
                is_campaign = plan.enabled and (rng.random() < plan.share_of_rows)

                # ids
                rid = f"req_{uuid.uuid4().hex}"
                req_id.append(rid)

                # time
                t = pick_ts_for_request(rng, start, end, is_campaign, plan, start)
                ts.append(t)

                # org/account selection
                if is_campaign:
                    a = rng.choice(plan.account_ids)
                    o = account_org_map.get(a, rng.choice(plan.org_ids))
                    # push org towards touched set
                    if rng.random() < 0.65:
                        o = rng.choice(plan.org_ids)
                    # keep mapping consistent-ish
                    account_org_map[a] = o
                else:
                    a = rng.choice(account_ids)
                    o = account_org_map.get(a, rng.choice(org_ids))

                acct.append(a)
                org.append(o)

                # device selection (reuse higher in campaign)
                if is_campaign and rng.random() < plan.device_reuse_rate:
                    d = rng.choice(suspicious_device_ids if rng.random() < plan.suspicious_device_bias else device_ids)
                else:
                    d = rng.choice(device_ids)
                dev.append(d)

                # infra selection
                chosen_asn, _atype = pick_asn(is_campaign)
                asn_col.append(int(chosen_asn))

                # map ASN to a synthetic IP from enrichment table (stable per asn row)
                # build quick lookup by asn once (lazy init)
                # (small overhead, fine)
                idx = asns.index(chosen_asn)
                ip.append(str(enr["ip"][idx].as_py()))

                endpoint.append(rng.choice(endpoints))
                model_name = choose_weighted(rng, model_probs) if model_probs else rng.choice(model_names)
                model.append(model_name)

                # token lengths (simple but realistic-ish)
                ptoks.append(rng.randint(15, 280))
                otoks.append(rng.randint(20, 420))

                # language + UI language
                if is_campaign:
                    lp = plan.lang_probs or baseline_lang_probs
                    ulp = plan.ui_lang_probs or baseline_ui_probs
                else:
                    lp = baseline_lang_probs
                    ulp = baseline_ui_probs
                lang.append(choose_weighted(rng, lp))
                ui_lang.append(choose_weighted(rng, ulp))

                # topic
                topic.append(choose_weighted(rng, baseline_topic_probs))

                # similarity fields
                if is_campaign and plan.focus_cluster_ids:
                    # concentrate clusters
                    if rng.random() < 0.75:
                        cid = rng.choice(plan.focus_cluster_ids)
                    else:
                        cid = rng.choice(cluster_ids)
                    cluster.append(cid)

                    # template reuse strongly visible
                    if rng.random() < plan.template_reuse_rate:
                        tid = rng.choice(plan.focus_template_ids)
                    else:
                        tid = rng.choice(template_ids)
                else:
                    cid = rng.choice(cluster_ids)
                    tid = rng.choice(template_ids)
                    cluster.append(cid)

                # hash-like template id
                template_hash.append(f"tmpl_{tid}_{rand_token(rng, 8)}" if not is_campaign else f"tmpl_{tid}")

                # automation suspicion (campaign elevated)
                auto_flag.append(bool(is_campaign and rng.random() < 0.18) or (not is_campaign and rng.random() < 0.02))

            batch = pa.record_batch(
                [
                    pa.array(req_id, type=pa.string()),
                    pa.array(ts, type=pa.timestamp("us", tz="UTC")),
                    pa.array(org, type=pa.string()),
                    pa.array(acct, type=pa.string()),
                    pa.array(dev, type=pa.string()),
                    pa.array(ip, type=pa.string()),
                    pa.array(asn_col, type=pa.int64()),
                    pa.array(endpoint, type=pa.string()),
                    pa.array(model, type=pa.string()),
                    pa.array(ptoks, type=pa.int32()),
                    pa.array(otoks, type=pa.int32()),
                    pa.array(lang, type=pa.string()),
                    pa.array(ui_lang, type=pa.string()),
                    pa.array(topic, type=pa.string()),
                    pa.array(template_hash, type=pa.string()),
                    pa.array(cluster, type=pa.string()),
                    pa.array(auto_flag, type=pa.bool_()),
                ],
                schema=llm_schema,
            )
            yield batch

    # moderation events: 1 per request (keeps joins simple)
    def moderation_batches(llm_reader: pq.ParquetFile) -> Iterable[pa.RecordBatch]:
        for rg in range(llm_reader.num_row_groups):
            t = llm_reader.read_row_group(rg, columns=["request_id", "ts", "is_automation_suspected"])
            reqs = t.column("request_id").to_pylist()
            tss = t.column("ts").to_pylist()
            autos = t.column("is_automation_suspected").to_pylist()

            out_req: List[str] = []
            out_ts: List[datetime] = []
            act: List[str] = []
            tag: List[str] = []
            score: List[str] = []

            for rid, ts0, auto in zip(reqs, tss, autos):
                is_campaign = bool(auto)  # approx; campaign correlates with automation in this synthetic
                probs = camp_action if is_campaign else base_action
                a = choose_weighted(rng, probs)
                out_req.append(rid)
                out_ts.append(ts0)
                act.append(a)

                # tags/scores coarse; bias tags upward for warn/block
                if a == "allow":
                    tag.append("benign")
                    score.append("low")
                elif a == "warn":
                    tag.append(rng.choice(["policy_attention", "automation_suspected", "suspicious_coordination"]))
                    score.append(rng.choice(["low", "med"]))
                else:
                    tag.append(rng.choice(["suspicious_coordination", "automation_suspected"]))
                    score.append(rng.choice(["med", "high"]))

            batch = pa.record_batch(
                [
                    pa.array(out_req, type=pa.string()),
                    pa.array(out_ts, type=pa.timestamp("us", tz="UTC")),
                    pa.array(act, type=pa.string()),
                    pa.array(tag, type=pa.string()),
                    pa.array(score, type=pa.string()),
                ],
                schema=mod_schema,
            )
            yield batch

    # rate limit events (sparse)
    def rate_limit_batches(llm_reader: pq.ParquetFile) -> Iterable[pa.RecordBatch]:
        # Very lightweight: generate sparse events per row group
        for rg in range(llm_reader.num_row_groups):
            t = llm_reader.read_row_group(rg, columns=["ts", "asn", "account_id", "is_automation_suspected"])
            tss = t.column("ts").to_pylist()
            asn_vals = t.column("asn").to_pylist()
            acct_vals = t.column("account_id").to_pylist()
            autos = t.column("is_automation_suspected").to_pylist()

            out_ts: List[datetime] = []
            out_asn: List[int] = []
            out_acct: List[str] = []
            out_action: List[str] = []
            out_win: List[int] = []
            out_thr: List[int] = []
            out_obs: List[int] = []

            for ts0, a, acct, auto in zip(tss, asn_vals, acct_vals, autos):
                p = rl_camp_prob if auto else rl_base_prob
                if rng.random() < p:
                    # sometimes infra scope: blank account_id
                    infra_scope = auto and (rng.random() < 0.35)
                    out_ts.append(ts0)
                    out_asn.append(int(a))
                    out_acct.append("" if infra_scope else str(acct))
                    out_action.append(choose_weighted(rng, rl_action_probs) if rl_action_probs else rng.choice(rl_actions))
                    out_win.append(900)
                    out_thr.append(120 if not infra_scope else 2200)
                    out_obs.append(rng.randint(out_thr[-1], out_thr[-1] + 800))

            if not out_ts:
                continue

            batch = pa.record_batch(
                [
                    pa.array(out_ts, type=pa.timestamp("us", tz="UTC")),
                    pa.array(out_asn, type=pa.int64()),
                    pa.array(out_acct, type=pa.string()),
                    pa.array(out_action, type=pa.string()),
                    pa.array(out_win, type=pa.int32()),
                    pa.array(out_thr, type=pa.int32()),
                    pa.array(out_obs, type=pa.int32()),
                ],
                schema=rl_schema,
            )
            yield batch

    # Write llm_requests in batches
    write_parquet_batches(llm_path, llm_schema, llm_batches())

    # Build moderation + rate limits based on llm_requests parquet (streamed)
    llm_reader = pq.ParquetFile(llm_path)

    write_parquet_batches(mod_path, mod_schema, moderation_batches(llm_reader))

    if rl_enabled:
        write_parquet_batches(rl_path, rl_schema, rate_limit_batches(llm_reader))

    # Done marker (helps debugging)
    meta_path = out_dir / "_generation_meta.txt"
    meta_path.write_text(
        f"case_id={cfg['meta'].get('case_id','CASE-0001')}\n"
        f"generated_at_utc={utcnow_iso()}\n"
        f"rows_llm_requests={total_rows}\n"
        f"config={cfg_path.as_posix()}\n",
        encoding="utf-8"
    )

    print(f"[gen] wrote parquet tables to: {out_dir}")
    print(f"[gen] llm_requests rows: {total_rows}")
    print(f"[gen] meta: {meta_path}")

if __name__ == "__main__":
    main()
