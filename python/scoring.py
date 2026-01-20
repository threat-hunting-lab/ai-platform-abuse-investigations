from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CASE_DEFAULT = "CASE-0001-coordinated-influence"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def safe_float(v: Any) -> Optional[float]:
    try:
        if v is None:
            return None
        if isinstance(v, (int, float)):
            return float(v)
        s = str(v).strip()
        if s == "":
            return None
        return float(s)
    except Exception:
        return None


def safe_int(v: Any) -> Optional[int]:
    f = safe_float(v)
    return None if f is None else int(f)


def load_csv_rows(path: Path) -> List[Dict[str, Any]]:
    """
    Loads a CSV as list[dict]. Uses pandas if present; otherwise csv module.
    """
    try:
        import pandas as pd  # type: ignore

        df = pd.read_csv(path)
        return df.to_dict(orient="records")
    except Exception:
        with path.open("r", encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))


@dataclass
class Signal:
    id: str
    title: str
    weight: float
    score_0_1: float
    rationale: str
    evidence: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "weight": self.weight,
            "score": round(self.score_0_1 * 100, 1),
            "rationale": self.rationale,
            "evidence": self.evidence,
        }


def pick_top(rows: List[Dict[str, Any]], key: str, n: int = 3) -> List[Dict[str, Any]]:
    def k(r: Dict[str, Any]) -> float:
        v = safe_float(r.get(key))
        return v if v is not None else -1.0

    return sorted(rows, key=k, reverse=True)[:n]


def extract_cross_tenant_by_asn(csv_path: Path) -> Optional[Signal]:
    rows = load_csv_rows(csv_path)
    if not rows:
        return None

    # Expect columns like: distinct_orgs, distinct_accounts, requests, reqs_per_account
    top = pick_top(rows, key="distinct_orgs", n=1)[0]
    distinct_orgs = safe_int(top.get("distinct_orgs")) or 0
    distinct_accounts = safe_int(top.get("distinct_accounts")) or 0
    requests = safe_int(top.get("requests")) or safe_int(top.get("total_requests")) or 0

    # Score ramps up after 5 orgs; saturates around 30 orgs
    s = clamp((distinct_orgs - 5) / 25)
    rationale = (
        f"High cross-tenant diversity: {distinct_orgs} orgs and {distinct_accounts} accounts tied to the same ASN bucket."
    )
    evidence = {
        "csv": str(csv_path),
        "top_row": top,
        "metric": {"distinct_orgs": distinct_orgs, "distinct_accounts": distinct_accounts, "requests": requests},
    }
    return Signal(
        id="cross_tenant_diversity_asn",
        title="Cross-tenant diversity on shared infrastructure",
        weight=1.2,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_hosting_vpn_concentration(csv_path: Path) -> Optional[Signal]:
    rows = load_csv_rows(csv_path)
    if not rows:
        return None

    # Expect pct_hosting_vpn (0..1) and total_reqs
    top = pick_top(rows, key="pct_hosting_vpn", n=1)[0]
    pct = safe_float(top.get("pct_hosting_vpn"))
    total = safe_int(top.get("total_reqs")) or safe_int(top.get("requests")) or 0
    if pct is None:
        return None

    # Score scales mostly with pct, but dampened if volume tiny
    vol_factor = clamp(total / 200.0)  # 200 reqs -> full strength
    s = clamp(pct) * vol_factor

    rationale = f"High fraction of requests from hosting/VPN-like infrastructure for at least one account (pct={pct:.2f}, total={total})."
    evidence = {"csv": str(csv_path), "top_row": top, "metric": {"pct_hosting_vpn": pct, "total": total}}
    return Signal(
        id="hosting_vpn_concentration",
        title="Hosting/VPN concentration",
        weight=0.9,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_synchronized_spikes(csv_path: Path) -> Optional[Signal]:
    rows = load_csv_rows(csv_path)
    if not rows:
        return None

    # Common patterns: spike_score, zscore, requests
    # Choose best available key
    key = "zscore" if any("zscore" in r for r in rows) else ("spike_score" if any("spike_score" in r for r in rows) else "requests")
    top = pick_top(rows, key=key, n=1)[0]
    v = safe_float(top.get(key)) or 0.0
    req = safe_int(top.get("requests")) or 0
    distinct_orgs = safe_int(top.get("distinct_orgs")) or 0

    # If zscore/spike_score exists: saturate around 8. Otherwise use requests.
    if key in ("zscore", "spike_score"):
        s = clamp(v / 8.0)
        rationale = f"Synchronized spike detected (key={key}, value={v:.2f}) affecting {distinct_orgs} orgs."
    else:
        s = clamp(req / 500.0)
        rationale = f"Synchronized spike detected via volume (requests={req}) affecting {distinct_orgs} orgs."

    evidence = {"csv": str(csv_path), "top_row": top, "metric": {"key": key, "value": v, "requests": req, "distinct_orgs": distinct_orgs}}
    return Signal(
        id="synchronized_spikes",
        title="Synchronized spikes across tenants",
        weight=1.0,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_template_reuse(csv_path: Path) -> Optional[Signal]:
    rows = load_csv_rows(csv_path)
    if not rows:
        return None

    # Expect distinct_orgs or orgs_count
    key = "distinct_orgs" if any("distinct_orgs" in r for r in rows) else ("orgs_count" if any("orgs_count" in r for r in rows) else None)
    if not key:
        return None

    top = pick_top(rows, key=key, n=1)[0]
    orgs = safe_int(top.get(key)) or 0
    s = clamp(orgs / 10.0)

    rationale = f"Template reuse observed across orgs (orgs={orgs})."
    evidence = {"csv": str(csv_path), "top_row": top, "metric": {"orgs": orgs}}
    return Signal(
        id="template_reuse",
        title="Template reuse across orgs",
        weight=0.8,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_content_cluster_spread(csv_path: Path) -> Optional[Signal]:
    rows = load_csv_rows(csv_path)
    if not rows:
        return None

    key = "distinct_orgs" if any("distinct_orgs" in r for r in rows) else None
    if not key:
        return None

    top = pick_top(rows, key=key, n=1)[0]
    orgs = safe_int(top.get(key)) or 0
    s = clamp(orgs / 12.0)

    rationale = f"Same content cluster appears across multiple orgs (orgs={orgs})."
    evidence = {"csv": str(csv_path), "top_row": top, "metric": {"orgs": orgs}}
    return Signal(
        id="content_cluster_spread",
        title="Content cluster spread",
        weight=0.7,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_policy_funnel(csv_path: Path) -> Optional[Signal]:
    rows = load_csv_rows(csv_path)
    if not rows:
        return None

    # Expect warn_rate/block_rate OR warn_events/block_events/total
    top = rows[0]
    warn_rate = safe_float(top.get("warn_rate"))
    block_rate = safe_float(top.get("block_rate"))

    if warn_rate is None and block_rate is None:
        warn = safe_int(top.get("warn_events")) or 0
        block = safe_int(top.get("block_events")) or 0
        total = safe_int(top.get("total_events")) or 0
        if total > 0:
            warn_rate = warn / total
            block_rate = block / total
        else:
            warn_rate = 0.0
            block_rate = 0.0

    # Score: higher when enforcement is concentrated (warn+block)
    s = clamp((warn_rate or 0.0) * 0.8 + (block_rate or 0.0) * 1.2)

    rationale = f"Policy funnel shows elevated enforcement (warn_rate={warn_rate:.2f}, block_rate={block_rate:.2f})."
    evidence = {"csv": str(csv_path), "top_row": top, "metric": {"warn_rate": warn_rate, "block_rate": block_rate}}
    return Signal(
        id="policy_funnel",
        title="Policy funnel concentration",
        weight=0.6,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_rate_limit(csv_path: Path) -> Optional[Signal]:
    rows = load_csv_rows(csv_path)
    if not rows:
        return None

    # Expect pct_throttled or throttled_rate
    key = "pct_throttled" if any("pct_throttled" in r for r in rows) else ("throttled_rate" if any("throttled_rate" in r for r in rows) else None)
    if not key:
        return None

    top = pick_top(rows, key=key, n=1)[0]
    pct = safe_float(top.get(key)) or 0.0
    s = clamp(pct * 1.2)  # slight boost

    rationale = f"Rate limiting / throttling elevated (pct={pct:.2f})."
    evidence = {"csv": str(csv_path), "top_row": top, "metric": {"pct_throttled": pct}}
    return Signal(
        id="rate_limit_pressure",
        title="Rate limit / throttling pressure",
        weight=0.5,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_ato_chain_candidates(csv_path: Path) -> Optional[Signal]:
    """Extract ATO chain signal from rollup"""
    rows = load_csv_rows(csv_path)
    if not rows:
        return None

    # Count high-risk accounts (risk_score >= 80)
    high_risk = [r for r in rows if safe_int(r.get("risk_score", 0)) >= 80]
    medium_risk = [r for r in rows if 50 <= safe_int(r.get("risk_score", 0)) < 80]
    
    total_compromised = len(rows)
    high_risk_count = len(high_risk)
    
    # Score based on number of high-confidence ATO chains
    s = clamp(high_risk_count / 20.0)  # saturate at 20 high-risk accounts
    
    rationale = f"Detected {total_compromised} ATO chain candidates ({high_risk_count} high-risk, {len(medium_risk)} medium-risk)"
    evidence = {
        "csv": str(csv_path),
        "total_chains": total_compromised,
        "high_risk_count": high_risk_count,
        "medium_risk_count": len(medium_risk),
    }
    
    return Signal(
        id="ato_chain_detection",
        title="Account Takeover Chain Detection",
        weight=2.0,  # Very high weight - this is the primary signal
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_failed_login_bursts(csv_path: Path) -> Optional[Signal]:
    """Extract failed login burst signal"""
    rows = load_csv_rows(csv_path)
    if not rows:
        return None
    
    # Look for high burst counts
    top = pick_top(rows, key="failures_in_10m", n=1)[0]
    burst_count = safe_int(top.get("failures_in_10m")) or 0
    
    s = clamp((burst_count - 6) / 24.0)  # 6 is minimum, saturate at 30
    
    rationale = f"Credential stuffing bursts detected (max {burst_count} failures in 10 minutes)"
    evidence = {"csv": str(csv_path), "top_row": top, "max_burst": burst_count}
    
    return Signal(
        id="failed_login_bursts",
        title="Failed Login Bursts",
        weight=1.0,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_new_asn_success(csv_path: Path) -> Optional[Signal]:
    """Extract new ASN after failures signal"""
    rows = load_csv_rows(csv_path)
    if not rows:
        return None
    
    account_count = len(set(r.get("account_id") for r in rows if r.get("account_id")))
    
    s = clamp(account_count / 15.0)  # saturate at 15 accounts
    
    rationale = f"Successful logins from new ASNs following failed attempts ({account_count} accounts)"
    evidence = {"csv": str(csv_path), "account_count": account_count, "total_events": len(rows)}
    
    return Signal(
        id="new_asn_after_failures",
        title="New ASN Success After Failures",
        weight=1.5,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_mfa_manipulation(csv_path: Path) -> Optional[Signal]:
    """Extract MFA device addition signal"""
    rows = load_csv_rows(csv_path)
    if not rows:
        return None
    
    account_count = len(set(r.get("account_id") for r in rows if r.get("account_id")))
    
    s = clamp(account_count / 10.0)  # saturate at 10 accounts
    
    rationale = f"MFA devices added post-compromise ({account_count} accounts)"
    evidence = {"csv": str(csv_path), "account_count": account_count}
    
    return Signal(
        id="mfa_manipulation",
        title="MFA Device Manipulation",
        weight=1.3,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_mailbox_abuse(csv_path: Path) -> Optional[Signal]:
    """Extract mailbox rule creation signal"""
    rows = load_csv_rows(csv_path)
    if not rows:
        return None
    
    account_count = len(set(r.get("account_id") for r in rows if r.get("account_id")))
    
    s = clamp(account_count / 10.0)  # saturate at 10 accounts
    
    rationale = f"Suspicious mailbox rules created ({account_count} accounts)"
    evidence = {"csv": str(csv_path), "account_count": account_count}
    
    return Signal(
        id="mailbox_rule_abuse",
        title="Mailbox Rule Abuse",
        weight=1.2,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_oauth_abuse(csv_path: Path) -> Optional[Signal]:
    """Extract OAuth consent grant signal"""
    rows = load_csv_rows(csv_path)
    if not rows:
        return None
    
    account_count = len(set(r.get("account_id") for r in rows if r.get("account_id")))
    
    s = clamp(account_count / 8.0)  # saturate at 8 accounts
    
    rationale = f"Suspicious OAuth consents granted ({account_count} accounts)"
    evidence = {"csv": str(csv_path), "account_count": account_count}
    
    return Signal(
        id="oauth_consent_abuse",
        title="OAuth Consent Abuse",
        weight=1.1,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


def extract_dns_triage_rollup(csv_path: Path) -> Optional[Signal]:
    """Extract DNS triage summary from rollup (precision/recall + flagged rate)"""
    rows = load_csv_rows(csv_path)
    if not rows or len(rows) == 0:
        return None
    
    row = rows[0]  # Rollup is single-row summary
    
    precision = safe_float(row.get("precision"))
    recall = safe_float(row.get("recall"))
    flagged_events = safe_int(row.get("flagged_events")) or 0
    total_events = safe_int(row.get("total_dns_events")) or 1
    
    flagged_rate = flagged_events / total_events if total_events > 0 else 0.0
    
    # Score based on detection quality (if precision/recall available)
    if precision is not None and recall is not None:
        # F1-like score
        if (precision + recall) > 0:
            f1 = 2 * (precision * recall) / (precision + recall)
            s = clamp(f1)
        else:
            s = 0.0
        rationale = f"DNS triage detection quality: precision={precision:.3f}, recall={recall:.3f}, flagged_rate={flagged_rate:.3f}"
    else:
        # Fallback: just use flagged rate
        s = clamp(flagged_rate * 2.0)  # boost to 0-1 range
        rationale = f"DNS triage flagged {flagged_events}/{total_events} events ({flagged_rate:.3f})"
    
    evidence = {
        "csv": str(csv_path),
        "precision": precision,
        "recall": recall,
        "flagged_events": flagged_events,
        "total_events": total_events,
        "flagged_rate": flagged_rate,
    }
    
    return Signal(
        id="dns_triage_detection",
        title="DNS Triage Detection Quality",
        weight=1.5,
        score_0_1=s,
        rationale=rationale,
        evidence=evidence,
    )


EXTRACTORS = {
    # CASE-0001 extractors
    "03_tenant_diversity_by_asn.csv": extract_cross_tenant_by_asn,
    "02_pct_hosting_vpn_by_account.csv": extract_hosting_vpn_concentration,
    "06_sync_org_spikes.csv": extract_synchronized_spikes,
    "07_template_reuse.csv": extract_template_reuse,
    "08_content_cluster_spread.csv": extract_content_cluster_spread,
    "09_policy_funnel_by_provider.csv": extract_policy_funnel,
    "11_rate_limit_summary.csv": extract_rate_limit,
    
    # CASE-0002 extractors
    "0002_01_failed_login_bursts.csv": extract_failed_login_bursts,
    "0002_02_new_asn_after_failures.csv": extract_new_asn_success,
    "0002_03_mfa_device_added.csv": extract_mfa_manipulation,
    "0002_05_mailbox_rule_creation.csv": extract_mailbox_abuse,
    "0002_06_oauth_consent_grants.csv": extract_oauth_abuse,
    "0002_07_ato_chain_candidates.csv": extract_ato_chain_candidates,
    
    # CASE-0003 extractors
    "0003_99_rollup.csv": extract_dns_triage_rollup,
}


def compute_overall(signals: List[Signal]) -> Tuple[int, str]:
    if not signals:
        return 0, "low"

    total_w = sum(s.weight for s in signals)
    if total_w <= 0:
        return 0, "low"

    weighted = sum(s.weight * s.score_0_1 for s in signals) / total_w
    score = int(round(weighted * 100))

    if score >= 70:
        sev = "high"
    elif score >= 40:
        sev = "medium"
    else:
        sev = "low"
    return score, sev


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--case-dir", required=True, help="Path to a case_studies/<CASE-xxxx>/ directory")
    args = ap.parse_args()

    case_dir = Path(args.case_dir).resolve()
    findings_path = case_dir / "findings.json"

    if not findings_path.exists():
        raise FileNotFoundError(f"Missing findings.json at {findings_path}. Run run_queries.py first.")

    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    artifacts_dir = case_dir / "artifacts"

    signals: List[Signal] = []

    # Prefer known artifact files. If missing, just skip.
    for fname, fn in EXTRACTORS.items():
        p = artifacts_dir / fname
        if p.exists():
            sig = fn(p)
            if sig:
                signals.append(sig)

    # If everything is missing, still emit a deterministic payload
    overall, severity = compute_overall(signals)

    out = {
        "case_id": findings.get("case_id", case_dir.name),
        "generated_at_utc": utc_now_iso(),
        "overall_risk_score": overall,
        "severity": severity,
        "signals": [s.as_dict() for s in sorted(signals, key=lambda s: (s.weight * s.score_0_1), reverse=True)],
        "notes": "Deterministic heuristic scoring over exported artifact CSVs. Reviewable + reproducible.",
    }

    (case_dir / "scoring.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[score] wrote {case_dir / 'scoring.json'}")


if __name__ == "__main__":
    main()
