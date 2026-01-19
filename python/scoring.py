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


EXTRACTORS = {
    "03_tenant_diversity_by_asn.csv": extract_cross_tenant_by_asn,
    "02_pct_hosting_vpn_by_account.csv": extract_hosting_vpn_concentration,
    "06_sync_org_spikes.csv": extract_synchronized_spikes,
    "07_template_reuse.csv": extract_template_reuse,
    "08_content_cluster_spread.csv": extract_content_cluster_spread,
    "09_policy_funnel_by_provider.csv": extract_policy_funnel,
    "11_rate_limit_summary.csv": extract_rate_limit,
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
