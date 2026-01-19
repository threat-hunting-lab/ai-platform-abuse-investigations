from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signal_severity_from_score(score: float) -> str:
    # Heuristic only (keeps report readable even if scoring schema changes)
    if score >= 80:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _fmt_evidence(ev: Any) -> str:
    """
    Supports:
      - string evidence
      - dict evidence: { csv: "...", top_row: {...}, metric: {...} }
    """
    if not ev:
        return ""

    if isinstance(ev, str):
        return ev

    if isinstance(ev, dict):
        parts: list[str] = []
        csv = ev.get("csv")
        if csv:
            parts.append(f"csv={csv}")

        top_row = ev.get("top_row")
        if isinstance(top_row, dict) and top_row:
            # Show a few key=value pairs to keep it short.
            keys = list(top_row.keys())[:6]
            kv = ", ".join(f"{k}={top_row.get(k)}" for k in keys)
            parts.append(f"top_row({kv})")

        metric = ev.get("metric")
        if isinstance(metric, dict) and metric:
            keys = list(metric.keys())[:6]
            kv = ", ".join(f"{k}={metric.get(k)}" for k in keys)
            parts.append(f"metric({kv})")

        return " | ".join(parts)

    return str(ev)


def render_report(case_dir: Path) -> Path:
    findings_path = case_dir / "findings.json"
    scoring_path = case_dir / "scoring.json"
    case_readme = case_dir / "README.md"

    findings = _read_json(findings_path)
    scoring = _read_json(scoring_path)

    meta = findings.get("meta", {})
    case_id = meta.get("case_id", case_dir.name)
    case_name = meta.get("case_name", case_dir.name)

    out_path = case_dir / "REPORT.md"

    lines: list[str] = []
    lines.append(f"# {case_id} - {case_name}")
    lines.append("")
    lines.append(f"- Generated (UTC): `{_utc_now()}`")
    if findings.get("generated_at_utc"):
        lines.append(f"- Dataset generated_at_utc: `{findings.get('generated_at_utc')}`")
    lines.append("")

    # Case summary
    if case_readme.exists():
        lines.append("## Case Summary")
        lines.append("")
        lines.append(case_readme.read_text(encoding="utf-8").strip())
        lines.append("")

    # Scoring section (supports both old + new schemas)
    lines.append("## Risk Scoring")
    lines.append("")
    if scoring:
        overall = scoring.get("overall_risk_score", 0)
        sev = str(scoring.get("severity", "low")).strip()
        lines.append(f"- Overall risk score: **{overall} / 100**")
        lines.append(f"- Severity: **{sev}**")
        lines.append("")

        signals = scoring.get("signals", [])
        if signals:
            # Sort by whatever field exists
            def sort_key(s: dict) -> float:
                if "points" in s:
                    return float(s.get("points", 0) or 0)
                return float(s.get("score", 0) or 0)

            signals_sorted = sorted(signals, key=sort_key, reverse=True)

            lines.append("### Key Signals")
            lines.append("")
            for s in signals_sorted:
                sid = s.get("id", "signal")
                title = s.get("title", "")

                # Old schema:
                pts = s.get("points")
                sig_sev = s.get("severity")

                # New schema:
                weight = s.get("weight")
                score = s.get("score")

                if sig_sev is None and score is not None:
                    sig_sev = _signal_severity_from_score(float(score))

                header_bits: list[str] = []
                if score is not None:
                    header_bits.append(f"score={float(score):.1f}")
                if weight is not None:
                    header_bits.append(f"weight={float(weight):.2f}")
                if pts is not None:
                    header_bits.append(f"points={pts}")

                hdr = ", ".join(header_bits) if header_bits else "signal"

                lines.append(f"- **[{sig_sev}] {sid}** ({hdr}) - {title}".rstrip())

                rationale = s.get("rationale") or s.get("detail")
                if rationale:
                    lines.append(f"  - Rationale: {rationale}")

                ev = _fmt_evidence(s.get("evidence"))
                if ev:
                    lines.append(f"  - Evidence: {ev}")

            lines.append("")
        else:
            lines.append("- No signals scored (signals list empty).")
            lines.append("")
    else:
        lines.append("- `scoring.json` not found or empty.")
        lines.append("")

    # Evidence artifacts
    lines.append("## Evidence Artifacts")
    lines.append("")
    artifacts = findings.get("artifacts", [])
    if not artifacts:
        lines.append("- No artifacts found in `findings.json`.")
        lines.append("")
    else:
        lines.append("| SQL | Artifact CSV | Rows |")
        lines.append("|---|---|---:|")
        for a in artifacts:
            sql_file = a.get("sql_file", "")
            csv_file = a.get("artifact_csv", "")
            rows = a.get("rows", "")
            lines.append(f"| `{sql_file}` | `{csv_file}` | {rows} |")
        lines.append("")

    # Table counts
    lines.append("## Dataset / Table Counts")
    lines.append("")
    counts = findings.get("tables_row_counts", {})
    if counts:
        for k, v in counts.items():
            lines.append(f"- `{k}`: **{v}** rows")
        lines.append("")
    else:
        lines.append("- (none)")
        lines.append("")

    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return out_path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-dir", required=True, help="Case study directory (contains findings.json)")
    args = ap.parse_args()

    case_dir = Path(args.case_dir)
    if not case_dir.exists():
        raise FileNotFoundError(f"case-dir not found: {case_dir}")

    out = render_report(case_dir)
    print(f"[report] wrote {out}")


if __name__ == "__main__":
    main()
