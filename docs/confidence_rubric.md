# Confidence Rubric (Calibrated Language)

This repo uses a **calibrated, non-numeric** confidence scale. The goal is to avoid false precision while still being decision-useful.

## Buckets

### High confidence
Use when **multiple independent signals** align and plausible benign explanations are weak.
Typical alignment:
- Cross-tenant diversity (many orgs) **and**
- Shared infrastructure/provider buckets **and**
- Synchronized burst timing **and**
- Content/template similarity **and/or**
- Reused device fingerprints / automation indicators

Language:
- “High confidence this is coordinated behavior”
- “Strongly suggests shared control / common operator”
- “Unlikely to be organic”

### Medium confidence
Use when **some signals align** but alternatives remain plausible.
Examples:
- High infra concentration without clear timing waves
- Timing waves without content similarity
- Similar content without cross-tenant diversity

Language:
- “Likely coordinated”
- “Consistent with coordination, but could also reflect…”
- “Requires corroboration”

### Low confidence
Use when evidence is **thin or ambiguous**, or could be explained by normal usage.
Examples:
- Single-tenant anomalies
- Small sample sizes (few accounts, short duration)
- One-off spikes without repetition

Language:
- “Possibly suspicious”
- “Insufficient evidence to conclude…”
- “Worth monitoring”

## Principles

1. **Independent corroboration beats volume.**  
   A million requests from one org is less convincing than moderate volume across many orgs plus shared infra.

2. **Prefer explanations with fewer assumptions.**  
   If a benign explanation requires multiple coincidences (e.g., many unrelated orgs picking the same provider, same device fingerprint, and same templates in the same hour), treat it as less likely.

3. **Call out missing data explicitly.**  
   If device telemetry is partial, or IP enrichment is missing, reduce confidence.

4. **Avoid “certainty words.”**  
   Avoid “definitely,” “proven,” “confirmed” unless you have ground truth.

5. **Model uncertainty is a feature.**  
   The report should remain actionable even when confidence is medium.

## Example phrasing

- High: “The combination of synchronized bursts + cross-tenant diversity + template reuse strongly suggests coordinated activity.”
- Medium: “The infrastructure concentration is consistent with coordination; however, some overlap could be explained by shared enterprise egress.”
- Low: “A single burst is insufficient to conclude coordination; recommend monitoring for recurrence.”
