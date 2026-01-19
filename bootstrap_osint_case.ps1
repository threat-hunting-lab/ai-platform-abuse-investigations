$ErrorActionPreference="Stop"

$CVE="CVE-2025-12420"
$SLUG="servicenow-bodysnatcher"
$CaseId="CASE-OSINT-0001-$CVE-$SLUG"

Write-Host "CaseId = $CaseId"

mkdir -Force "docs\intel\templates" | Out-Null
mkdir -Force "intel_reports" | Out-Null
mkdir -Force "hunting_packages\$CVE" | Out-Null
mkdir -Force "case_studies\$CaseId" | Out-Null

$files = @(
  "docs\intel\source_tiers_and_validation.md",
  "docs\intel\signal_workbook.md",
  "docs\intel\templates\intel_report_template.md",
  "docs\intel\templates\actor_dossier_template.md",
  "docs\intel\templates\hunt_package_template.md",
  "intel_reports\2026-01-$CVE-$SLUG.md",
  "hunting_packages\$CVE\README.md",
  "hunting_packages\$CVE\attck_mapping.yaml",
  "hunting_packages\$CVE\iocs.json",
  "hunting_packages\$CVE\hunt_queries.md",
  "case_studies\$CaseId\README.md",
  "case_studies\$CaseId\links_and_sources.md",
  "case_studies\$CaseId\attck_notes.md"
)

foreach ($f in $files) {
  Write-Host "Creating: $f"
  New-Item -ItemType File -Force -Path $f | Out-Null
}

Write-Host "OK: all files created"
