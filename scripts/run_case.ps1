param(
  [Parameter(Mandatory=$true)]
  [string]$CaseDir,

  [Parameter(Mandatory=$true)]
  [string]$DataDir,

  [string]$DuckDbPath = "artifacts/ai_abuse.duckdb",

  [string]$SqlDir = "sql",

  [switch]$Strict
)

$ErrorActionPreference = "Stop"

# Ensure artifacts dir exists
if (!(Test-Path "artifacts")) { New-Item -ItemType Directory -Path "artifacts" | Out-Null }

Write-Host "[run] case-dir=$CaseDir"
Write-Host "[run] data-dir=$DataDir"
Write-Host "[run] duckdb=$DuckDbPath"
Write-Host "[run] sql=$SqlDir"
Write-Host "[run] strict=$Strict"

# Build args safely (no fragile backticks)
$runArgs = @(
  "python/run_queries.py",
  "--duckdb", $DuckDbPath,
  "--data",   $DataDir,
  "--sql",    $SqlDir,
  "--case-dir", $CaseDir
)
if ($Strict) { $runArgs += "--strict" }

python @runArgs

python python/scoring.py --case-dir $CaseDir
python python/render_report.py --case-dir $CaseDir

Write-Host "[ok] wrote scoring.json + REPORT.md in $CaseDir"
