param(
  [Parameter(Mandatory=$true)]
  [string]$Config,

  [Parameter(Mandatory=$true)]
  [string]$OutDir,

  [switch]$Clean
)

$ErrorActionPreference = "Stop"

# Optional: clean target output dir
if ($Clean -and (Test-Path $OutDir)) {
  Write-Host "[gen] cleaning $OutDir"
  Remove-Item -Recurse -Force $OutDir
}

# Ensure target exists
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# Generate into the repo's default datasets/output (because generate_dataset currently does that)
Write-Host "[gen] generating base tables using config: $Config"
python python/generate_dataset.py --config $Config

# Copy results into the desired OutDir
Write-Host "[gen] syncing datasets/output -> $OutDir"
Copy-Item -Path "datasets/output/*" -Destination $OutDir -Recurse -Force

# Check if this is a CASE-0002 config (identity events enabled)
# Use Get-Content -Raw to handle CRLF/LF consistently
$configContent = Get-Content -Path $Config -Raw
$hasIdentityEvents = $configContent -match "identity_events:\s*(?:\r?\n)\s*enabled:\s*true"
$isCase0002 = $Config -match "case0002" -or $hasIdentityEvents

if ($isCase0002) {
  Write-Host "[gen] Identity events enabled, generating..."
  
  $errLog = Join-Path $OutDir "identity_events.err.log"
  python python/generate_identity_events.py --config $Config --data $OutDir 2>$errLog
  
  if ($LASTEXITCODE -eq 0) {
    $identityFile = Join-Path $OutDir "identity_events.parquet"
    if (Test-Path $identityFile) {
      Write-Host "[gen] identity_events.parquet generated successfully"
    } else {
      Write-Host "[ERROR] Exit code 0 but identity_events.parquet missing!" -ForegroundColor Red
      if (Test-Path $errLog) { 
        Write-Host "Last 40 lines of error log:"
        Get-Content $errLog -Tail 40 
      }
      throw "identity_events.parquet not created"
    }
  } else {
    Write-Host "[ERROR] generate_identity_events.py failed (exit code: $LASTEXITCODE)" -ForegroundColor Red
    if (Test-Path $errLog) {
      Write-Host "Last 40 lines of error log:"
      Get-Content $errLog -Tail 40
    }
    throw "identity_events generation failed"
  }
} else {
  Write-Host "[gen] Identity events not enabled for this config, skipping"
}

Write-Host "[ok] dataset synced to $OutDir"
