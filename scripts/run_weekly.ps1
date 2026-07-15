# Sunday weekly-report draft. Invoked by Task Scheduler (see register_tasks.ps1).
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# Note titles reach the draft prompt; see run_daily.ps1 for why this is required.
$env:PYTHONIOENCODING = "utf-8"

New-Item -ItemType Directory -Force -Path "$repo\logs" | Out-Null
$log = "$repo\logs\weekly-$(Get-Date -Format yyyy-MM-dd).log"

"=== weekly draft started $(Get-Date -Format o) ===" | Out-File -Append -Encoding utf8 $log
& "$repo\.venv\Scripts\python.exe" -m pipeline.weekly_report *>> $log
"=== weekly draft finished $(Get-Date -Format o) (exit $LASTEXITCODE) ===" | Out-File -Append -Encoding utf8 $log
exit $LASTEXITCODE
