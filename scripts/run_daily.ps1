# Daily threat-intel ingestion + enrichment. Invoked by Task Scheduler (see register_tasks.ps1).
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# Feed-supplied titles carry CJK, em-dashes, and emoji. Windows stdout is cp1252
# even when redirected, so without this a title crashes the run at the log line.
$env:PYTHONIOENCODING = "utf-8"

New-Item -ItemType Directory -Force -Path "$repo\logs" | Out-Null
$log = "$repo\logs\daily-$(Get-Date -Format yyyy-MM-dd).log"

"=== daily run started $(Get-Date -Format o) ===" | Out-File -Append -Encoding utf8 $log
& "$repo\.venv\Scripts\python.exe" -m pipeline.run *>> $log
"=== daily run finished $(Get-Date -Format o) (exit $LASTEXITCODE) ===" | Out-File -Append -Encoding utf8 $log
exit $LASTEXITCODE
