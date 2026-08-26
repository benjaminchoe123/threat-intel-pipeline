# Sunday weekly-report draft, then a verification-gated auto-publish attempt.
# Invoked by Task Scheduler (see register_tasks.ps1).
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# Note titles reach the draft prompt; see run_daily.ps1 for why this is required.
$env:PYTHONIOENCODING = "utf-8"

New-Item -ItemType Directory -Force -Path "$repo\logs" | Out-Null
$log = "$repo\logs\weekly-$(Get-Date -Format yyyy-MM-dd).log"

"=== weekly draft started $(Get-Date -Format o) ===" | Out-File -Append -Encoding utf8 $log

# Encoding is stated, not inherited. Under Task Scheduler there is no console, and
# PowerShell 5.1's `*>>` operator then falls back to UTF-16LE for the redirected
# body while `Out-File -Encoding utf8` keeps the header UTF-8 — producing a log
# that is two encodings spliced together and unsearchable by grep/Select-String
# exactly when someone is trying to diagnose a failed run. Piping each record
# through .ToString() into an explicit -Encoding utf8 removes the dependency on
# ambient console encoding. ErrorActionPreference is relaxed across the call
# because merging a native command's stderr raises NativeCommandError under Stop.
$prev = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& "$repo\.venv\Scripts\python.exe" -m pipeline.weekly_report 2>&1 |
    ForEach-Object { $_.ToString() } | Out-File -Append -Encoding utf8 $log
$draftExit = $LASTEXITCODE
"=== weekly draft finished $(Get-Date -Format o) (exit $draftExit) ===" | Out-File -Append -Encoding utf8 $log

"=== auto-publish started $(Get-Date -Format o) ===" | Out-File -Append -Encoding utf8 $log
& "$repo\.venv\Scripts\python.exe" -m pipeline.publish --auto 2>&1 |
    ForEach-Object { $_.ToString() } | Out-File -Append -Encoding utf8 $log
$publishExit = $LASTEXITCODE
$ErrorActionPreference = $prev
"=== auto-publish finished $(Get-Date -Format o) (exit $publishExit) ===" | Out-File -Append -Encoding utf8 $log
exit $publishExit
