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
& "$repo\.venv\Scripts\python.exe" -m pipeline.run 2>&1 |
    ForEach-Object { $_.ToString() } | Out-File -Append -Encoding utf8 $log
$runExit = $LASTEXITCODE
$ErrorActionPreference = $prev
"=== daily run finished $(Get-Date -Format o) (exit $runExit) ===" | Out-File -Append -Encoding utf8 $log
exit $runExit
