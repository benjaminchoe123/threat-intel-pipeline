# Registers the two scheduled tasks (run once, as the logged-in user).
#   ThreatIntel-Daily  — every day 08:00
#   ThreatIntel-Weekly — Sundays 09:00
# StartWhenAvailable=true → missed runs (PC off/asleep) fire as soon as it's back.
# RestartCount=2 → a run that dies partway retries instead of waiting a full day.
#   On 2026-08-27 the daily run exited 0xC000013A (STATUS_CONTROL_C_EXIT) about a
#   minute in, having enriched two of three KEV items. Unfinished items carry over,
#   so nothing was lost — but with no retry the next attempt was 20 hours away, and
#   for the Sunday task that would have meant no weekly report at all that week.
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries `
    -MultipleInstances IgnoreNew `
    -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 20) `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

# Run whether or not the user is logged on.
#
# Registering with no -Principal defaults to LogonType Interactive, which means
# the task lives inside the interactive login session and is torn down with it —
# reported as exit 0xC000013A, STATUS_CONTROL_C_EXIT. That happened on
# 2026-08-27, 2026-08-28 and 2026-08-31. The 08-28 investigation ruled out the
# execution time limit, batteries and the idle condition, and never looked at
# the principal. The decisive evidence was on 08-31: the run wrote no log header
# and no start stamp, so it died before run_daily.ps1's first statement. A crash
# partway through does not look like that; a session teardown at launch does.
#
# S4U ("service for user") needs no stored password. If Register-ScheduledTask
# fails here, this account is missing the "Log on as a batch job" right, which
# is a one-time grant from an elevated session — see docs/OPERATIONS.md.
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType S4U -RunLevel Limited

$daily = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$repo\scripts\run_daily.ps1`""
Register-ScheduledTask -TaskName "ThreatIntel-Daily" -Action $daily `
    -Trigger (New-ScheduledTaskTrigger -Daily -At 8:00am) `
    -Settings $settings -Principal $principal -Force | Out-Null

$weekly = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$repo\scripts\run_weekly.ps1`""
Register-ScheduledTask -TaskName "ThreatIntel-Weekly" -Action $weekly `
    -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 9:00am) `
    -Settings $settings -Principal $principal -Force | Out-Null

Write-Host "Registered ThreatIntel-Daily (daily 08:00) and ThreatIntel-Weekly (Sun 09:00)"
Write-Host "as S4U (run whether or not you are logged on), each retrying twice at"
Write-Host "20-minute intervals if a run dies partway."
Write-Host ""
Write-Host "Verify the principal took:"
Write-Host "  (Get-ScheduledTask ThreatIntel-Daily).Principal.LogonType   # expect S4U"
Write-Host "Then confirm enrichment still authenticates outside an interactive session:"
Write-Host "  Start-ScheduledTask -TaskName ThreatIntel-Daily"
Write-Host "  Get-Content logs\daily-\$(Get-Date -Format yyyy-MM-dd).log -Tail 5"
