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

$daily = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$repo\scripts\run_daily.ps1`""
Register-ScheduledTask -TaskName "ThreatIntel-Daily" -Action $daily `
    -Trigger (New-ScheduledTaskTrigger -Daily -At 8:00am) -Settings $settings -Force | Out-Null

$weekly = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$repo\scripts\run_weekly.ps1`""
Register-ScheduledTask -TaskName "ThreatIntel-Weekly" -Action $weekly `
    -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 9:00am) -Settings $settings -Force | Out-Null

Write-Host "Registered ThreatIntel-Daily (daily 08:00) and ThreatIntel-Weekly (Sun 09:00),"
Write-Host "each retrying twice at 20-minute intervals if a run dies partway."
Write-Host "Test with: Start-ScheduledTask -TaskName ThreatIntel-Daily"
