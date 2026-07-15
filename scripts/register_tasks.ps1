# Registers the two scheduled tasks (run once, as the logged-in user).
#   ThreatIntel-Daily  — every day 08:00
#   ThreatIntel-Weekly — Sundays 09:00
# StartWhenAvailable=true → missed runs (PC off/asleep) fire as soon as it's back.
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

$daily = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$repo\scripts\run_daily.ps1`""
Register-ScheduledTask -TaskName "ThreatIntel-Daily" -Action $daily `
    -Trigger (New-ScheduledTaskTrigger -Daily -At 8:00am) -Settings $settings -Force | Out-Null

$weekly = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$repo\scripts\run_weekly.ps1`""
Register-ScheduledTask -TaskName "ThreatIntel-Weekly" -Action $weekly `
    -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 9:00am) -Settings $settings -Force | Out-Null

Write-Host "Registered ThreatIntel-Daily (daily 08:00) and ThreatIntel-Weekly (Sun 09:00)."
Write-Host "Test with: Start-ScheduledTask -TaskName ThreatIntel-Daily"
