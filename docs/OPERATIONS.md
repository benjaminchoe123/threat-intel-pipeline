# Operations — the two scheduled tasks

`scripts/register_tasks.ps1` registers both unattended runs:

| Task | Schedule | Entry point |
|---|---|---|
| `ThreatIntel-Daily` | daily 08:00 | `scripts/run_daily.ps1` → `python -m pipeline.run` |
| `ThreatIntel-Weekly` | Sundays 09:00 | `scripts/run_weekly.ps1` → draft, then `publish --auto` |

Both use `-StartWhenAvailable`, so a run missed because the machine was off fires
as soon as it comes back. `WakeToRun` is deliberately off: waking someone's
computer on a schedule is a decision about their machine, not about this
pipeline.

## Registering requires an elevated prompt

The tasks run under an **S4U** principal — "run whether or not the user is
logged on", with no stored password. Registering an S4U principal needs rights
an ordinary session does not have, so `register_tasks.ps1` fails with
`Register-ScheduledTask : Access is denied` (HRESULT 0x80070005) unless it is
run from an **Administrator PowerShell**:

```powershell
cd C:\Claude\threat-intel-pipeline
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\register_tasks.ps1
```

A failed registration is safe: `Register-ScheduledTask` is atomic per task and
the script stops on the first error, so the previously registered tasks keep
running unchanged.

## Why S4U, and what it fixed

Registering with no `-Principal` defaults to `LogonType: Interactive`. The task
then lives inside the interactive login session and is torn down along with it,
which Task Scheduler reports as `0xC000013A` (`STATUS_CONTROL_C_EXIT`).

That happened three times — 2026-08-27, 2026-08-28 and 2026-08-31. The 08-28
investigation ruled out the execution time limit, batteries and the idle
condition, and never looked at the principal.

The decisive evidence came on 08-31: the run wrote **no log header and no start
stamp**, so it died before `run_daily.ps1` reached its first statement. A crash
partway through does not look like that. A session teardown at launch does.

## Verifying it took

```powershell
(Get-ScheduledTask ThreatIntel-Daily).Principal.LogonType   # expect: S4U
```

Then confirm the part that genuinely might not survive the change — **`claude -p`
must still authenticate with no interactive session**. Credentials are per-user
files, so it should, but "should" is not evidence:

```powershell
Start-ScheduledTask -TaskName ThreatIntel-Daily
Get-Content logs\daily-$(Get-Date -Format yyyy-MM-dd).log -Tail 5
```

A log showing `enriching kev:CVE-…` followed by a `done:` line with a non-zero
`written` count is the proof. If authentication is what breaks instead, the run
now says so directly rather than draining the item budget: `pipeline.enrich`
raises `EngineUnavailable` on a response that spent zero tokens, and
`pipeline.run` abandons the run on the first one.

If it cannot authenticate under S4U, revert to the previous principal:

```powershell
$p = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
Set-ScheduledTask -TaskName ThreatIntel-Daily -Principal $p
Set-ScheduledTask -TaskName ThreatIntel-Weekly -Principal $p
```

…and accept the kills as a known cost. They are no longer invisible either way —
see below.

## Checking health without running anything

```powershell
python -m pipeline.health     # exit 0 healthy, 1 not
```

This is a separate entry point from the run on purpose: a watchdog that only
executes as part of the run it is watching reports "fine" right up until the run
stops happening, and then reports nothing at all forever.

It reads three independent signals, because each one is blind to a failure the
others catch:

1. **Note staleness** — survives the pipeline not running at all.
2. **The heartbeat** (`data/last_run.json`) — a start with no matching finish is
   a run that died partway.
3. **The scheduler's own record** (`pipeline.scheduler`) — the only observer of a
   run that died *before* it could write anything. Added 2026-08-31, when the
   first two both said OK about a task that had been killed eleven minutes
   earlier.

A non-zero task result is only treated as a failure when it is in the NTSTATUS
range (`>= 0xC0000000`), meaning the run did not choose its own exit code. The
daily legitimately exits 1 whenever a single item fails, and a banner that is red
most weeks is one nobody reads by the time it matters.
