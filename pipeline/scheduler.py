"""What the OS scheduler thinks happened to our tasks.

Every other health signal is written *by* a run: `record_start` stamps the
heartbeat, notes date themselves, totals come from the run that produced them.
That leaves one blind spot, and on 2026-08-31 it opened. The daily task's last
result was 0xC000013A (STATUS_CONTROL_C_EXIT) at 12:16:51, and the run had
written no log header and no `started_at` — it died before PowerShell's first
line of output. `pipeline.health` reported OK, because the previous run's
finished_at was eleven hours old and nothing had contradicted it.

This is the 2026-08-26 gap one level earlier. That one closed "a run that dies
partway is indistinguishable from one that never started" with a start stamp.
A run that dies *at launch* is indistinguishable from a healthy day, and no
stamp written inside the run can close it — the run is what failed to happen.
The wrapper script cannot close it either; on 2026-08-31 `run_daily.ps1` never
produced its first line.

The only observer left is the scheduler itself, so that is what this reads.

Everything here degrades to "unknown" rather than raising. Health reporting must
never be the thing that breaks, and a machine with no Task Scheduler is a
perfectly ordinary place to run this code.
"""

import logging
import os
import subprocess

log = logging.getLogger(__name__)

DAILY_TASK = "ThreatIntel-Daily"
WEEKLY_TASK = "ThreatIntel-Weekly"

# Windows NTSTATUS failure codes start at 0xC0000000. Everything below that is a
# process exit code the task actually chose to return.
#
# The distinction decides whether a non-zero result means anything new. The daily
# run exits 1 whenever a single item fails, which is both correct and common, and
# is already reported through `totals`. Treating that the same as a kill would
# put the banner in the red most weeks, and a banner that is usually red is one
# nobody reads by the time it matters.
NTSTATUS_FLOOR = 0xC0000000

# The specific one seen three times (2026-08-27, 08-28, 08-31), named because a
# bare hex code in a health banner sends the reader to a search engine.
KNOWN_STATUS = {
    0xC000013A: "terminated (Ctrl+C / session ended)",
    0xC0000005: "access violation",
    0xC0000142: "DLL initialization failed",
    0x80070002: "the task action could not be found",
}


def was_killed(result):
    """True when the task did not choose its own exit code.

    A run that returns 1 ran and reported failure; a run that returns
    0xC000013A was stopped by something outside it.
    """
    return result is not None and result >= NTSTATUS_FLOOR


def describe(result):
    if result is None:
        return "unknown"
    if result == 0:
        return "ok"
    if was_killed(result):
        return KNOWN_STATUS.get(result, f"terminated (0x{result:08X})")
    return f"exited {result}"


def task_info(name, runner=None):
    """(last_run_time, last_result) for a scheduled task, or (None, None).

    Returns (None, None) for every failure — not on Windows, task not
    registered, PowerShell missing, output unparseable. A health check that
    cannot see the scheduler must report that it cannot see it, never guess.
    """
    if os.name != "nt":
        return None, None
    runner = runner or _powershell
    try:
        out = runner(
            f"$i = Get-ScheduledTaskInfo -TaskName '{name}' -ErrorAction Stop; "
            "Write-Output $i.LastRunTime.ToString('o'); "
            "Write-Output ([int64]$i.LastTaskResult)"
        )
    except Exception as e:  # noqa: BLE001 - any failure here means "unknown"
        log.debug("could not read scheduled task %s: %s", name, e)
        return None, None

    lines = [line.strip() for line in (out or "").splitlines() if line.strip()]
    if len(lines) < 2:
        return None, None
    try:
        # LastTaskResult is signed in PowerShell's view, so 0xC000013A comes back
        # negative. Fold it back into the unsigned space the codes are documented
        # in, or every kill would be reported as a small negative exit code.
        result = int(lines[1])
        if result < 0:
            result += 1 << 32
        return lines[0], result
    except ValueError:
        return None, None


def _powershell(script):
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=30, shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "powershell failed")
    return completed.stdout


def killed_tasks(names=(DAILY_TASK, WEEKLY_TASK), info=task_info):
    """The tasks whose most recent run was killed rather than completed.

    A list of {"task", "last_run", "result", "detail"}, empty when nothing was
    killed *and* when nothing could be read. Those two are not the same thing,
    but neither is evidence of a failure, and inventing one would make this the
    component that cries wolf.
    """
    killed = []
    for name in names:
        last_run, result = info(name)
        if was_killed(result):
            killed.append({
                "task": name, "last_run": last_run,
                "result": result, "detail": describe(result),
            })
    return killed
