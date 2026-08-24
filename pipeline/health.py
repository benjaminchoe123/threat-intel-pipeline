"""Is the pipeline still being fed?

Between 2026-08-02 and 2026-08-18 every enrichment failed, and nothing anywhere
said so. The exit code was already correct — `run.cli()` exits 1 when anything
fails, and it did — but an exit code is only a signal if something reads it. The
vault dashboard rendered a dead pipeline exactly like a quiet week: "*(none in
the last 7 days)*". The weekly report said "no threat notes in the last 7 days"
and wrote no draft, which is the right behavior for a quiet week and the wrong
silence for a broken one.

So this module answers one question the rest of the pipeline could not: has
output actually stopped, and did the last run tell us why. Two independent
signals, because either alone lies:

  * note staleness  — the symptom. Survives the pipeline not running at all,
    which a run-reported metric cannot.
  * last run totals — the cause. Distinguishes "nothing was published because
    nothing happened" from "15 items were fetched and every one of them failed".

Everything here is pure and clock-injectable: `assess()` takes already-parsed
frontmatter rather than a directory, so it neither re-reads the vault nor imports
`notes` (which imports this module for the banner).
"""

import json
from datetime import UTC, date, datetime
from pathlib import Path

# Feeds are daily and the machine is a desktop that gets shut off, so one quiet
# day is normal and two is a weekend. Three consecutive days with no new note has
# never happened while the pipeline was healthy.
STALE_AFTER_DAYS = 3

OK = "ok"
STALE = "stale"
DEGRADED = "degraded"

# Worst-last, so `max(..., key=SEVERITY.index)` picks the more urgent status.
SEVERITY = [OK, STALE, DEGRADED]

LAST_RUN_FILE = "last_run.json"


def record_run(data_dir, totals, when=None):
    """Write the heartbeat. Called at the end of every run, including failed ones.

    A run that writes zero notes leaves no trace in the vault, which is precisely
    the run we most need evidence of. Written before the dashboards so the banner
    reflects the run that is finishing, not the one before it.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    when = when or datetime.now(UTC)
    payload = {"finished_at": when.isoformat(), "totals": dict(totals)}
    path = data_dir / LAST_RUN_FILE
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_last_run(data_dir):
    """Read the heartbeat, or None if absent/corrupt.

    Never raises: health reporting must not be the thing that breaks a run.
    """
    try:
        return json.loads((Path(data_dir) / LAST_RUN_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _newest_date(threat_metas):
    dates = [str(m.get("date", "")) for m in threat_metas]
    dates = [d for d in dates if d]
    return max(dates) if dates else None


def assess(threat_metas, today=None, last_run=None, stale_after_days=STALE_AFTER_DAYS):
    """Return the health of the pipeline as a plain dict.

    threat_metas: parsed frontmatter of every note in vault/threats (callers
    already have this — update_dashboards parses it to build the dashboard).
    """
    today = today or date.today()
    newest = _newest_date(threat_metas)

    days_stale = None
    if newest:
        try:
            days_stale = (today - date.fromisoformat(newest)).days
        except ValueError:
            # A hallucinated or hand-edited date must not crash the health check.
            newest, days_stale = None, None

    if days_stale is None:
        # No notes at all, or no parseable date on any of them. An empty vault is
        # a legitimate first-run state, so lean on the heartbeat: never run = ok.
        status = STALE if last_run else OK
    else:
        status = STALE if days_stale >= stale_after_days else OK

    totals = (last_run or {}).get("totals") or {}
    failed = int(totals.get("failed") or 0)
    written = int(totals.get("written") or 0)
    if failed and not written:
        # Every item in the last run failed — the 2026-08 signature exactly.
        status = max(status, DEGRADED, key=SEVERITY.index)

    return {
        "status": status,
        "newest_note_date": newest,
        "days_stale": days_stale,
        "last_run_at": (last_run or {}).get("finished_at"),
        "last_run_totals": totals or None,
        "stale_after_days": stale_after_days,
    }


def banner(state):
    """One-line markdown summary for the top of a dashboard or report."""
    status = state["status"]
    if status == OK:
        newest = state["newest_note_date"] or "—"
        return f"> **Pipeline health: OK** — newest threat note {newest}."

    parts = []
    if state["days_stale"] is None:
        parts.append("no threat notes with a usable date")
    else:
        parts.append(
            f"newest threat note is {state['newest_note_date']} "
            f"({state['days_stale']} days old, threshold {state['stale_after_days']})"
        )
    totals = state["last_run_totals"] or {}
    if totals.get("failed"):
        parts.append(
            f"last run wrote {totals.get('written', 0)} note(s) and failed "
            f"{totals['failed']}"
        )
    if state["last_run_at"]:
        parts.append(f"last run {state['last_run_at']}")

    label = "DEGRADED" if status == DEGRADED else "STALE"
    return (
        f"> **⚠ Pipeline health: {label}** — " + "; ".join(parts) + ".\n>\n"
        "> Enrichment output has stopped. Check the newest `logs/daily-*.log` and\n"
        "> `logs/audit/*.jsonl` for the failure detail before trusting this dashboard."
    )
