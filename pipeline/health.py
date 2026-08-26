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
import sys
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


def _days_since_run(last_run, today):
    """Whole days between the last heartbeat and `today`, or None if unknowable.

    Never raises. A truncated or hand-edited heartbeat must degrade to "unknown"
    rather than take the health check down — the health check is the thing that
    is supposed to still work when everything else has stopped.
    """
    stamp = (last_run or {}).get("finished_at")
    if not stamp:
        return None
    try:
        return (today - datetime.fromisoformat(stamp).date()).days
    except (TypeError, ValueError):
        return None


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

    days_since_run = _days_since_run(last_run, today)

    if days_stale is None:
        # No notes at all, or no parseable date on any of them. An empty vault is
        # a legitimate first-run state, so lean on the heartbeat: never run = ok.
        status = STALE if last_run else OK
    else:
        status = STALE if days_stale >= stale_after_days else OK

    if days_since_run is not None and days_since_run >= stale_after_days:
        # The signal note-staleness structurally cannot carry: the dashboard is
        # only ever rendered *by a run*, so "no runs at all" freezes the banner
        # mid-sentence at whatever the last healthy run wrote. Only a reader that
        # does not require a run — see main() — can act on this.
        status = max(status, STALE, key=SEVERITY.index)

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
        "days_since_run": days_since_run,
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
    if state.get("days_since_run") is not None and state["days_since_run"] >= state[
        "stale_after_days"
    ]:
        parts.append(
            f"no run for {state['days_since_run']} days "
            f"(last {state['last_run_at']})"
        )
    elif state["last_run_at"]:
        parts.append(f"last run {state['last_run_at']}")

    label = "DEGRADED" if status == DEGRADED else "STALE"
    return (
        f"> **⚠ Pipeline health: {label}** — " + "; ".join(parts) + ".\n>\n"
        "> Enrichment output has stopped. Check the newest `logs/daily-*.log` and\n"
        "> `logs/audit/*.jsonl` for the failure detail before trusting this dashboard."
    )


def check(vault_dir, data_dir, today=None):
    """Assess health by reading the vault directly, without running anything.

    `assess()` is pure and takes already-parsed frontmatter because its in-process
    callers already have it. This one does the reading, which is what an external
    watchdog needs: the whole point is to answer "is the pipeline alive" at a
    moment when the pipeline is *not* running and therefore cannot answer.
    """
    from .notes import _read_frontmatter  # local: notes imports this module

    threats = sorted((Path(vault_dir) / "threats").glob("*.md"))
    metas = [_read_frontmatter(p) for p in threats]
    return assess(metas, today=today, last_run=load_last_run(data_dir))


def main(argv=None, today=None):
    """`python -m pipeline.health [vault_dir data_dir]` -> 0 healthy, 1 not.

    Deliberately a separate entry point from `run.cli()`. A watchdog that only
    executes as part of the run it is watching reports "fine" right up until the
    run stops happening, and then reports nothing at all forever.
    """
    from . import config

    argv = list(argv if argv is not None else sys.argv[1:])
    vault_dir = argv[0] if len(argv) > 0 else config.VAULT_DIR
    data_dir = argv[1] if len(argv) > 1 else config.DATA_DIR

    # The STALE banner carries U+26A0, which cp1252 cannot encode, and Windows
    # stdout is cp1252 even when redirected. Duplicated from run._utf8_stream()
    # on purpose: run.py imports this module, and a watchdog that needs the whole
    # run machinery loaded before it can print is a watchdog with a second way to
    # fail silently.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass  # not a real tty (pytest capture); the default is fine

    state = check(vault_dir, data_dir, today=today)
    print(banner(state))
    return 0 if state["status"] == OK else 1


if __name__ == "__main__":  # pragma: no cover - thin shell
    sys.exit(main())
