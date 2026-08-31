"""Sunday analyst-report draft from the week's threat notes.

Writes vault/reports/drafts/YYYY-Wnn-DRAFT.md — gitignored, so nothing reaches
GitHub until a human approves it via pipeline.publish.
"""

import sys
from datetime import date, timedelta
from pathlib import Path

from . import audit, config, enrich, health
from .notes import _read_frontmatter
from .runlock import LockHeld, RunLock

# Long enough to outlast a daily run (15 items, tens of seconds each), short
# enough that a wedged run does not hold the weekly past its usefulness.
WEEKLY_LOCK_WAIT_SECONDS = 45 * 60

REPORT_INSTRUCTIONS = """Draft a weekly threat intelligence report for a small-organization
audience (an IT lead who is not a security specialist), based ONLY on the threat notes
provided below. Structure:

# Weekly Threat Report — {week}

## TL;DR (3-5 bullets)
## Top threats this week
   (ranked; for each: what it is in plain English, who's affected, severity + why)
## What changed vs. prior weeks
   (only if inferable from the notes; otherwise say activity baseline is still being established)
## What a small organization should actually do
   (concrete, prioritized actions: patch X, block Y, check Z — no generic advice like
   "raise awareness")
## Sources
   (list the source feeds the notes came from)

Voice: same analyst rules as note enrichment — factual, plain English, no hype, never
claim anything not supported by the notes. If the week's data is thin, say so plainly.
Return ONLY the markdown report, starting with the H1."""


def week_id(day):
    iso = day.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"


def report_week_end(day):
    """The Sunday of the most recent *completed* ISO week.

    The week a report covers is a property of the notes it summarises, not of
    the moment the machine happened to wake up. `register_tasks.ps1` sets
    -StartWhenAvailable, so the Sunday task fires late whenever the desktop was
    off — and on 2026-08-31 it fired on the Monday that *begins* ISO week 36,
    labelled itself 2026-W36, and summarised the week before it. The verifier
    refused to publish and said exactly why: "ISO week 36 of 2026 begins
    2026-08-31, so all but the final day's notes fall in W35."

    Same defect as STIX `created = now` and the Navigator layer title: run
    wall-clock leaking into content identity. Anchoring to the completed week
    means a deferred run produces the report it would have produced on time.

    ISO weekdays are Mon=1..Sun=7, so `isoweekday() % 7` is the number of days
    back to the Sunday on or before `day` — zero when `day` is itself a Sunday.
    """
    return day - timedelta(days=day.isoweekday() % 7)


def week_window(today=None):
    """(first, last) dates of the week being reported on, both inclusive."""
    end = report_week_end(today or date.today())
    return end - timedelta(days=6), end


def collect_week_notes(vault_dir, today=None):
    """The notes dated inside the completed week being reported on.

    A closed Mon–Sun window rather than a trailing seven days from `today`.
    That is what makes the label honest, and it also settles the concurrency
    problem structurally: the daily run writes *today's* notes, and today is
    always after a completed week has closed, so a daily running underneath the
    weekly cannot change the set the weekly is summarising. On 2026-08-31 it
    could — the draft saw 19 notes and verification, eleven minutes later, saw
    22, and the whole publish failed on the difference.
    """
    vault_dir = Path(vault_dir)
    first, last = week_window(today)
    first, last = first.isoformat(), last.isoformat()
    metas = []
    for path in sorted((vault_dir / "threats").glob("*.md")):
        meta = _read_frontmatter(path)
        if first <= str(meta.get("date", "")) <= last:
            meta["_body"] = path.read_text(encoding="utf-8")
            metas.append(meta)
    return metas


def _all_threat_metas(vault_dir):
    """Every threat note's frontmatter, unfiltered by week.

    Health needs the newest note overall. Asking collect_week_notes() would be
    circular: this runs only when that window is empty.
    """
    return [_read_frontmatter(p) for p in (Path(vault_dir) / "threats").glob("*.md")]


def draft_report(vault_dir, today=None, runner=enrich.run_claude, todo_path=None):
    """todo_path: where to append the human review reminder. None (the default)
    skips the reminder — only the __main__/scheduled entry point passes the real
    Brain todo, so tests and library callers can never touch it."""
    vault_dir = Path(vault_dir)
    today = today or date.today()
    wid = week_id(report_week_end(today))
    metas = collect_week_notes(vault_dir, today)
    if not metas:
        # A quiet week and a starved pipeline both arrive here, and this line
        # reported the second as the first for 2026-W31 through W34. Say which.
        state = health.assess(
            _all_threat_metas(vault_dir),
            today=today,
            last_run=health.load_last_run(config.DATA_DIR),
        )
        first, last = week_window(today)
        print(f"{wid}: no threat notes dated {first}..{last} — no draft written")
        print(health.banner(state))
        audit.log_enrichment(
            config.AUDIT_DIR,
            {"type": "weekly_report_skipped", "week": wid, "health": state},
        )
        return None

    notes_blob = "\n\n---\n\n".join(m["_body"] for m in metas)
    prompt = (
        REPORT_INSTRUCTIONS.format(week=wid)
        + f"\n\n<week-notes count=\"{len(metas)}\">\n{notes_blob}\n</week-notes>"
    )
    report_text, engine_meta = runner(prompt)

    drafts_dir = vault_dir / "reports" / "drafts"
    drafts_dir.mkdir(parents=True, exist_ok=True)
    path = drafts_dir / f"{wid}-DRAFT.md"
    path.write_text(report_text, encoding="utf-8")

    audit.log_enrichment(
        config.AUDIT_DIR,
        {"type": "weekly_report", "week": wid, "notes_used": len(metas),
         "engine": engine_meta, "draft_path": str(path)},
    )
    if todo_path is not None:
        _add_review_todo(wid, path, todo_path)
    print(f"draft written: {path}")
    return path


def _add_review_todo(wid, path, todo_path):
    """Append a review item to the given todo list (best-effort)."""
    try:
        todo_path = Path(todo_path)
        if todo_path.exists():
            line = (f"- [ ] Review & publish weekly threat report {wid} — edit "
                    f"`{path}`, then run `python -m pipeline.publish {wid}` in the repo.\n")
            if line not in todo_path.read_text(encoding="utf-8"):
                with todo_path.open("a", encoding="utf-8") as f:
                    f.write(line)
    except OSError as e:
        print(f"could not update todo list: {e}")


def main():
    """Draft under the run lock, waiting for a daily run rather than racing it.

    The closed week window already keeps *new* notes out of a completed week's
    report, so this is the second line of defence: it also covers a run that
    edits or backfills a note inside the window, and it stops two `claude`
    workloads competing for the same rate limit.

    Waiting, not skipping. A daily that finds the lock held exits 0 because
    someone else is doing its job; nobody else is going to write this report.
    """
    with RunLock(config.DATA_DIR / "run.lock", wait_seconds=WEEKLY_LOCK_WAIT_SECONDS):
        return draft_report(
            config.VAULT_DIR,
            todo_path=Path(config.BRAIN_TODO) if config.BRAIN_TODO else None,
        )


if __name__ == "__main__":
    try:
        main()
    except LockHeld as e:
        # Loud, non-zero: a missing weekly report must never look like a quiet week.
        print(f"weekly report not drafted — {e}", file=sys.stderr)
        sys.exit(1)
