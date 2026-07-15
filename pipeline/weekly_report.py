"""Sunday analyst-report draft from the week's threat notes.

Writes vault/reports/drafts/YYYY-Wnn-DRAFT.md — gitignored, so nothing reaches
GitHub until a human approves it via pipeline.publish.
"""

import os
from datetime import date, timedelta
from pathlib import Path

from . import audit, config, enrich
from .notes import _read_frontmatter

BRAIN_TODO = Path(os.getenv("BRAIN_TODO", r"C:\Claude\Brain\todo.md"))

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


def collect_week_notes(vault_dir, today=None):
    vault_dir = Path(vault_dir)
    today = today or date.today()
    cutoff = (today - timedelta(days=7)).isoformat()
    metas = []
    for path in sorted((vault_dir / "threats").glob("*.md")):
        meta = _read_frontmatter(path)
        if str(meta.get("date", "")) >= cutoff:
            meta["_body"] = path.read_text(encoding="utf-8")
            metas.append(meta)
    return metas


def draft_report(vault_dir, today=None, runner=enrich.run_claude, todo_path=None):
    """todo_path: where to append the human review reminder. None (the default)
    skips the reminder — only the __main__/scheduled entry point passes the real
    Brain todo, so tests and library callers can never touch it."""
    vault_dir = Path(vault_dir)
    today = today or date.today()
    wid = week_id(today)
    metas = collect_week_notes(vault_dir, today)
    if not metas:
        print(f"{wid}: no threat notes in the last 7 days — no draft written")
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


if __name__ == "__main__":
    draft_report(config.VAULT_DIR, todo_path=BRAIN_TODO)
