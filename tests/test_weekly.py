import json
from datetime import date, timedelta

from pipeline import config, health
from pipeline.weekly_report import (
    collect_week_notes,
    draft_report,
    report_week_end,
    week_id,
)

NOTE = """---
title: {title}
type: threat
severity: {severity}
confidence: high
flagged: false
date: {date}
---

# {title}

## What it is
{summary}
"""


def _write(vault, name, **kw):
    (vault / "threats").mkdir(parents=True, exist_ok=True)
    (vault / "threats" / name).write_text(NOTE.format(**kw), encoding="utf-8")


def test_week_id_format():
    assert week_id(date(2026, 7, 15)) == "2026-W29"


def test_collect_week_notes_filters_by_date(tmp_path):
    # today is Wed 2026-07-15, so the week under report is Mon 07-06 -- Sun 07-12.
    _write(tmp_path, "recent.md", title="Recent", severity="high",
           date="2026-07-08", summary="Fresh threat.")
    _write(tmp_path, "old.md", title="Old", severity="low",
           date="2026-05-01", summary="Stale.")
    metas = collect_week_notes(tmp_path, today=date(2026, 7, 15))
    assert [m["title"] for m in metas] == ["Recent"]
    assert "Fresh threat." in metas[0]["_body"]


def test_draft_report_writes_draft_file(tmp_path):
    _write(tmp_path, "recent.md", title="Recent", severity="high",
           date="2026-07-08", summary="Fresh threat.")

    def fake_runner(prompt):
        assert "Recent" in prompt  # week's notes are in the prompt
        return "# Weekly Threat Report\n\ncontent\n", {"duration_ms": 1}

    todo = tmp_path / "todo.md"
    todo.write_text("# To-Do\n", encoding="utf-8")
    # Wed 2026-07-15 reports on the week that ended Sun 07-12, which is W28.
    path = draft_report(tmp_path, today=date(2026, 7, 15), runner=fake_runner,
                        todo_path=todo)
    assert path.name == "2026-W28-DRAFT.md"
    assert path.parent.name == "drafts"
    assert "Weekly Threat Report" in path.read_text(encoding="utf-8")
    assert "2026-W28" in todo.read_text(encoding="utf-8")


def test_draft_report_default_never_touches_real_todo(tmp_path, monkeypatch):
    import pipeline.config as config
    import pipeline.weekly_report as wr

    _write(tmp_path, "recent.md", title="Recent", severity="high",
           date="2026-07-14", summary="Fresh threat.")
    sentinel = tmp_path / "real-todo.md"
    sentinel.write_text("# To-Do\n", encoding="utf-8")
    monkeypatch.setattr(config, "BRAIN_TODO", str(sentinel))

    wr.draft_report(tmp_path, today=date(2026, 7, 15),
                    runner=lambda p: ("# r\n", {}), todo_path=None)
    assert sentinel.read_text(encoding="utf-8") == "# To-Do\n"


def test_draft_report_refuses_empty_week(tmp_path):
    (tmp_path / "threats").mkdir(parents=True)
    path = draft_report(tmp_path, today=date(2026, 7, 15), runner=None)
    assert path is None


def test_starved_week_is_reported_differently_from_a_quiet_one(tmp_path, capsys):
    """2026-W31..W34 each hit the empty-week branch and said "no threat notes",
    which reads as a quiet week. The vault held notes — they were just 19 days old
    because enrichment was dead. The skip must name that."""
    (tmp_path / "threats").mkdir(parents=True)
    (tmp_path / "threats" / "2026-08-04-old.md").write_text(
        NOTE.format(title="Old", severity="high", date="2026-08-04", summary="x"), encoding="utf-8"
    )
    health.record_run(config.DATA_DIR, {"written": 0, "failed": 15})

    assert draft_report(tmp_path, today=date(2026, 8, 23), runner=None) is None

    out = capsys.readouterr().out
    assert "no threat notes dated 2026-08-17..2026-08-23" in out
    assert "Pipeline health: DEGRADED" in out
    assert "2026-08-04" in out

    records = list((config.AUDIT_DIR).glob("*.jsonl"))
    assert records, "a skipped week must still leave an audit trace"
    entry = json.loads(records[0].read_text(encoding="utf-8").splitlines()[-1])
    assert entry["type"] == "weekly_report_skipped"
    assert entry["health"]["status"] == "degraded"


def test_quiet_week_with_current_notes_is_not_degraded(tmp_path, capsys):
    """The other half: a genuinely quiet week must not cry wolf."""
    (tmp_path / "threats").mkdir(parents=True)
    (tmp_path / "threats" / "2026-08-22-recent.md").write_text(
        NOTE.format(title="Recent", severity="low", date="2026-08-22", summary="x"), encoding="utf-8"
    )
    health.record_run(config.DATA_DIR, {"written": 2, "failed": 0})

    # Mon 2026-08-31 reports on Mon 08-24 -- Sun 08-30, so the 08-22 note falls
    # outside the window but is well inside the staleness threshold.
    assert draft_report(tmp_path, today=date(2026, 8, 31), runner=None) is None
    assert "DEGRADED" not in capsys.readouterr().out


# --- the week a run reports on is a property of the notes, not of the clock ---
#
# 2026-08-31: the Sunday task was deferred into Monday by StartWhenAvailable and
# labelled its report 2026-W36 -- the ISO week that *begins* that Monday -- while
# summarising the week before it. The verifier caught it and refused to publish.


def test_report_week_end_is_the_sunday_that_just_passed():
    # A Sunday run reports on the week ending that day.
    assert report_week_end(date(2026, 8, 30)) == date(2026, 8, 30)
    # Deferred into Monday, it still reports on that same completed week --
    # this is the case that shipped a mislabelled report.
    assert report_week_end(date(2026, 8, 31)) == date(2026, 8, 30)
    # ...and every other day of the week points back at the same Sunday.
    for offset in range(1, 7):
        assert report_week_end(date(2026, 8, 30) + timedelta(days=offset)) == date(2026, 8, 30)


def test_deferred_run_keeps_the_label_it_would_have_had_on_time():
    on_time = week_id(report_week_end(date(2026, 8, 30)))   # Sunday, as scheduled
    deferred = week_id(report_week_end(date(2026, 8, 31)))  # Monday, as it actually ran
    assert on_time == deferred == "2026-W35"


def test_window_is_the_completed_week_not_the_trailing_seven_days(tmp_path):
    # Inside the reported week.
    _write(tmp_path, "in.md", title="In window", severity="high",
           date="2026-08-26", summary="Belongs in the report.")
    # Written the morning the deferred run fired. A trailing-7-day window from
    # Monday sweeps this in; the completed week it claims to cover does not
    # contain it. This is the note class that made the draft and the verifier
    # disagree about how many notes the week held.
    _write(tmp_path, "after.md", title="After window", severity="high",
           date="2026-08-31", summary="Written after the week closed.")
    # Before the reported week.
    _write(tmp_path, "before.md", title="Before window", severity="low",
           date="2026-08-23", summary="Previous week.")

    metas = collect_week_notes(tmp_path, today=date(2026, 8, 31))
    assert [m["title"] for m in metas] == ["In window"]


def test_a_note_written_today_cannot_enter_a_completed_weeks_report(tmp_path):
    """The structural half of the concurrency fix.

    The daily run writes today's notes. A report on a *completed* week closes its
    window before today begins, so a daily running underneath the weekly can no
    longer change what the weekly is summarising -- with or without the lock.
    """
    _write(tmp_path, "settled.md", title="Settled", severity="high",
           date="2026-08-27", summary="Already in the week.")
    before = collect_week_notes(tmp_path, today=date(2026, 8, 31))

    # The daily lands mid-report, exactly as it did at 01:40 on 2026-08-31.
    for n in range(3):
        _write(tmp_path, f"concurrent{n}.md", title=f"Concurrent {n}", severity="high",
               date="2026-08-31", summary="Written while the weekly was drafting.")

    assert collect_week_notes(tmp_path, today=date(2026, 8, 31)) == before


def test_draft_labels_the_week_it_summarises(tmp_path):
    _write(tmp_path, "in.md", title="In window", severity="high",
           date="2026-08-26", summary="Belongs in the report.")

    def fake_runner(prompt):
        # The label handed to the model must be the week the notes came from.
        assert "2026-W35" in prompt
        assert "2026-W36" not in prompt
        return "# Weekly Threat Report — 2026-W35\n\ncontent\n", {"duration_ms": 1}

    path = draft_report(tmp_path, today=date(2026, 8, 31), runner=fake_runner)
    assert path.name == "2026-W35-DRAFT.md"


def test_draft_and_publish_agree_across_midnight(tmp_path):
    """A draft at 23:59 Sunday and a publish at 00:01 Monday are one run.

    Both used to call week_id(date.today()) independently, so a run straddling
    midnight drafted one week and then went looking for a different one.
    """
    from pipeline import publish

    _write(tmp_path, "in.md", title="In window", severity="high",
           date="2026-08-28", summary="Belongs in the report.")

    drafted = draft_report(
        tmp_path, today=date(2026, 8, 30),
        runner=lambda p: ("# Weekly Threat Report\n\ncontent\n", {"duration_ms": 1}),
    )
    assert publish.auto_week_id(today=date(2026, 8, 31)) == drafted.stem.removesuffix("-DRAFT")
