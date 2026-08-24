import json
from datetime import date

from pipeline import config, health
from pipeline.weekly_report import collect_week_notes, draft_report, week_id

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
    _write(tmp_path, "recent.md", title="Recent", severity="high",
           date="2026-07-14", summary="Fresh threat.")
    _write(tmp_path, "old.md", title="Old", severity="low",
           date="2026-05-01", summary="Stale.")
    metas = collect_week_notes(tmp_path, today=date(2026, 7, 15))
    assert [m["title"] for m in metas] == ["Recent"]
    assert "Fresh threat." in metas[0]["_body"]


def test_draft_report_writes_draft_file(tmp_path):
    _write(tmp_path, "recent.md", title="Recent", severity="high",
           date="2026-07-14", summary="Fresh threat.")

    def fake_runner(prompt):
        assert "Recent" in prompt  # week's notes are in the prompt
        return "# Weekly Threat Report\n\ncontent\n", {"duration_ms": 1}

    todo = tmp_path / "todo.md"
    todo.write_text("# To-Do\n", encoding="utf-8")
    path = draft_report(tmp_path, today=date(2026, 7, 15), runner=fake_runner,
                        todo_path=todo)
    assert path.name == "2026-W29-DRAFT.md"
    assert path.parent.name == "drafts"
    assert "Weekly Threat Report" in path.read_text(encoding="utf-8")
    assert "2026-W29" in todo.read_text(encoding="utf-8")


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
    assert "no threat notes in the last 7 days" in out
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

    # today - 7 days = 2026-08-24, so the 08-22 note falls outside the window but
    # is well inside the staleness threshold.
    assert draft_report(tmp_path, today=date(2026, 8, 31), runner=None) is None
    assert "DEGRADED" not in capsys.readouterr().out
