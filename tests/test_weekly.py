from datetime import date

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
