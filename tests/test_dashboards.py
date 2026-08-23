from datetime import date

from pipeline.notes import update_dashboards

# The seeded notes are dated 2026-07-15/14, and home.md's "recent" list is a rolling
# 7-day window off `today`. Letting `today` default to date.today() made these tests
# pass the week they were written and fail every week after — pin it to the seed date.
SEED_TODAY = date(2026, 7, 15)

NOTE_OK = """---
title: Normal Threat
type: threat
severity: high
confidence: high
flagged: false
date: 2026-07-15
---

# Normal Threat
"""

NOTE_FLAGGED = """---
title: Uncertain Threat
type: threat
severity: medium
confidence: low
flagged: true
date: 2026-07-14
---

# Uncertain Threat
"""


def _seed(vault):
    (vault / "threats").mkdir(parents=True)
    (vault / "families").mkdir()
    (vault / "techniques").mkdir()
    (vault / "threats" / "2026-07-15-Normal-Threat.md").write_text(NOTE_OK, encoding="utf-8")
    (vault / "threats" / "2026-07-14-Uncertain-Threat.md").write_text(NOTE_FLAGGED, encoding="utf-8")
    (vault / "families" / "SomeFamily.md").write_text("x", encoding="utf-8")


def test_home_dashboard_counts_notes(tmp_path):
    _seed(tmp_path)
    update_dashboards(tmp_path, today=SEED_TODAY)
    home = (tmp_path / "home.md").read_text(encoding="utf-8")
    assert "| total threat notes | 2 |" in home
    assert "| malware families tracked | 1 |" in home
    assert "[[threats/2026-07-15-Normal-Threat]]" in home


def test_review_queue_lists_only_flagged(tmp_path):
    _seed(tmp_path)
    update_dashboards(tmp_path, today=SEED_TODAY)
    queue = (tmp_path / "review-queue.md").read_text(encoding="utf-8")
    assert "[[threats/2026-07-14-Uncertain-Threat]]" in queue
    assert "Normal-Threat" not in queue


def test_home_includes_dataview_queries(tmp_path):
    _seed(tmp_path)
    update_dashboards(tmp_path, today=SEED_TODAY)
    home = (tmp_path / "home.md").read_text(encoding="utf-8")
    assert "```dataview" in home
    assert 'FROM "threats"' in home


def test_static_lists_survive_alongside_the_queries(tmp_path):
    """Dataview is a community plugin. Until it is installed the queries are inert
    code blocks, so the hand-built lists must still carry the dashboard."""
    _seed(tmp_path)
    update_dashboards(tmp_path, today=SEED_TODAY)
    home = (tmp_path / "home.md").read_text(encoding="utf-8")
    assert "| total threat notes | 2 |" in home
    assert "[[threats/2026-07-15-Normal-Threat]]" in home


def test_recent_list_drops_notes_older_than_a_week(tmp_path):
    """The rolling 7-day window is the behaviour that silently broke these tests.

    Guard it explicitly: run the same seed a month later and the notes must fall out
    of the recent list while the totals stay put.
    """
    _seed(tmp_path)
    update_dashboards(tmp_path, today=date(2026, 8, 23))
    home = (tmp_path / "home.md").read_text(encoding="utf-8")
    assert "*(none in the last 7 days)*" in home
    assert "[[threats/2026-07-15-Normal-Threat]]" not in home
    assert "| total threat notes | 2 |" in home
