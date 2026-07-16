from pipeline.notes import update_dashboards

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
    update_dashboards(tmp_path)
    home = (tmp_path / "home.md").read_text(encoding="utf-8")
    assert "| total threat notes | 2 |" in home
    assert "| malware families tracked | 1 |" in home
    assert "[[threats/2026-07-15-Normal-Threat]]" in home


def test_review_queue_lists_only_flagged(tmp_path):
    _seed(tmp_path)
    update_dashboards(tmp_path)
    queue = (tmp_path / "review-queue.md").read_text(encoding="utf-8")
    assert "[[threats/2026-07-14-Uncertain-Threat]]" in queue
    assert "Normal-Threat" not in queue


def test_home_includes_dataview_queries(tmp_path):
    _seed(tmp_path)
    update_dashboards(tmp_path)
    home = (tmp_path / "home.md").read_text(encoding="utf-8")
    assert "```dataview" in home
    assert 'FROM "threats"' in home


def test_static_lists_survive_alongside_the_queries(tmp_path):
    """Dataview is a community plugin. Until it is installed the queries are inert
    code blocks, so the hand-built lists must still carry the dashboard."""
    _seed(tmp_path)
    update_dashboards(tmp_path)
    home = (tmp_path / "home.md").read_text(encoding="utf-8")
    assert "| total threat notes | 2 |" in home
    assert "[[threats/2026-07-15-Normal-Threat]]" in home
