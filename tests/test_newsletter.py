import pytest

from pipeline import newsletter

REPORT = """# Weekly Threat Report — 2026-W29

## TL;DR

- Two actively exploited Microsoft vulnerabilities were added to CISA's KEV catalog.

## Top threats this week

### 1. CVE-2026-56164 — Microsoft SharePoint Server — **Critical**

Patch it now.
"""


def _seed_published(vault, wid="2026-W29"):
    (vault / "reports").mkdir(parents=True)
    (vault / "reports" / f"{wid}.md").write_text(REPORT, encoding="utf-8")


def test_output_wraps_intact_report_with_boilerplate(tmp_path):
    _seed_published(tmp_path)
    out = newsletter.build_newsletter(tmp_path, "2026-W29")
    assert out == tmp_path / "reports" / "newsletter" / "2026-W29-substack.md"
    text = out.read_text(encoding="utf-8")
    # report body intact
    assert "CVE-2026-56164" in text
    assert "Patch it now." in text
    # boilerplate present
    assert "Signal & Noise" in text
    assert "github.com/benjaminchoe123/threat-intel-pipeline" in text
    assert "Subscribe" in text
    # human-review disclosure in the footer
    assert "human" in text.lower()


def test_refuses_when_only_draft_exists(tmp_path):
    drafts = tmp_path / "reports" / "drafts"
    drafts.mkdir(parents=True)
    (drafts / "2026-W29-DRAFT.md").write_text(REPORT, encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="pipeline.publish"):
        newsletter.build_newsletter(tmp_path, "2026-W29")


def test_refuses_when_week_missing_entirely(tmp_path):
    (tmp_path / "reports").mkdir(parents=True)
    with pytest.raises(FileNotFoundError, match="2026-W29"):
        newsletter.build_newsletter(tmp_path, "2026-W29")


def test_refuses_to_overwrite_existing_output(tmp_path):
    _seed_published(tmp_path)
    newsletter.build_newsletter(tmp_path, "2026-W29")
    with pytest.raises(FileExistsError):
        newsletter.build_newsletter(tmp_path, "2026-W29")


def test_main_returns_nonzero_on_missing_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(newsletter.config, "VAULT_DIR", tmp_path)
    (tmp_path / "reports").mkdir(parents=True)
    assert newsletter.main(["2026-W29"]) == 1
    assert "2026-W29" in capsys.readouterr().out


def test_main_usage_error_without_week(capsys):
    assert newsletter.main([]) == 2
    assert "usage" in capsys.readouterr().out.lower()


def test_main_happy_path_prints_output_location(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(newsletter.config, "VAULT_DIR", tmp_path)
    _seed_published(tmp_path)
    assert newsletter.main(["2026-W29"]) == 0
    assert "2026-W29-substack.md" in capsys.readouterr().out


# --- GitHub Pages issues ---------------------------------------------------

def test_issue_page_lands_in_jekyll_posts_dated_by_its_week(tmp_path):
    _seed_published(tmp_path)
    docs = tmp_path / "docs"
    page = newsletter.build_issue_page(tmp_path, "2026-W29", docs_dir=docs)
    # Sunday of ISO 2026-W29 — the week the report covers, never the run date
    assert page == docs / "_posts" / "2026-07-19-signal-noise-2026-W29.md"
    text = page.read_text(encoding="utf-8")
    assert text.startswith("---\nlayout: default\n")
    assert 'title: "Signal & Noise #1 — 2026-W29"' in text
    assert "date: 2026-07-19" in text
    assert "Patch it now." in text
    assert "human" in text.lower()


def test_issue_page_drops_the_reports_own_h1(tmp_path):
    """The page prints its own title; the report's H1 would say it twice."""
    _seed_published(tmp_path)
    text = newsletter.build_issue_page(tmp_path, "2026-W29", docs_dir=tmp_path / "d").read_text(
        encoding="utf-8")
    assert "# Weekly Threat Report — 2026-W29" not in text
    assert "## TL;DR" in text


def test_issue_page_is_byte_stable_when_nothing_changed(tmp_path):
    _seed_published(tmp_path)
    docs = tmp_path / "docs"
    first = newsletter.build_issue_page(tmp_path, "2026-W29", docs_dir=docs).read_bytes()
    second = newsletter.build_issue_page(tmp_path, "2026-W29", docs_dir=docs).read_bytes()
    assert first == second


def test_issue_numbers_follow_publication_order(tmp_path):
    _seed_published(tmp_path)
    (tmp_path / "reports" / "2026-W35.md").write_text(
        REPORT.replace("W29", "W35"), encoding="utf-8")
    text = newsletter.build_issue_page(tmp_path, "2026-W35", docs_dir=tmp_path / "d").read_text(
        encoding="utf-8")
    assert "Signal & Noise #2 — 2026-W35" in text


def test_report_text_cannot_break_the_jekyll_build(tmp_path):
    """Pages runs Liquid over every page. A `{{` in a report would fail the
    whole site build, not just this issue."""
    (tmp_path / "reports").mkdir(parents=True)
    (tmp_path / "reports" / "2026-W29.md").write_text(
        REPORT + "\nTemplate injection looks like {{ 7*7 }} and {% raw %}.\n", encoding="utf-8")
    text = newsletter.build_issue_page(tmp_path, "2026-W29", docs_dir=tmp_path / "d").read_text(
        encoding="utf-8")
    body = text.split("---\n", 2)[2]
    assert body.count("{% raw %}") == 1 and body.rstrip().endswith("{% endraw %}")
    assert "{{ 7*7 }}" in body
    assert "{% raw %}." not in body  # an inner raw tag would end the escape early


def test_issue_page_refuses_drafts(tmp_path):
    drafts = tmp_path / "reports" / "drafts"
    drafts.mkdir(parents=True)
    (drafts / "2026-W29-DRAFT.md").write_text(REPORT, encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="pipeline.publish"):
        newsletter.build_issue_page(tmp_path, "2026-W29", docs_dir=tmp_path / "d")


def test_main_github_all_backfills_every_published_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(newsletter.config, "VAULT_DIR", tmp_path)
    monkeypatch.setattr(newsletter, "DOCS_DIR", tmp_path / "docs")
    _seed_published(tmp_path)
    (tmp_path / "reports" / "2026-W35.md").write_text(REPORT, encoding="utf-8")
    assert newsletter.main(["--github-all"]) == 0
    posts = sorted(p.name for p in (tmp_path / "docs" / "_posts").iterdir())
    assert posts == ["2026-07-19-signal-noise-2026-W29.md", "2026-08-30-signal-noise-2026-W35.md"]
