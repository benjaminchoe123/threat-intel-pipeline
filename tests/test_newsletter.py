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
