import pytest

from pipeline.publish import approve_draft


def test_approve_moves_draft_to_reports(tmp_path):
    drafts = tmp_path / "reports" / "drafts"
    drafts.mkdir(parents=True)
    (drafts / "2026-W29-DRAFT.md").write_text("report body", encoding="utf-8")

    final = approve_draft(tmp_path, "2026-W29")
    assert final == tmp_path / "reports" / "2026-W29.md"
    assert final.read_text(encoding="utf-8") == "report body"
    assert not (drafts / "2026-W29-DRAFT.md").exists()


def test_approve_refuses_missing_draft(tmp_path):
    (tmp_path / "reports" / "drafts").mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        approve_draft(tmp_path, "2026-W29")


def test_approve_refuses_overwriting_published_report(tmp_path):
    drafts = tmp_path / "reports" / "drafts"
    drafts.mkdir(parents=True)
    (drafts / "2026-W29-DRAFT.md").write_text("new", encoding="utf-8")
    (tmp_path / "reports" / "2026-W29.md").write_text("already published", encoding="utf-8")
    with pytest.raises(FileExistsError):
        approve_draft(tmp_path, "2026-W29")
