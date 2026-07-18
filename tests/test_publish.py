import pytest

from pipeline import publish
from pipeline.publish import approve_draft
from pipeline.verify_report import VerificationResult


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


def _write_draft(vault, wid, text="# Weekly Threat Report\n\ncontent\n"):
    drafts = vault / "reports" / "drafts"
    drafts.mkdir(parents=True, exist_ok=True)
    (drafts / f"{wid}-DRAFT.md").write_text(text, encoding="utf-8")


def test_auto_publish_no_draft_does_nothing(tmp_path):
    calls = []
    code = publish.auto_publish("2026-W29", vault_dir=tmp_path,
                                 git=lambda *a: calls.append(a))
    assert code == 0
    assert calls == []


def test_auto_publish_pushes_when_verification_passes(tmp_path):
    _write_draft(tmp_path, "2026-W29")
    calls = []

    def fake_verifier(draft_text, week_notes):
        return VerificationResult(passed=True, entity_mismatches=[], claim_results=[])

    def fake_git(*args):
        calls.append(args)

    def fake_linkedin(prompt):
        return "linkedin post text", {}

    code = publish.auto_publish("2026-W29", vault_dir=tmp_path, verifier=fake_verifier,
                                 git=fake_git, linkedin_runner=fake_linkedin)
    assert code == 0
    assert ("add", str(tmp_path / "reports" / "2026-W29.md")) in calls
    assert any(c[0] == "commit" for c in calls)
    assert any(c[0] == "push" for c in calls)
    linkedin_path = tmp_path / "reports" / "linkedin-drafts" / "2026-W29.md"
    assert linkedin_path.read_text(encoding="utf-8") == "linkedin post text"
    assert not (tmp_path / "reports" / "drafts" / "2026-W29-DRAFT.md").exists()


def test_auto_publish_never_touches_git_when_verification_fails(tmp_path):
    _write_draft(tmp_path, "2026-W29")
    calls = []

    def fake_verifier(draft_text, week_notes):
        return VerificationResult(passed=False, entity_mismatches=["bad cve"], claim_results=[])

    code = publish.auto_publish("2026-W29", vault_dir=tmp_path, verifier=fake_verifier,
                                 git=lambda *a: calls.append(a))
    assert code == 1
    assert calls == []
    assert (tmp_path / "reports" / "drafts" / "2026-W29-DRAFT.md").exists()
    assert not (tmp_path / "reports" / "2026-W29.md").exists()
