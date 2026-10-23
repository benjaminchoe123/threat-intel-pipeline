from datetime import date

import pytest

from pipeline import config, publish
from pipeline.publish import approve_draft
from pipeline.runlock import RunLock
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
                                 git=fake_git, linkedin_runner=fake_linkedin, min_notes=0)
    assert code == 0
    assert any(c[0] == "add" and str(tmp_path / "reports" / "2026-W29.md") in c for c in calls)
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
                                 git=lambda *a: calls.append(a), min_notes=0)
    assert code == 1
    assert calls == []
    assert (tmp_path / "reports" / "drafts" / "2026-W29-DRAFT.md").exists()
    assert not (tmp_path / "reports" / "2026-W29.md").exists()


def _fake_week(monkeypatch, count):
    notes = [{"date": "2026-10-16", "_body": f"note {i}"} for i in range(count)]
    monkeypatch.setattr(publish.weekly_report, "collect_week_notes",
                        lambda vault_dir: notes)


def test_auto_publish_holds_a_thin_week_without_asking_the_verifier(tmp_path, monkeypatch):
    """2026-W42 went out unattended on two notes. The gate checks that a draft is
    faithful to its notes; it cannot say whether two notes are a week. A thin
    week is held for a human, never verified-and-pushed."""
    _write_draft(tmp_path, "2026-W42")
    _fake_week(monkeypatch, 2)
    calls, verified = [], []

    def fake_verifier(draft_text, week_notes):
        verified.append(True)
        return VerificationResult(passed=True, entity_mismatches=[], claim_results=[])

    code = publish.auto_publish("2026-W42", vault_dir=tmp_path, verifier=fake_verifier,
                                 git=lambda *a: calls.append(a), min_notes=8)
    assert code == 0  # a deliberate hold, not a failure
    assert verified == [] and calls == []
    assert (tmp_path / "reports" / "drafts" / "2026-W42-DRAFT.md").exists()
    records = "".join(p.read_text(encoding="utf-8") for p in config.AUDIT_DIR.glob("*.jsonl"))
    assert '"auto_publish_held"' in records
    assert '"notes": 2' in records


def test_auto_publish_proceeds_at_the_floor(tmp_path, monkeypatch):
    _write_draft(tmp_path, "2026-W43")
    _fake_week(monkeypatch, 8)
    verified = []

    def fake_verifier(draft_text, week_notes):
        verified.append(len(week_notes))
        return VerificationResult(passed=False, entity_mismatches=["x"], claim_results=[])

    publish.auto_publish("2026-W43", vault_dir=tmp_path, verifier=fake_verifier,
                         git=lambda *a: None, min_notes=8)
    assert verified == [8]


def test_auto_publish_floor_defaults_to_config(tmp_path, monkeypatch):
    _write_draft(tmp_path, "2026-W42")
    _fake_week(monkeypatch, config.MIN_NOTES_FOR_AUTO_PUBLISH - 1)
    code = publish.auto_publish(
        "2026-W42", vault_dir=tmp_path, git=lambda *a: None,
        verifier=lambda *a: pytest.fail("verifier must not run below the floor"))
    assert code == 0


def test_main_dispatches_auto_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VAULT_DIR", tmp_path)
    called = {}

    def fake_auto_publish(wid):
        called["wid"] = wid
        return 0

    monkeypatch.setattr(publish, "auto_publish", fake_auto_publish)
    code = publish.main(["--auto"])
    assert code == 0
    assert called["wid"] == publish.auto_week_id()


def test_auto_publish_targets_the_week_the_draft_covers():
    """--auto used to ask week_id(date.today()), which names the week *containing*
    today. Run on a Sunday that is right; deferred into Monday it names the week
    that has only just begun, which is how 2026-W36 came to be drafted from W35's
    notes. Anchored to the completed week, the two agree."""
    assert publish.auto_week_id(today=date(2026, 8, 30)) == "2026-W35"  # on time
    assert publish.auto_week_id(today=date(2026, 8, 31)) == "2026-W35"  # deferred


def test_main_shows_verification_before_confirming(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "VAULT_DIR", tmp_path)
    _write_draft(tmp_path, "2026-W29")

    monkeypatch.setattr(
        publish.verify_report, "verify",
        lambda draft, notes: VerificationResult(
            passed=False, entity_mismatches=["draft cites CVE-2099-0000, which is not in "
                                              "any of this week's notes"],
            claim_results=[],
        ),
    )
    code = publish.main(["2026-W29"], confirm=lambda prompt: "no")
    assert code == 1
    assert "CVE-2099-0000" in capsys.readouterr().out


def test_main_publishes_on_confirm_after_verification(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VAULT_DIR", tmp_path)
    _write_draft(tmp_path, "2026-W29")

    monkeypatch.setattr(
        publish.verify_report, "verify",
        lambda draft, notes: VerificationResult(passed=True, entity_mismatches=[],
                                                 claim_results=[]),
    )
    monkeypatch.setattr(publish, "_push_and_draft_linkedin",
                        lambda vault_dir, wid, **kw: (
                            tmp_path / "reports" / f"{wid}.md", "post text",
                            tmp_path / "reports" / "linkedin-drafts" / f"{wid}.md",
                        ))
    monkeypatch.setattr(publish.subprocess, "run", lambda *a, **kw: None)

    code = publish.main(["2026-W29"], confirm=lambda prompt: "publish")
    assert code == 0


def test_main_aborts_without_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VAULT_DIR", tmp_path)
    _write_draft(tmp_path, "2026-W29")
    monkeypatch.setattr(
        publish.verify_report, "verify",
        lambda draft, notes: VerificationResult(passed=True, entity_mismatches=[],
                                                 claim_results=[]),
    )
    code = publish.main(["2026-W29"], confirm=lambda prompt: "no")
    assert code == 1
    assert (tmp_path / "reports" / "drafts" / "2026-W29-DRAFT.md").exists()


def test_auto_publish_waits_for_a_daily_run_rather_than_pushing_mid_write(tmp_path, monkeypatch):
    """--auto git-adds and pushes the vault. A daily run writing notes underneath
    would commit a half-written tree, so it takes the same lock the draft did."""
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(publish.weekly_report, "WEEKLY_LOCK_WAIT_SECONDS", 0)
    monkeypatch.setattr(publish, "auto_publish", lambda wid: 0)

    with RunLock(tmp_path / "run.lock"):
        assert publish.main(["--auto"]) == 1  # loud, not a silent skip

    assert publish.main(["--auto"]) == 0  # lock free again


def test_publishing_a_report_also_publishes_its_newsletter_issue(tmp_path, monkeypatch):
    _write_draft(tmp_path, "2026-W29")
    monkeypatch.setattr(publish.newsletter, "DOCS_DIR", tmp_path / "docs")
    calls = []
    publish._push_and_draft_linkedin(tmp_path, "2026-W29", git=lambda *a: calls.append(a),
                                     linkedin_runner=lambda p: ("post", {}))
    page = tmp_path / "docs" / "_posts" / "2026-07-19-signal-noise-2026-W29.md"
    assert page.exists()
    names = [c[0] for c in calls]
    add = next(c for c in calls if c[0] == "add")
    assert str(page) in add
    # one commit carries both, and it comes before the push
    assert names.index("add") < names.index("commit") < names.index("push")
    assert names[-1] == "push"


def test_a_newsletter_failure_never_blocks_the_report(tmp_path, monkeypatch):
    _write_draft(tmp_path, "2026-W29")

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(publish.newsletter, "build_issue_page", boom)
    calls = []
    final, _, _ = publish._push_and_draft_linkedin(
        tmp_path, "2026-W29", git=lambda *a: calls.append(a),
        linkedin_runner=lambda p: ("post", {}))
    assert final.exists()
    assert any(c[0] == "push" for c in calls)


# --- the weekly push publishes the issue and nothing else -----------------

def _run_tail(tmp_path, git, linkedin=lambda p: ("post", {})):
    _write_draft(tmp_path, "2026-W29")
    return publish._push_and_draft_linkedin(tmp_path, "2026-W29", git=git,
                                            linkedin_runner=linkedin)


def test_commit_is_limited_to_the_report_and_its_issue(tmp_path):
    """A bare `git commit` takes everything staged. Whatever happened to be in
    the index on a Sunday morning would have gone public with the newsletter."""
    calls = []
    _run_tail(tmp_path, lambda *a: calls.append(a))
    commit = next(c for c in calls if c[0] == "commit")
    paths = list(commit[commit.index("--") + 1:])
    assert paths == [str(tmp_path / "reports" / "2026-W29.md"),
                     str(tmp_path / "docs" / "_posts" / "2026-07-19-signal-noise-2026-W29.md")]


def test_a_rejected_push_rebases_onto_the_remote_and_retries(tmp_path):
    """Dependabot merges land on GitHub, not here. The first Sunday after one,
    a plain push is rejected as non-fast-forward and the issue never ships."""
    calls, pushes = [], []

    def git(*args):
        calls.append(args)
        if args[0] == "push":
            pushes.append(args)
            if len(pushes) == 1:
                raise RuntimeError("git push failed: ! [rejected] main -> main (fetch first)")

    _run_tail(tmp_path, git)
    names = [c[0] for c in calls]
    assert names[-3:] == ["push", "pull", "push"]
    assert ("pull", "--rebase", "--autostash") in calls


def test_a_push_that_still_fails_is_raised_not_swallowed(tmp_path):
    def git(*args):
        if args[0] in ("push", "pull"):
            raise RuntimeError(f"git {args[0]} failed: no network")

    with pytest.raises(RuntimeError, match="no network"):
        _run_tail(tmp_path, git)


def test_linkedin_failure_after_a_push_does_not_fail_the_publish(tmp_path):
    """The issue is already public by then; reporting the week as failed
    would be false."""
    def linkedin(prompt):
        raise RuntimeError("claude -p failed")

    final, post, path = _run_tail(tmp_path, lambda *a: None, linkedin)
    assert final.exists()
    assert post is None and path is None
