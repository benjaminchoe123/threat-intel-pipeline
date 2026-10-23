"""Approval-gated publishing: promote an edited draft to vault/reports/,
push to GitHub, and put a LinkedIn summary on the clipboard.

Run interactively by the human: python -m pipeline.publish 2026-W29
Nothing in the pipeline calls this automatically — that is the point.
"""

import subprocess
import sys
from datetime import date
from pathlib import Path

from . import audit, config, enrich, newsletter, verify_report, weekly_report
from .runlock import LockHeld, RunLock

LINKEDIN_PROMPT = """Below is my approved weekly threat intelligence report. Write a LinkedIn
post summarizing it: first person, ~120-180 words, plain English, no hashtag spam (max 3),
no emojis, mention it's from my automated threat-intel pipeline project, and end by inviting
people to read the full report on my GitHub. Return ONLY the post text.

<report>
{report}
</report>"""


def approve_draft(vault_dir, wid):
    """Move reports/drafts/{wid}-DRAFT.md -> reports/{wid}.md with guards."""
    vault_dir = Path(vault_dir)
    draft = vault_dir / "reports" / "drafts" / f"{wid}-DRAFT.md"
    final = vault_dir / "reports" / f"{wid}.md"
    if not draft.exists():
        raise FileNotFoundError(f"no draft at {draft} — run pipeline.weekly_report first")
    if final.exists():
        raise FileExistsError(f"{final} already published — refusing to overwrite")
    final.write_text(draft.read_text(encoding="utf-8"), encoding="utf-8")
    draft.unlink()
    return final


def _git(*args):
    result = subprocess.run(["git", *args], cwd=config.ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _push(git):
    """Push, rebasing once onto the remote if it moved.

    Dependabot merges land on GitHub, not here, so the first Sunday after one
    the local branch is behind and a plain push is rejected. --autostash
    because the vault always has uncommitted generated files. A second failure
    is raised: an issue that did not reach GitHub must not be reported as sent.
    """
    try:
        git("push")
    except RuntimeError as e:
        print(f"push rejected ({e}); rebasing onto origin and retrying once")
        git("pull", "--rebase", "--autostash")
        git("push")


def _push_and_draft_linkedin(vault_dir, wid, git=_git, linkedin_runner=enrich.run_claude):
    """Shared tail of both publish paths: commit, push, draft the LinkedIn text.

    LinkedIn text used to only go to the clipboard via clip.exe, which needs an
    interactive session and doesn't exist when Task Scheduler runs this
    unattended — it's now always written to a file too.
    """
    final = approve_draft(vault_dir, wid)
    paths = [str(final)]
    # The newsletter issue rides in the same commit, so the report and its
    # issue go live together. Best-effort: the report is what was approved and
    # verified, and a page that fails to build must not hold it back.
    try:
        paths.append(str(newsletter.build_issue_page(vault_dir, wid)))
    except Exception as e:
        print(f"newsletter issue not written for {wid}: {e} — the report still "
              f"publishes; rebuild with `python -m pipeline.newsletter --github-all`")
    git("add", *paths)
    # Path-limited: this commit is the week's issue and nothing else. A bare
    # commit takes the whole index, and the vault's unpublished backlog lives
    # one `git add` away from it.
    git("commit", "-m", f"Publish weekly threat report {wid}", "--", *paths)
    _push(git)

    # The issue is public from here on. A LinkedIn failure is reported, but it
    # must not turn a published week into a failed one.
    try:
        post, _ = linkedin_runner(
            LINKEDIN_PROMPT.format(report=final.read_text(encoding="utf-8")))
    except Exception as e:
        print(f"LinkedIn draft not written for {wid}: {e} — {final.name} is published")
        return final, None, None
    linkedin_dir = Path(vault_dir) / "reports" / "linkedin-drafts"
    linkedin_dir.mkdir(parents=True, exist_ok=True)
    linkedin_path = linkedin_dir / f"{wid}.md"
    linkedin_path.write_text(post, encoding="utf-8")
    return final, post, linkedin_path


def auto_week_id(today=None):
    """The week `--auto` drafts and publishes, from one shared anchor.

    The draft and the publish are two processes minutes apart, and each used to
    call week_id(date.today()) for itself. A run starting at 23:59 on Sunday
    would draft one week and then go looking for another. Anchored to the
    completed week, both land on the same Sunday however long the gap.
    """
    return weekly_report.week_id(weekly_report.report_week_end(today or date.today()))


def auto_publish(wid, vault_dir=None, verifier=verify_report.verify, git=_git,
                  linkedin_runner=enrich.run_claude, min_notes=None):
    """Unattended publish path, run right after the Sunday draft.

    Never touches git unless verifier() passes — a failed check leaves the
    draft exactly where it was (same "quarantine is a queue, not a dead end"
    posture the rest of the pipeline uses for a bad enrichment) and logs why,
    so a failure is never a silent no-op.

    A week below `min_notes` is held before verification. The verifier answers
    "is this draft faithful to its notes?" and a two-note draft can pass that
    honestly — 2026-W42 did — while still not being a week of intelligence.
    Holding returns 0: it is the pipeline declining, not failing, and the
    human path (`publish <week>`) can still ship it.
    """
    vault_dir = Path(vault_dir) if vault_dir else config.VAULT_DIR
    min_notes = config.MIN_NOTES_FOR_AUTO_PUBLISH if min_notes is None else min_notes
    draft = vault_dir / "reports" / "drafts" / f"{wid}-DRAFT.md"
    if not draft.exists():
        print(f"no draft found at {draft} — nothing to auto-publish")
        return 0

    week_notes = weekly_report.collect_week_notes(vault_dir)
    if len(week_notes) < min_notes:
        audit.log_enrichment(config.AUDIT_DIR, {
            "type": "auto_publish_held", "week": wid,
            "notes": len(week_notes), "min_notes": min_notes,
        })
        print(f"{wid} held for review — {len(week_notes)} note(s), below the "
              f"auto-publish floor of {min_notes}; draft untouched")
        return 0

    result = verifier(draft.read_text(encoding="utf-8"), week_notes)
    audit.log_enrichment(config.AUDIT_DIR, {
        "type": "auto_publish_verification", "week": wid,
        "passed": result.passed, "report": result.report(),
    })
    print(result.report())
    if not result.passed:
        print(f"verification failed — {wid} left unpublished, draft untouched")
        return 1

    final, post, linkedin_path = _push_and_draft_linkedin(
        vault_dir, wid, git=git, linkedin_runner=linkedin_runner
    )
    print(f"auto-published {final.name} to GitHub"
          + (f"; LinkedIn draft at {linkedin_path}" if linkedin_path else ""))
    return 0


def main(argv=None, confirm=input):
    argv = argv if argv is not None else sys.argv[1:]
    if argv == ["--auto"]:
        # Under the same lock the draft used. This step git-adds and pushes the
        # vault, so a daily run writing notes underneath it would commit a
        # half-written tree. Waiting, not skipping: see RunLock's docstring.
        try:
            with RunLock(config.DATA_DIR / "run.lock",
                         wait_seconds=weekly_report.WEEKLY_LOCK_WAIT_SECONDS):
                return auto_publish(auto_week_id())
        except LockHeld as e:
            print(f"not published — {e}", file=sys.stderr)
            return 1

    if len(argv) != 1:
        print("usage: python -m pipeline.publish <YYYY-Wnn>  |  python -m pipeline.publish --auto")
        return 2
    wid = argv[0]

    draft = config.VAULT_DIR / "reports" / "drafts" / f"{wid}-DRAFT.md"
    if not draft.exists():
        print(f"no draft found at {draft}")
        return 1

    week_notes = weekly_report.collect_week_notes(config.VAULT_DIR)
    result = verify_report.verify(draft.read_text(encoding="utf-8"), week_notes)
    print("Verification:")
    print(result.report())
    print()

    print(f"About to publish {wid}: commit + push to GitHub and draft a LinkedIn post.")
    print(f"Have you reviewed and edited {draft}?")
    if confirm("Type 'publish' to confirm: ").strip().lower() != "publish":
        print("aborted — nothing published")
        return 1

    final, post, linkedin_path = _push_and_draft_linkedin(config.VAULT_DIR, wid)
    print(f"pushed {final.name} to GitHub")
    if post is None:
        return 0
    print(f"LinkedIn draft saved to {linkedin_path}")
    subprocess.run(["clip.exe"], input=post, text=True, encoding="utf-8")
    print("\nAlso copied to clipboard — paste and post when ready:\n")
    print(post)
    return 0


if __name__ == "__main__":
    sys.exit(main())
