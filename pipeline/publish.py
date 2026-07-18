"""Approval-gated publishing: promote an edited draft to vault/reports/,
push to GitHub, and put a LinkedIn summary on the clipboard.

Run interactively by the human: python -m pipeline.publish 2026-W29
Nothing in the pipeline calls this automatically — that is the point.
"""

import subprocess
import sys
from pathlib import Path

from . import audit, config, enrich, verify_report, weekly_report

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


def _push_and_draft_linkedin(vault_dir, wid, git=_git, linkedin_runner=enrich.run_claude):
    """Shared tail of both publish paths: commit, push, draft the LinkedIn text.

    LinkedIn text used to only go to the clipboard via clip.exe, which needs an
    interactive session and doesn't exist when Task Scheduler runs this
    unattended — it's now always written to a file too.
    """
    final = approve_draft(vault_dir, wid)
    git("add", str(final))
    git("commit", "-m", f"Publish weekly threat report {wid}")
    git("push")

    post, _ = linkedin_runner(LINKEDIN_PROMPT.format(report=final.read_text(encoding="utf-8")))
    linkedin_dir = Path(vault_dir) / "reports" / "linkedin-drafts"
    linkedin_dir.mkdir(parents=True, exist_ok=True)
    linkedin_path = linkedin_dir / f"{wid}.md"
    linkedin_path.write_text(post, encoding="utf-8")
    return final, post, linkedin_path


def auto_publish(wid, vault_dir=None, verifier=verify_report.verify, git=_git,
                  linkedin_runner=enrich.run_claude):
    """Unattended publish path, run right after the Sunday draft.

    Never touches git unless verifier() passes — a failed check leaves the
    draft exactly where it was (same "quarantine is a queue, not a dead end"
    posture the rest of the pipeline uses for a bad enrichment) and logs why,
    so a failure is never a silent no-op.
    """
    vault_dir = Path(vault_dir) if vault_dir else config.VAULT_DIR
    draft = vault_dir / "reports" / "drafts" / f"{wid}-DRAFT.md"
    if not draft.exists():
        print(f"no draft found at {draft} — nothing to auto-publish")
        return 0

    week_notes = weekly_report.collect_week_notes(vault_dir)
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
    print(f"auto-published {final.name} to GitHub; LinkedIn draft at {linkedin_path}")
    return 0


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("usage: python -m pipeline.publish <YYYY-Wnn>")
        return 2
    wid = argv[0]

    draft = config.VAULT_DIR / "reports" / "drafts" / f"{wid}-DRAFT.md"
    if not draft.exists():
        print(f"no draft found at {draft}")
        return 1

    print(f"About to publish {wid}: commit + push to GitHub and draft a LinkedIn post.")
    print(f"Have you reviewed and edited {draft}?")
    if input("Type 'publish' to confirm: ").strip().lower() != "publish":
        print("aborted — nothing published")
        return 1

    final = approve_draft(config.VAULT_DIR, wid)
    _git("add", str(final))
    _git("commit", "-m", f"Publish weekly threat report {wid}")
    _git("push")
    print(f"pushed {final.name} to GitHub")

    post, _ = enrich.run_claude(LINKEDIN_PROMPT.format(report=final.read_text(encoding="utf-8")))
    subprocess.run(["clip.exe"], input=post, text=True, encoding="utf-8")
    print("\nLinkedIn post copied to clipboard — paste and post when ready:\n")
    print(post)
    return 0


if __name__ == "__main__":
    sys.exit(main())
