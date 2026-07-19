# Signal & Noise newsletter — launch + prep step design

Date: 2026-07-19. Status: approved.

## Goal

Launch a free weekly threat-intel newsletter, **Signal & Noise**, on Substack, sourced from
this pipeline's human-approved weekly reports, and add a small repeatable prep step so each
future issue is a two-minute paste.

Audience: small orgs / IT generalists — the same plain-English, action-first voice the
weekly reports already use. A paid tier is explicitly out of scope for now.

## Components

### 1. `pipeline/newsletter.py` (new, standalone)

- CLI: `python -m pipeline.newsletter <YYYY-Wnn>`.
- Reads the **published** report at `vault/reports/<wid>.md`. Refuses drafts: if only
  `vault/reports/drafts/<wid>-DRAFT.md` exists, exit non-zero with a message telling the
  user to run `pipeline.publish <wid>` first. Missing week entirely → non-zero, clear error.
- Wraps the report body with newsletter boilerplate:
  - masthead intro line (what Signal & Noise is, one sentence),
  - link to the full report on GitHub (`https://github.com/benjaminchoe123/threat-intel-pipeline`),
  - subscribe CTA,
  - standard footer (how the pipeline works, human-reviewed disclosure).
- Writes `vault/reports/newsletter/<wid>-substack.md`, creating the directory as needed.
  Refuses to overwrite an existing output file (same guard style as `approve_draft`).
- Pure text transformation: no network, no Claude calls, no changes to
  `publish.py`/`verify_report.py`.

### 2. Issue #1 content (hand-drafted, not generated)

One Substack post: short intro (who Big Ben is, what the pipeline is, why it's credible —
the honest "what went wrong" framing) followed by the 2026-W29 report content. Drafted by
Claude, reviewed and pasted by Big Ben. Prerequisite: W29 must first be published via
`python -m pipeline.publish 2026-W29` (human-gated), so the newsletter links to a public
report, not a gitignored draft.

### 3. Substack setup (human steps)

Account/publication creation, about text, welcome email, and every publish action are Big
Ben's — same human-gate rule as `pipeline.publish`. Claude pre-drafts all copy. Substack has
no posting API; the manual paste is the enforcement mechanism, not a limitation to engineer
around.

## Testing

TDD, matching existing test style (`tmp_path` isolation via `conftest.py`):

- happy path: published report in, output file contains boilerplate + intact report body;
- refuses when only a draft exists (non-zero, actionable message);
- refuses when the week doesn't exist at all;
- refuses to overwrite existing output.

Existing suite (331 tests) must stay green.

## Out of scope

Paid tier, Substack automation/API integration, changes to the publish/verification path,
social-media cross-posting.
