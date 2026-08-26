# Threat Intel Pipeline

Automated threat intelligence pipeline: Python ingests public feeds (CISA KEV, abuse.ch
URLhaus/ThreatFox, malware-traffic-analysis.net RSS) daily, Claude (headless `claude -p`)
enriches each item into structured Obsidian notes in `vault/`, a weekly analyst report is
drafted for human approval before publishing to GitHub + LinkedIn.

## Ground rules

- `skills/threat-analyst.md` is the single source of truth for enrichment voice, note
  template, severity rubric, and the low-confidence rule. `pipeline/enrich.py` embeds it
  into every prompt. Edit it there only.
- Every enrichment is audit-logged to `logs/audit/YYYY-MM-DD.jsonl` (source snapshot vs.
  Claude output). Never skip or weaken the audit trail.
- Publishing happens two ways: explicit human approval via `python -m pipeline.publish
  <week>`, or the unattended `python -m pipeline.publish --auto` path the Sunday scheduled
  task runs automatically. Auto-publish is gated by `pipeline.verify_report`. A verification
  failure blocks the push entirely and leaves the draft untouched for manual review — it
  never fails silently. Never weaken or bypass this check, and never let a broken
  verification call be treated as a pass.
- The gate asks **two different questions**, because the report contains two different kinds
  of writing and judging both by one standard is what broke 2026-W35. Every CVE/ATT&CK ID
  anywhere in the draft must trace to that week's real notes. Beyond that:
  - **Factual sections** (TL;DR, top threats, what changed, sources) — every substantive
    claim must be *directly supported* by the week's notes. Unchanged bar.
  - **The recommendations section** (`## What a small organization should actually do`) —
    checked by `ADVICE_VERIFICATION_PROMPT` instead. Advice is *expected* to go beyond the
    notes; that is the section's purpose. It fails if it invents a fact (count, date,
    deadline, version, exploitation status), contradicts a note, prescribes action on a
    product the week's notes never mention, states an absolute about the world that is
    false, or recommends something that would not reduce exposure to the threat it cites.
  This is not a lower bar for advice — it adds a contradiction check the single-question
  prompt never had. Do not collapse the two prompts back into one.
- Verification runs `VERIFICATION_ROUNDS` (3) times per section and **fails on the union of
  the rounds' objections**. A single pass was observed flagging different subsets of the same
  draft run to run — one claim passed rounds 1-8 and was rejected on round 9 — so one pass
  certifies "passed this roll of the dice", not "passed". A disagreement between rounds
  resolves against publishing: the round that objected is the one that noticed something.
  Lowering the round count or taking a majority instead of a union weakens the gate.
- Secrets live in `.env` only (gitignored): `ABUSECH_AUTH_KEY`, `VT_API_KEY`,
  `ABUSEIPDB_API_KEY`. All optional — each missing key just disables its lookup/feed.
- `data/`, `logs/`, `.env`, `vault/reports/drafts/` are gitignored — unapproved drafts and
  raw data never reach GitHub.
- Vault notes are machine-generated; fix generation code, don't hand-edit notes (except
  report drafts, which are meant to be human-edited).

## Commands

- Daily run: `python -m pipeline.run` (options: `--source kev --limit 3` for testing)
- Weekly draft: `python -m pipeline.weekly_report`
- Publish approved report (human-reviewed): `python -m pipeline.publish <YYYY-Wnn>`
- Auto-publish (verification-gated, unattended): `python -m pipeline.publish --auto`
- Audit summary (cost, quarantine rate, cache hits): `python -m pipeline.stats --days 30`
- ATT&CK Navigator layer: `python -m pipeline.navigator` → `vault/docs/attack-layer.json`
- STIX 2.1 bundles (one per threat note): `python -m pipeline.stix` → `vault/docs/stix/`
- MISP push (optional, needs `MISP_URL`/`MISP_API_KEY`): wired into `pipeline.run` automatically; see `docs/MISP-SETUP.md`
- Refresh the ATT&CK catalog after a MITRE release: `python -m pipeline.attack --refresh`
- Tests: `python -m pytest tests/` · Lint: `python -m ruff check pipeline/ tests/`
- venv: `.venv\Scripts\Activate.ps1`

## Invariants worth not breaking

- `conftest.py` redirects every writable config path to tmp_path for all tests. Without it
  pytest writes into the real audit log — that already happened once.
- Reputation is prompt context, never a precondition: a provider failure must degrade the
  note, not stop the run.
- A feed returning zero items must be distinguishable from a feed that is broken. abuse.ch
  signals failure in `query_status` with HTTP 200 — check the envelope, never the status.
- Only `written` marks an item seen. `quarantined`/`failed` carry over so a fix can rescue
  them; quarantine is a queue, not a dead end.
- `python -m pipeline.run` takes a lock. Two concurrent runs double-enrich and double-bill.
