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
- Nothing publishes without explicit human approval via `python -m pipeline.publish`.
  Do not add auto-publish paths.
- Secrets live in `.env` only (gitignored). Currently just `ABUSECH_AUTH_KEY`.
- `data/`, `logs/`, `.env`, `vault/reports/drafts/` are gitignored — unapproved drafts and
  raw data never reach GitHub.
- Vault notes are machine-generated; fix generation code, don't hand-edit notes (except
  report drafts, which are meant to be human-edited).

## Commands

- Daily run: `python -m pipeline.run` (options: `--source kev --limit 3` for testing)
- Weekly draft: `python -m pipeline.weekly_report`
- Publish approved report: `python -m pipeline.publish <YYYY-Wnn>`
- Tests: `python -m pytest tests/`
- venv: `.venv\Scripts\Activate.ps1`
