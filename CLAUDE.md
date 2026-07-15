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
- Secrets live in `.env` only (gitignored): `ABUSECH_AUTH_KEY`, `VT_API_KEY`,
  `ABUSEIPDB_API_KEY`. All optional — each missing key just disables its lookup/feed.
- `data/`, `logs/`, `.env`, `vault/reports/drafts/` are gitignored — unapproved drafts and
  raw data never reach GitHub.
- Vault notes are machine-generated; fix generation code, don't hand-edit notes (except
  report drafts, which are meant to be human-edited).

## Commands

- Daily run: `python -m pipeline.run` (options: `--source kev --limit 3` for testing)
- Weekly draft: `python -m pipeline.weekly_report`
- Publish approved report: `python -m pipeline.publish <YYYY-Wnn>`
- Audit summary (cost, quarantine rate, cache hits): `python -m pipeline.stats --days 30`
- ATT&CK Navigator layer: `python -m pipeline.navigator` → `vault/docs/attack-layer.json`
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
