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
- Observed ATT&CK techniques, for `ruleproof gap`: `python -m pipeline.techniques`
  (`--report` for the confirmed/flagged split, `--confirmed-only` to export just
  the sightings from notes the enrichment did not flag)
- MISP push (optional, needs `MISP_URL`/`MISP_API_KEY`): wired into `pipeline.run` automatically; see `docs/MISP-SETUP.md`
- Refresh the ATT&CK catalog after a MITRE release: `python -m pipeline.attack --refresh`
- Health, without running anything: `python -m pipeline.health` (0 healthy, 1 not)
- Register/repair the scheduled tasks: `scripts/register_tasks.ps1` (**needs an elevated prompt** — see `docs/OPERATIONS.md`)
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
  The weekly takes the **same** lock, with the opposite policy on finding it held: the daily
  gives up and exits 0 because another run is already doing its job, while the weekly waits,
  because nobody else is going to write that report and skipping would turn a collision into
  a silently missing week. Both are pinned by tests — do not tidy them into agreement.
  `-MultipleInstances IgnoreNew` does not cover this: it is per-task, and `-StartWhenAvailable`
  fires both deferred triggers at the same instant on wake, which is what happened on
  2026-08-31.
- **A report's week comes from the notes it summarises, never from `date.today()`.** The same
  wall-clock-into-content defect as the STIX timestamps above. `report_week_end()` anchors to
  the most recent *completed* ISO week, so a run deferred into Monday produces the report it
  would have produced on Sunday, and `collect_week_notes` uses that closed Mon–Sun window
  rather than a trailing seven days. That window is also what stops a concurrent daily from
  changing what a weekly is summarising: today's notes fall after a completed week has closed.
  `publish --auto` derives the week from the same anchor so a run straddling midnight cannot
  draft one week and publish another.
- Health has **three** independent signals and each is blind to something the others catch:
  note staleness (survives the pipeline not running), the heartbeat (a start with no finish is
  a run that died partway), and `pipeline.scheduler` (the OS's own record — the only observer
  of a run that died *before* it could write anything). Only NTSTATUS-range results
  (`>= 0xC0000000`) count as failures there; the daily exits 1 whenever one item fails, and a
  banner that is red most weeks is one nobody reads. `assess()` stays pure and takes the
  reading as an argument, which also keeps transient scheduler state out of the committed
  dashboard.
- A `claude -p` failure that spent **zero tokens** is `EngineUnavailable`, not a normal
  enrichment failure: a bad prompt still burns input tokens, so zero means auth, quota or a
  usage limit. The run abandons itself on the first one rather than rediscovering it fourteen
  more times at a subprocess and a retry each. Errors report the parsed `result`/`is_error`,
  never a truncated head of raw JSON — those fields sit late in the payload, which is how the
  2026-08-31 failure recorded a `usage` block and nothing about why.
- Scheduled tasks are registered **S4U** (run whether or not the user is logged on). The
  default, `Interactive`, ties the run to the login session and kills it with
  `0xC000013A` — three times before this was found. Registering needs an elevated prompt; see
  `docs/OPERATIONS.md`.
- Generated artifacts must be **byte-stable when nothing changed**. `pipeline.stix` and
  `pipeline.navigator` rebuild every file from scratch on every ingest, so any wall-clock
  value in the output restamps ~80 unchanged notes as modified today. That is not diff
  noise: STIX consumers (MISP, TIPs) dedupe and diff on `modified`, so a regenerated
  timestamp is a false claim a machine acts on. Timestamps come from the note's own date;
  ids are derived (uuid5), never minted. `tests/test_stix.py` asserts a re-export of an
  unchanged note is byte-identical — keep it that way.
