# Postmortem: 19 days of silent enrichment failure

**Date:** 2026-08-23 · **Impact window:** 2026-08-02 → 2026-08-23 · **Status:** mitigated,
one hypothesis still unconfirmed

## Summary

Every enrichment call failed for roughly two weeks. The pipeline kept fetching feeds, kept
exiting with the correct non-zero status, and kept writing an audit record for each failure —
and no surface a human looks at said anything was wrong. The vault dashboard rendered the
outage identically to a quiet week. Four weekly reports (2026-W31 through W34) were never
drafted. The public repository advertised a project whose newest output was 2026-08-04.

Nobody noticed until someone asked an unrelated question 19 days later.

## Impact

- **19 days** with no new threat notes (newest was 2026-08-04).
- **4 weekly reports missed** — 2026-W31, W32, W33, W34. Not recoverable: month-old feed
  snapshots cannot be honestly enriched after the fact, so these weeks stay gaps rather than
  being backfilled.
- No data loss. Un-enriched items were correctly carried over rather than marked seen, so
  nothing was silently dropped — `_update_state()` only records `written`.
- No incorrect intelligence published. The failure mode was silence, not wrong answers.

## Timeline

| Date | Event |
|---|---|
| 2026-08-02 | First all-fail run. 5 items attempted, 5 failed. |
| 2026-08-03 | 5 attempted, 5 failed. |
| 2026-08-04 | Partial success — **the last real output the pipeline ever produced**. |
| 2026-08-05 → 08-18 | Every run writes 0 notes. 08-18 attempts 15, fails 15. |
| 2026-08-17 | Weekly task runs, correctly logs `2026-W34: no threat notes in the last 7 days`, writes no draft. Auto-publish finds no draft and stops. |
| 2026-08-19 → 08-22 | No runs at all — desktop powered off. No logs, no signal. |
| 2026-08-23 | Outage discovered while auditing what could be published to GitHub. Root-caused, mitigated, detection added. |

## Root cause

Enrichment shells out to headless Claude Code (`claude -p`), which authenticates from the
interactive CLI's OAuth credentials. Those credentials carry a short-lived access token — the
file on disk shows an **8-hour** `expiresAt` against a refresh token good for a month.

The machine went unattended for about four weeks. In that window nothing refreshed the
credentials interactively, and the unattended scheduled task could not obtain a usable token
on its own. `claude -p` exited 1 on every invocation.

**Honesty about the evidence:** this is the best-supported explanation, not an observed one.
The improved error logging (below) shipped *after* the failure stopped reproducing — the first
run following an interactive login succeeded immediately, on the first attempt, with no code
change to the enrichment path. What is directly established: it failed on every unattended run
for two weeks, it worked instantly once credentials were fresh, and the token lifetime is 8
hours. The precise CLI-side error was never captured, because of contributing cause #1.

### Contributing cause 1 — the error message threw away the error

```python
raise EnrichmentError(f"claude -p failed ({result.returncode}): {result.stderr[:500]}")
```

`claude -p --output-format json` writes its payload to **stdout**, error payloads included.
This line reported stderr and discarded stdout. Every one of the ~100 failures therefore
recorded itself, in both the log and the audit trail, as:

```
claude -p failed (1):
```

Nothing after the colon. Two weeks of failures produced zero diagnostic information, and the
one artifact that would have identified the cause on day one was destroyed at the point of
capture. Fixing an error path is not glamorous work; the cost of not fixing it was the entire
investigation.

### Contributing cause 2 — correct signals with no consumer

The exit code was already right. `run.cli()` exits 1 when anything fails — a deliberate
earlier fix, with a docstring explaining that a broken run must not look like a quiet day. It
worked. 2026-08-18 exited 1.

But an exit code is only a signal if something reads it, and nothing did. Worse, the two
surfaces that *are* read daily both actively disguised the failure:

- `vault/home.md` printed `*(none in the last 7 days)*` — the same text a genuinely quiet
  week produces.
- `pipeline/weekly_report.py` printed `no threat notes in the last 7 days — no draft written`
  and returned cleanly. Correct behavior for a quiet week; the wrong silence for a dead one.

The report chain was never broken. It was **starved of input**, and reported starvation in
the vocabulary of calm.

## What changed

1. **`pipeline/enrich.py`** — the failure path now reports stdout *and* stderr, labelled and
   truncated. The next occurrence identifies itself.

2. **`pipeline/health.py`** (new) — a pure, clock-injectable assessment over two independent
   signals, because either alone lies:
   - *note staleness* (the symptom) — survives the pipeline not running at all, which no
     run-reported metric can.
   - *last-run totals* (the cause) — separates "nothing published because nothing happened"
     from "15 items fetched and all 15 failed".

   Threshold: 3 days with no new note. One quiet day is normal; two is a weekend.

3. **`data/last_run.json`** — a heartbeat written at the end of every run, including failed
   ones. The run that most needs evidence is precisely the one that leaves no trace in the
   vault.

4. **The two lying surfaces now tell the truth.** `vault/home.md` carries a health banner at
   the top, and the weekly report's skip path prints the health state and writes a
   `weekly_report_skipped` audit record naming the newest note's real date.

5. **Tests** — 19 new, every one with a pinned clock. They include a negative test seeded with
   the exact state of disk on 2026-08-23 (newest note 08-04, last run 0 written / 15 failed)
   asserting the dashboard renders `DEGRADED`. A detection that has never been proven to fire
   is not a detection.

## Still open

The mitigation refreshed the credentials; it did not remove the dependency on them. The
current access token expires **2026-08-24 07:02**, and the daily task fires at **08:00** — one
hour later. That run is the first genuine test of whether the scheduler can refresh on its
own, and the new health banner is what will report the answer without anyone watching.

If it fails, the durable fix is to stop depending on an interactive login for an unattended
job: move enrichment to the Anthropic API with a key in `.env`, alongside the four service
keys already handled that way. That trades a subscription for metered billing, so it is a
deliberate decision rather than an automatic one.

## What this actually taught me

The bug I would have predicted was in the enrichment logic. The bug that cost 19 days was in
the `except` branch — the code that runs only when something else has already gone wrong, and
that nobody tests because by definition it only executes on a bad day.

Related: the exit code was correct and useless. Getting a signal *right* is only half of it;
somebody has to be listening. Automation that reports failure to a channel nobody reads has
the same operational value as automation that does not report failure at all.
