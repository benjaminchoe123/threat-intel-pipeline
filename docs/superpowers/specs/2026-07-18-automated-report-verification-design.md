# Automated report verification + unattended publish

## Context

Weekly threat reports are drafted automatically (`pipeline.weekly_report`, Sunday via Task
Scheduler) but currently require a human at the keyboard to run
`python -m pipeline.publish <week>` and type `publish` to confirm before anything reaches
GitHub. `CLAUDE.md` states this deliberately: "Nothing publishes without explicit human
approval... Do not add auto-publish paths."

Big Ben asked to remove the requirement that he be present to publish, including while his
computer is off. Two things were clarified before designing this:

- **Computer-off scope**: the whole pipeline (ingestion, enrichment, drafting) already
  requires the local Windows machine to be on via Task Scheduler; that is not changing.
  Migrating to cloud hosting (e.g. GitHub Actions) was explicitly declined — it would move
  API keys into CI secrets and replace the subscription-based headless `claude -p` billing
  model with metered API billing, at the cost of solving a "computer off" scenario the
  pipeline doesn't otherwise support anyway. **Decision: stays local, Task Scheduler as-is.**
- **Review gate**: rather than truly zero review, an automated consistency check stands in
  for a human when Big Ben isn't present to review personally. This is grounded in two real
  past incidents where a human catch — not a test — stopped a wrong claim from reaching the
  public repo: the README's "flagship anecdote" was actually a mis-filed bug, and EPSS scores
  of 0.99999 were rendering as "100.0% probability," a certainty the model never claimed.
  Both were caught by a human looking at output, not by any automated check that existed at
  the time. **Decision: build the automated check the project never had, rather than skip
  review entirely.**

Researched the right technique rather than inventing one: SelfCheckGPT-style
sampling-consistency checks apply when there is no ground truth to check against. This
pipeline has ground truth for every report claim — the week's audit-logged, ATT&CK/EPSS/
VT-validated threat notes it drafts from. That makes this a **FActScore-style** problem:
decompose the generated text into atomic factual claims, verify each against a reference
source. This also matches a pattern the pipeline already uses elsewhere (`pipeline/attack.py`
validates every ATT&CK ID against a real catalog instead of trusting the model's freeform
output) — extending "don't trust the model, verify against ground truth" from note
enrichment to report drafting.

## Architecture

New module `pipeline/verify_report.py`, invoked before every publish — both the unattended
scheduled path and the human-triggered path (chat or terminal) run through the same
verification, so there is one code path for "is this draft safe to publish," not two.

Two check types:

1. **Deterministic entity check.** Every CVE ID, malware family name, ATT&CK technique ID,
   and severity level cited in the draft must match an entry actually present in that week's
   notes, per `weekly_report.collect_week_notes()`. This is a membership/lookup check, not an
   LLM judgment call — the same "validate against a real catalog" philosophy `pipeline/
   attack.py` already applies to technique IDs.
2. **Atomic-claim check.** For prose that isn't a structured entity (e.g. "what a small
   organization should actually do" recommendations, "what changed vs. prior weeks"), decompose
   the draft into atomic claims and verify each against the week's note bodies. **Deviates from
   the FActScore paper's per-fact verification calls**: this pipeline tracks cost per `claude`
   call (`pipeline.stats`) and specifically chose subscription-based headless Claude to avoid
   metered billing, so decomposition and verification happen in a single `enrich.run_claude()`
   call with a strict prompt, not one call per atomic claim. Returns a list of
   `{claim, supported: bool, reason}` parsed from that one structured response.

**Result:** any deterministic mismatch, or any atomic claim marked `supported: false`, fails
verification as a whole. A single flagged claim blocks the entire publish — the same
all-or-nothing posture the pipeline already takes on quarantining a bad enrichment rather than
partially trusting it.

## Components

### `pipeline/verify_report.py` (new)

- `extract_entities(draft_text) -> set[Entity]` — regex/structured parse of CVE IDs, family
  names, ATT&CK IDs, severity words from the draft.
- `check_entities(entities, week_notes) -> list[Mismatch]` — deterministic set-membership
  check against `collect_week_notes()`'s ground truth.
- `extract_and_verify_claims(draft_text, week_notes) -> list[ClaimResult]` — one
  `enrich.run_claude()` call, structured verification prompt, parses the `{claim, supported,
  reason}` list back out the same way `enrich.py` already parses structured model output.
- `verify(draft_text, week_notes) -> VerificationResult` — combines both checks; `.passed`
  is `False` if either check found any problem; `.report()` renders a human-readable summary
  (used both in the audit log and shown to a human in the interactive path).

### `pipeline/publish.py` (changed)

- `auto_publish(wid)` — new entrypoint for the unattended path. Runs `verify_report.verify()`
  first.
  - **Pass:** does exactly what today's manual path does after confirmation — `approve_draft`,
    git add/commit/push. No `input()` prompt; nothing interactive.
  - **Fail:** no git operations at all. Draft stays in `drafts/` untouched (same "quarantine
    is a queue, not a dead end" posture the pipeline already applies to failed enrichments).
    Appends a clear entry to the audit log with the verification failure reason(s) — never a
    silent skip, matching the pipeline's own hard-learned rule about distinguishing "nothing to
    do" from "something went wrong."
- `main()` (existing interactive path, reached whether typed at a raw terminal or triggered by
  saying "publish" in a Claude Code chat session) — now runs the same `verify_report.verify()`
  first and prints/shows the result before the existing "type 'publish' to confirm" prompt, so
  the human sees what was checked, not just the bare draft.
- LinkedIn draft generation: replace `clip.exe` (requires an interactive session, doesn't exist
  headlessly) with writing the text to `vault/reports/linkedin-drafts/{wid}.md` in both paths.
  The interactive path may additionally copy it to the clipboard as a convenience.

### Scheduling

Extend `register_tasks.ps1`'s existing Sunday weekly-report task to chain
`python -m pipeline.publish --auto` immediately after drafting. No new scheduling
infrastructure — same Task Scheduler mechanism the rest of the pipeline already uses.

## Data flow

```
weekly_report.draft_report()  (Sunday, Task Scheduler — unchanged)
        |
        v
drafts/{wid}-DRAFT.md
        |
        v
verify_report.verify(draft, week_notes)
   |-- fail --> audit log entry, draft left in place, nothing pushed
   |
   `-- pass --> approve_draft() -> git add/commit/push -> linkedin-drafts/{wid}.md written
```

The human-triggered path (chat "publish" or terminal) is the same diagram, entered manually
instead of via Task Scheduler, with the verification result additionally shown to the human
before the existing confirm prompt.

## Error handling

- A provider/Claude-call failure inside the atomic-claim check must not silently pass the
  draft — treat a failed verification call as `verify.passed = False` with a distinct reason
  ("verification call failed"), not as "no claims flagged." Degrading to auto-publish on a
  broken checker would defeat the entire point of the feature.
- `auto_publish` failures are visible in Task Scheduler's run history (non-zero exit + a
  logged reason) and in the audit log — never just an exit-0 no-op, the same failure mode
  already fixed once for abuse.ch's silent `illegal_auth_key` responses.

## Testing

TDD, per the repo's existing convention:

- `check_entities` catches a CVE/family/ATT&CK ID cited in the draft that isn't in the week's
  actual notes.
- `extract_and_verify_claims` catches an unsupported claim (mocked `enrich.run_claude()`).
- `verify()` fails as a whole if either sub-check fails; passes only if both pass.
- `auto_publish` never invokes git when `verify()` fails.
- `auto_publish` performs the same git sequence as today's manual path when `verify()` passes.
- `main()`'s interactive path is unchanged in behavior except for showing verification output
  before the confirm prompt.
- A verification-call failure (exception/malformed response) is treated as a failed check, not
  a pass.
