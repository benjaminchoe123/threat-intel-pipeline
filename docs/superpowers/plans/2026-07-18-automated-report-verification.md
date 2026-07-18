# Automated Report Verification + Unattended Publish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the weekly threat report publish itself unattended (Sunday, Task Scheduler) by gating the push behind an automated FActScore-style claim-verification check, while the existing human-triggered path (terminal or a "publish" chat message) now shows that same check's findings before asking for confirmation.

**Architecture:** A new `pipeline/verify_report.py` module checks a draft two ways: (1) deterministically, every `CVE-####-####` and `T####[.###]` ATT&CK ID cited in the draft must appear in that week's actual notes; (2) via one Claude call, the draft's other substantive claims (recommendations, "what changed" statements, etc.) are checked against the week's note bodies and returned as `{claim, supported, reason}`. `pipeline/publish.py` gets a new `auto_publish()` entrypoint that runs this check and only pushes to GitHub if it passes; the existing interactive `main()` runs the same check and displays it, but does not block on it — a present human retains final judgment.

**Tech Stack:** Python 3, pytest, PyYAML (already a dependency), the existing `enrich.run_claude` headless-Claude wrapper. No new dependencies.

## Global Constraints

- TDD: write the failing test before the implementation, for every Python change.
- Tests: `python -m pytest tests/` · Lint: `python -m ruff check pipeline/ tests/` — run both before every commit.
- `conftest.py`'s `isolate_production_paths` fixture is autouse — tests never touch the real `logs/`, `vault/`, or `data/` directories, but functions under test still take explicit `vault_dir`/`audit_dir` parameters where the existing code does (follow the pattern already in `weekly_report.draft_report(vault_dir, ...)`).
- Follow the codebase's existing dependency-injection convention for anything that calls out (Claude, git): default parameters like `runner=enrich.run_claude`, never `unittest.mock.patch`. This mirrors `weekly_report.draft_report`'s `runner` parameter.
- A verification-call failure (bad JSON, exception, malformed shape) must be treated as a **failed** check, never as "no problems found." This is the same failure mode already fixed once for abuse.ch's silent `illegal_auth_key` 200-OK responses — never let an error look like success.
- **Deviation from the design spec, recorded here for the next reader:** the spec's deterministic check lists "CVE ID, malware family name, ATT&CK technique ID, and severity level." Family names and severity framing don't have a fixed regex shape the way CVE IDs (`CVE-\d{4}-\d{4,7}`) and ATT&CK IDs (`T\d{4}(\.\d{3})?`) do, so extracting them reliably needs semantic judgment, not pattern matching. This plan folds family-name and severity-framing verification into the atomic-claim (Claude) check instead of forcing them through a regex that would either miss real problems or false-positive on ordinary prose. The deterministic check covers exactly CVE IDs and ATT&CK IDs.

---

### Task 1: Deterministic entity check

**Files:**
- Create: `pipeline/verify_report.py`
- Test: `tests/test_verify_report.py`

**Interfaces:**
- Produces: `extract_entities(draft_text: str) -> dict[str, set[str]]` with keys `"cve"` and `"attack_techniques"`.
- Produces: `check_entities(entities: dict[str, set[str]], week_notes: list[dict]) -> list[str]` — human-readable mismatch strings, `[]` if none. `week_notes` elements are the dicts `weekly_report.collect_week_notes()` returns (frontmatter dict + `_body`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_verify_report.py
from pipeline.verify_report import check_entities, extract_entities

WEEK_NOTES = [
    {"cve": ["CVE-2026-1111"], "attack_techniques": ["T1059"], "family": ["AdaptixC2"],
     "_body": "# AdaptixC2\n\nUses T1059 execution. CVE-2026-1111 exploited in the wild."},
]


def test_extract_entities_finds_cve_and_attack_ids():
    text = "This week features CVE-2026-1111 and technique T1059.001 heavily."
    entities = extract_entities(text)
    assert entities["cve"] == {"CVE-2026-1111"}
    assert entities["attack_techniques"] == {"T1059.001"}


def test_extract_entities_empty_on_no_matches():
    entities = extract_entities("Nothing structured mentioned here.")
    assert entities["cve"] == set()
    assert entities["attack_techniques"] == set()


def test_check_entities_passes_when_all_cited_ids_are_known():
    entities = {"cve": {"CVE-2026-1111"}, "attack_techniques": {"T1059"}}
    assert check_entities(entities, WEEK_NOTES) == []


def test_check_entities_flags_unknown_cve():
    entities = {"cve": {"CVE-2026-9999"}, "attack_techniques": set()}
    mismatches = check_entities(entities, WEEK_NOTES)
    assert len(mismatches) == 1
    assert "CVE-2026-9999" in mismatches[0]


def test_check_entities_flags_unknown_attack_id():
    entities = {"cve": set(), "attack_techniques": {"T9999"}}
    mismatches = check_entities(entities, WEEK_NOTES)
    assert len(mismatches) == 1
    assert "T9999" in mismatches[0]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_verify_report.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pipeline.verify_report'`

- [ ] **Step 3: Write minimal implementation**

```python
# pipeline/verify_report.py
"""Automated draft verification: catch a wrong claim before it reaches GitHub
unattended, the way a human review used to be the only thing that did.

Two past incidents in this repo were caught by a human looking at output, not
by any test: the README's "flagship anecdote" was actually a mis-filed bug,
and EPSS scores of 0.99999 rendered as "100.0% probability" — a certainty the
model never claimed. This module is the automated stand-in for that human
catch when nobody is at the keyboard to publish.

FActScore-style, not SelfCheckGPT-style: this pipeline has real ground truth
for every report claim (the week's audit-logged, ATT&CK/EPSS/VT-validated
threat notes), so verification means checking claims against that reference,
not sampling the model against itself.
"""

import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_entities(draft_text):
    """Structured IDs cited in the draft — the only entities with a fixed
    enough shape to check without semantic judgment. See the deviation note
    in the plan for why family names and severity aren't handled here."""
    return {
        "cve": set(CVE_RE.findall(draft_text)),
        "attack_techniques": set(ATTACK_ID_RE.findall(draft_text)),
    }


def check_entities(entities, week_notes):
    """Every cited CVE/ATT&CK ID must trace to one of this week's real notes."""
    known_cves = set()
    known_techniques = set()
    for note in week_notes:
        known_cves.update(note.get("cve") or [])
        known_techniques.update(str(t) for t in (note.get("attack_techniques") or []))

    mismatches = []
    for cve in sorted(entities["cve"] - known_cves):
        mismatches.append(f"draft cites {cve}, which is not in any of this week's notes")
    for tid in sorted(entities["attack_techniques"] - known_techniques):
        mismatches.append(f"draft cites {tid}, which is not in any of this week's notes")
    return mismatches
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_verify_report.py -v`
Expected: 5 passed

- [ ] **Step 5: Lint and commit**

```bash
python -m ruff check pipeline/verify_report.py tests/test_verify_report.py
git add pipeline/verify_report.py tests/test_verify_report.py
git commit -m "Add deterministic CVE/ATT&CK ID verification for weekly report drafts"
```

---

### Task 2: Atomic-claim check via Claude

**Files:**
- Modify: `pipeline/verify_report.py`
- Test: `tests/test_verify_report.py`

**Interfaces:**
- Consumes: `enrich.run_claude(prompt, timeout=300) -> (text, engine_meta)` and `enrich._strip_code_fence(text) -> text` (both already exist, `pipeline/enrich.py:76` and `:116`).
- Produces: `class VerificationError(RuntimeError)`.
- Produces: `extract_and_verify_claims(draft_text: str, week_notes: list[dict], runner=enrich.run_claude) -> list[dict]`, each dict `{"claim": str, "supported": bool, "reason": str}`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_verify_report.py
import pytest

from pipeline.verify_report import VerificationError, extract_and_verify_claims


def test_extract_and_verify_claims_parses_runner_response():
    def fake_runner(prompt):
        assert "AdaptixC2" in prompt  # week's note bodies are in the prompt
        return (
            '[{"claim": "AdaptixC2 uses T1059", "supported": true, "reason": "matches note"}]',
            {},
        )
    results = extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)
    assert results == [
        {"claim": "AdaptixC2 uses T1059", "supported": True, "reason": "matches note"}
    ]


def test_extract_and_verify_claims_strips_code_fence():
    def fake_runner(prompt):
        return ('```json\n[{"claim": "x", "supported": false, "reason": "no source"}]\n```', {})
    results = extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)
    assert results[0]["supported"] is False


def test_extract_and_verify_claims_raises_on_invalid_json():
    def fake_runner(prompt):
        return ("not json", {})
    with pytest.raises(VerificationError):
        extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)


def test_extract_and_verify_claims_raises_on_non_list():
    def fake_runner(prompt):
        return ('{"claim": "x"}', {})
    with pytest.raises(VerificationError):
        extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)


def test_extract_and_verify_claims_raises_on_malformed_entry():
    def fake_runner(prompt):
        return ('[{"claim": "x"}]', {})  # missing "supported"
    with pytest.raises(VerificationError):
        extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_verify_report.py -v`
Expected: FAIL — `ImportError: cannot import name 'VerificationError'`

- [ ] **Step 3: Write minimal implementation**

```python
# add to pipeline/verify_report.py, after the imports
import json

from . import enrich

CLAIM_VERIFICATION_PROMPT = """You are fact-checking a draft weekly threat intelligence \
report against the source threat notes it was supposed to be drafted from. Identify the \
report's substantive claims (recommendations, "what changed" statements, severity framing, \
any other assertion beyond a bare structured ID) and judge whether each is directly \
supported by the source notes below.

<source-notes count="{count}">
{notes_blob}
</source-notes>

<draft-report>
{draft_text}
</draft-report>

Return ONLY a JSON array, no markdown fence, no commentary. Each element:
{{"claim": "<the atomic claim, quoted or closely paraphrased from the report>", \
"supported": true or false, "reason": "<one sentence: what supports it, or why it doesn't>"}}

If the report makes no claims beyond what the source notes already state, return []."""


class VerificationError(RuntimeError):
    """The verification call did not return a usable result.

    Raised, never swallowed into a default pass — a broken checker must look
    like a failed check, not like a clean one."""


def extract_and_verify_claims(draft_text, week_notes, runner=enrich.run_claude):
    notes_blob = "\n\n---\n\n".join(n["_body"] for n in week_notes)
    prompt = CLAIM_VERIFICATION_PROMPT.format(
        count=len(week_notes), notes_blob=notes_blob, draft_text=draft_text
    )
    response_text, _ = runner(prompt)
    text = enrich._strip_code_fence(response_text)
    try:
        claims = json.loads(text)
    except json.JSONDecodeError as e:
        raise VerificationError(f"claim verification response was not valid JSON: {e}") from e
    if not isinstance(claims, list):
        raise VerificationError("claim verification response was not a JSON array")

    results = []
    for c in claims:
        if not isinstance(c, dict) or "claim" not in c or "supported" not in c:
            raise VerificationError(f"malformed claim entry: {c!r}")
        results.append({
            "claim": c["claim"],
            "supported": bool(c["supported"]),
            "reason": c.get("reason", ""),
        })
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_verify_report.py -v`
Expected: 10 passed

- [ ] **Step 5: Lint and commit**

```bash
python -m ruff check pipeline/verify_report.py tests/test_verify_report.py
git add pipeline/verify_report.py tests/test_verify_report.py
git commit -m "Add Claude-verified atomic-claim check to report verification"
```

---

### Task 3: `verify()` orchestration + result reporting

**Files:**
- Modify: `pipeline/verify_report.py`
- Test: `tests/test_verify_report.py`

**Interfaces:**
- Consumes: `extract_entities`, `check_entities`, `extract_and_verify_claims`, `VerificationError` (Tasks 1-2).
- Produces: `class VerificationResult` with attributes `passed: bool`, `entity_mismatches: list[str]`, `claim_results: list[dict]`, `error: str | None`, and method `.report() -> str`.
- Produces: `verify(draft_text: str, week_notes: list[dict], runner=enrich.run_claude) -> VerificationResult`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_verify_report.py
from pipeline.verify_report import verify


def test_verify_passes_when_entities_and_claims_are_supported():
    def fake_runner(prompt):
        return ('[{"claim": "AdaptixC2 uses T1059", "supported": true, "reason": "ok"}]', {})
    result = verify("CVE-2026-1111 and T1059 seen this week.", WEEK_NOTES, runner=fake_runner)
    assert result.passed is True
    assert result.entity_mismatches == []
    assert result.error is None


def test_verify_fails_on_entity_mismatch():
    def fake_runner(prompt):
        return ("[]", {})
    result = verify("CVE-2099-0000 is new.", WEEK_NOTES, runner=fake_runner)
    assert result.passed is False
    assert "CVE-2099-0000" in result.report()


def test_verify_fails_on_unsupported_claim():
    def fake_runner(prompt):
        return (
            '[{"claim": "Ransomware doubled", "supported": false, "reason": "not in notes"}]',
            {},
        )
    result = verify("Ransomware activity doubled this week.", WEEK_NOTES, runner=fake_runner)
    assert result.passed is False
    assert "Ransomware doubled" in result.report()


def test_verify_fails_when_claim_call_is_unusable():
    def broken_runner(prompt):
        return ("not json", {})
    result = verify("CVE-2026-1111 seen.", WEEK_NOTES, runner=broken_runner)
    assert result.passed is False
    assert result.error is not None


def test_verify_report_text_says_passed_when_clean():
    def fake_runner(prompt):
        return ("[]", {})
    result = verify("CVE-2026-1111 seen.", WEEK_NOTES, runner=fake_runner)
    assert result.passed is True
    assert "passed" in result.report().lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_verify_report.py -v`
Expected: FAIL — `ImportError: cannot import name 'verify'`

- [ ] **Step 3: Write minimal implementation**

```python
# add to pipeline/verify_report.py, at the end


class VerificationResult:
    def __init__(self, passed, entity_mismatches, claim_results, error=None):
        self.passed = passed
        self.entity_mismatches = entity_mismatches
        self.claim_results = claim_results
        self.error = error

    def report(self):
        lines = []
        if self.error:
            lines.append(f"verification call failed: {self.error}")
        for m in self.entity_mismatches:
            lines.append(f"ENTITY MISMATCH: {m}")
        for c in self.claim_results:
            if not c["supported"]:
                lines.append(f"UNSUPPORTED CLAIM: {c['claim']} ({c['reason']})")
        if not lines:
            lines.append(
                "verification passed: all cited IDs and claims are supported by "
                "this week's notes."
            )
        return "\n".join(lines)


def verify(draft_text, week_notes, runner=enrich.run_claude):
    entities = extract_entities(draft_text)
    mismatches = check_entities(entities, week_notes)
    try:
        claim_results = extract_and_verify_claims(draft_text, week_notes, runner=runner)
    except VerificationError as e:
        return VerificationResult(
            passed=False, entity_mismatches=mismatches, claim_results=[], error=str(e)
        )
    unsupported = [c for c in claim_results if not c["supported"]]
    passed = not mismatches and not unsupported
    return VerificationResult(passed=passed, entity_mismatches=mismatches,
                               claim_results=claim_results)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_verify_report.py -v`
Expected: 15 passed

- [ ] **Step 5: Lint and commit**

```bash
python -m ruff check pipeline/verify_report.py tests/test_verify_report.py
git add pipeline/verify_report.py tests/test_verify_report.py
git commit -m "Add verify() orchestration combining entity and claim checks"
```

---

### Task 4: `auto_publish()` — unattended, verification-gated push

**Files:**
- Modify: `pipeline/publish.py`
- Test: `tests/test_publish.py`

**Interfaces:**
- Consumes: `verify_report.verify(draft_text, week_notes, runner=...) -> VerificationResult` (Task 3); `weekly_report.collect_week_notes(vault_dir) -> list[dict]` (`pipeline/weekly_report.py:40`); `approve_draft(vault_dir, wid)` (existing, `pipeline/publish.py`); `audit.log_enrichment(audit_dir, record)` (existing, `pipeline/audit.py:8`).
- Produces: `_push_and_draft_linkedin(vault_dir, wid, git=_git, linkedin_runner=enrich.run_claude) -> (final_path, post_text, linkedin_path)` — shared by this task and Task 5.
- Produces: `auto_publish(wid, vault_dir=None, verifier=verify_report.verify, git=_git, linkedin_runner=enrich.run_claude) -> int` (process exit code: 0 success or nothing-to-do, 1 verification failed).

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_publish.py
from pipeline import publish
from pipeline.verify_report import VerificationResult


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
                                 git=fake_git, linkedin_runner=fake_linkedin)
    assert code == 0
    assert ("add", str(tmp_path / "reports" / "2026-W29.md")) in calls
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
                                 git=lambda *a: calls.append(a))
    assert code == 1
    assert calls == []
    assert (tmp_path / "reports" / "drafts" / "2026-W29-DRAFT.md").exists()
    assert not (tmp_path / "reports" / "2026-W29.md").exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_publish.py -v`
Expected: FAIL — `AttributeError: module 'pipeline.publish' has no attribute 'auto_publish'`

- [ ] **Step 3: Write minimal implementation**

Modify `pipeline/publish.py`. Change the imports at the top:

```python
from . import audit, config, enrich, verify_report, weekly_report
```

Add, after `_git`'s existing definition and before `main()` — this ordering matters: both new
functions default to `git=_git`, and Python resolves default parameter values at definition
time, so `_git` must already exist above them in the file:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_publish.py -v`
Expected: all tests pass (3 new + the 3 existing `approve_draft` tests)

- [ ] **Step 5: Lint and commit**

```bash
python -m ruff check pipeline/publish.py tests/test_publish.py
git add pipeline/publish.py tests/test_publish.py
git commit -m "Add auto_publish(): verification-gated unattended publish"
```

---

### Task 5: Wire verification + `--auto` into the human-triggered path

**Files:**
- Modify: `pipeline/publish.py`
- Test: `tests/test_publish.py`

**Interfaces:**
- Consumes: `auto_publish(wid)` (Task 4), `verify_report.verify` (Task 3), `weekly_report.week_id(day)` (existing, `pipeline/weekly_report.py:35`).
- Produces: `main(argv=None, confirm=input) -> int`, now dispatching `--auto` to `auto_publish`, and showing `verify_report.verify(...)`'s report before the existing confirm prompt in the manual path.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_publish.py
from datetime import date

from pipeline import config


def test_main_dispatches_auto_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VAULT_DIR", tmp_path)
    called = {}

    def fake_auto_publish(wid):
        called["wid"] = wid
        return 0

    monkeypatch.setattr(publish, "auto_publish", fake_auto_publish)
    code = publish.main(["--auto"])
    assert code == 0
    assert called["wid"] == publish.weekly_report.week_id(date.today())


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_publish.py -v`
Expected: FAIL — `main() got an unexpected keyword argument 'confirm'` (and the `--auto` test fails since dispatch doesn't exist yet)

- [ ] **Step 3: Write minimal implementation**

Replace `pipeline/publish.py`'s `main()` function entirely with:

```python
def main(argv=None, confirm=input):
    argv = argv if argv is not None else sys.argv[1:]
    if argv == ["--auto"]:
        wid = weekly_report.week_id(date.today())
        return auto_publish(wid)

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
    print(f"pushed {final.name} to GitHub; LinkedIn draft saved to {linkedin_path}")
    subprocess.run(["clip.exe"], input=post, text=True, encoding="utf-8")
    print("\nAlso copied to clipboard — paste and post when ready:\n")
    print(post)
    return 0
```

Add `from datetime import date` to the imports at the top of `pipeline/publish.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_publish.py -v`
Expected: all tests pass

- [ ] **Step 5: Run the full suite, lint, and commit**

```bash
python -m pytest tests/ -v
python -m ruff check pipeline/ tests/
git add pipeline/publish.py tests/test_publish.py
git commit -m "Show verification results in the interactive publish path; add --auto dispatch"
```

---

### Task 6: Chain auto-publish into the Sunday scheduled task

**Files:**
- Modify: `scripts/run_weekly.ps1`

**Interfaces:**
- Consumes: `python -m pipeline.publish --auto` (Task 5), invoked as a second step in the same script that already runs `python -m pipeline.weekly_report`.

- [ ] **Step 1: Edit the script**

Replace the contents of `scripts/run_weekly.ps1` with:

```powershell
# Sunday weekly-report draft, then a verification-gated auto-publish attempt.
# Invoked by Task Scheduler (see register_tasks.ps1).
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# Note titles reach the draft prompt; see run_daily.ps1 for why this is required.
$env:PYTHONIOENCODING = "utf-8"

New-Item -ItemType Directory -Force -Path "$repo\logs" | Out-Null
$log = "$repo\logs\weekly-$(Get-Date -Format yyyy-MM-dd).log"

"=== weekly draft started $(Get-Date -Format o) ===" | Out-File -Append -Encoding utf8 $log
& "$repo\.venv\Scripts\python.exe" -m pipeline.weekly_report *>> $log
"=== weekly draft finished $(Get-Date -Format o) (exit $LASTEXITCODE) ===" | Out-File -Append -Encoding utf8 $log

"=== auto-publish started $(Get-Date -Format o) ===" | Out-File -Append -Encoding utf8 $log
& "$repo\.venv\Scripts\python.exe" -m pipeline.publish --auto *>> $log
$publishExit = $LASTEXITCODE
"=== auto-publish finished $(Get-Date -Format o) (exit $publishExit) ===" | Out-File -Append -Encoding utf8 $log
exit $publishExit
```

- [ ] **Step 2: Verify manually**

There is no scheduled-task test harness in this repo (`register_tasks.ps1` is registered once, run manually to verify — same as every other scheduled script here). Verify by hand:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_weekly.ps1
Get-Content .\logs\weekly-$(Get-Date -Format yyyy-MM-dd).log -Tail 20
```
Expected: log shows both the draft and auto-publish sections; if there's no draft for the current week (e.g. no notes in the last 7 days), the auto-publish section prints "nothing to auto-publish" and exits 0.

- [ ] **Step 3: Commit**

```bash
git add scripts/run_weekly.ps1
git commit -m "Chain verification-gated auto-publish after the Sunday weekly draft"
```

---

### Task 7: Update `CLAUDE.md` to describe the new invariant

**Files:**
- Modify: `CLAUDE.md`

The current rule ("Nothing publishes without explicit human approval... Do not add auto-publish paths") is now inaccurate — `CLAUDE.md` is supposed to be this repo's single source of truth, so it must describe what the code actually does, not what it used to do.

- [ ] **Step 1: Edit the ground rules**

In `CLAUDE.md`, replace:

```
- Nothing publishes without explicit human approval via `python -m pipeline.publish`.
  Do not add auto-publish paths.
```

with:

```
- Publishing happens two ways: explicit human approval via `python -m pipeline.publish
  <week>`, or the unattended `python -m pipeline.publish --auto` path the Sunday scheduled
  task runs automatically. Auto-publish is gated by `pipeline.verify_report`: every CVE/
  ATT&CK ID the draft cites must trace to that week's real notes, and every other
  substantive claim must be verified as supported by a Claude call before anything is
  pushed. A verification failure blocks the push entirely and leaves the draft untouched
  for manual review — it never fails silently. Never weaken or bypass this check, and
  never let a broken verification call be treated as a pass.
```

- [ ] **Step 2: Update the Commands section**

In `CLAUDE.md`, replace:

```
- Publish approved report: `python -m pipeline.publish <YYYY-Wnn>`
```

with:

```
- Publish approved report (human-reviewed): `python -m pipeline.publish <YYYY-Wnn>`
- Auto-publish (verification-gated, unattended): `python -m pipeline.publish --auto`
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "Update CLAUDE.md publish rule to describe verification-gated auto-publish"
```

## Self-Review Notes

- **Spec coverage:** deterministic entity check (Task 1), atomic-claim check (Task 2),
  `verify()` orchestration (Task 3), `auto_publish` (Task 4), interactive path + `--auto`
  dispatch (Task 5), scheduling (Task 6), docs (Task 7) — every spec section has a task.
- **Placeholder scan:** no TBD/TODO; every step has complete code, exact commands, and
  expected output.
- **Type consistency:** `VerificationResult` (Task 3) is constructed identically in Task 3's
  own tests and reused verbatim in Task 4/5's tests; `verify_report.verify` and `auto_publish`
  signatures are consistent everywhere they're called across Tasks 3-5.
