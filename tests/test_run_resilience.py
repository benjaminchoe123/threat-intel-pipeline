"""The run must survive failures, and must never lose the audit record.

Previously main() had no try/except at all: any exception aborted every
remaining item across every source, skipped update_dashboards(), and — because
audit.log_enrichment sat after everything that could throw — left no trace of a
`claude` call that had already been made and billed.
"""

import json

import pytest

from pipeline import config, run
from pipeline.state import State

from test_validate import VALID_NOTE

ITEM = {
    "source": "kev", "external_id": "CVE-2026-1111", "title": "ExampleServer RCE",
    "url": "https://example.com/kev", "raw": {"cveID": "CVE-2026-1111"},
    "content_hash": "abc",
}
BAD_NOTE = "not a note at all"


def _item(source, ext):
    return {**ITEM, "source": source, "external_id": ext}


def _audit_records():
    files = list(config.AUDIT_DIR.glob("*.jsonl"))
    if not files:
        return []
    return [json.loads(x) for x in files[0].read_text(encoding="utf-8").splitlines() if x.strip()]


def _ok_runner(prompt):
    return VALID_NOTE, {"is_error": False}


def test_runner_default_resolves_at_call_time(tmp_path, monkeypatch):
    """Guard: monkeypatching enrich.run_claude must actually take effect.

    Bound as a default argument it captured the real `claude -p` at import, so a
    test that forgot runner= would spawn a live, billed subprocess.
    """
    called = []
    monkeypatch.setattr(run.enrich, "run_claude", lambda p: called.append(1) or (VALID_NOTE, {}))
    monkeypatch.setattr(run.reputation, "default_reputation", lambda i, cache=None: (None, []))

    run.process_item(ITEM, State(tmp_path / "s.db"), "skill", "2026-07-15")
    assert called, "process_item ignored the patched runner and would have called claude"


# --- the audit record survives everything ---------------------------------

def test_audit_record_written_when_runner_raises(tmp_path):
    def boom(prompt):
        raise RuntimeError("claude -p failed (1): boom")

    outcome = run.process_item(ITEM, State(tmp_path / "s.db"), "skill", "2026-07-15",
                               runner=boom, reputation_fn=lambda i, cache=None: (None, []))
    assert outcome == "failed"
    records = _audit_records()
    assert len(records) == 1
    assert records[0]["error_type"] == "RuntimeError"
    assert "boom" in records[0]["error"]
    assert records[0]["outcome"] == "failed"


def test_audit_record_written_when_reputation_raises(tmp_path):
    def boom(item):
        raise RuntimeError("VirusTotal returned 429")

    outcome = run.process_item(ITEM, State(tmp_path / "s.db"), "skill", "2026-07-15",
                               runner=_ok_runner, reputation_fn=boom)
    assert outcome == "failed"
    assert _audit_records()[0]["error_type"] == "RuntimeError"


def test_failed_item_is_not_recorded_as_seen_so_it_retries(tmp_path):
    state = State(tmp_path / "s.db")

    def boom(prompt):
        raise RuntimeError("transient")

    run.process_item(ITEM, state, "skill", "2026-07-15", runner=boom,
                     reputation_fn=lambda i, cache=None: (None, []))
    assert state.check("kev", "CVE-2026-1111", "abc") == "new"


# --- both attempts are preserved ------------------------------------------

def test_both_attempts_are_recorded_not_overwritten(tmp_path):
    outputs = [BAD_NOTE, VALID_NOTE]

    def runner(prompt):
        return outputs.pop(0), {"is_error": False}

    outcome = run.process_item(ITEM, State(tmp_path / "s.db"), "skill", "2026-07-15",
                               runner=runner, reputation_fn=lambda i, cache=None: (None, []))
    assert outcome == "written"
    attempts = _audit_records()[0]["attempts"]
    assert len(attempts) == 2
    assert attempts[0]["validation_ok"] is False
    assert attempts[0]["claude_output"] == BAD_NOTE  # attempt 1 forensics survive
    assert attempts[1]["validation_ok"] is True


def test_retry_prompt_includes_the_validation_errors(tmp_path):
    prompts = []

    def runner(prompt):
        prompts.append(prompt)
        return BAD_NOTE, {"is_error": False}

    run.process_item(ITEM, State(tmp_path / "s.db"), "skill", "2026-07-15",
                     runner=runner, reputation_fn=lambda i, cache=None: (None, []))
    assert len(prompts) == 2
    assert "frontmatter" in prompts[1].lower()
    assert prompts[0] != prompts[1], "retry must not re-send an identical prompt"


# --- quarantine is a queue, not a dead end --------------------------------

def test_quarantined_item_retries_next_run(tmp_path):
    state = State(tmp_path / "s.db")

    def bad(prompt):
        return BAD_NOTE, {"is_error": False}

    outcome = run.process_item(ITEM, state, "skill", "2026-07-15", runner=bad,
                               reputation_fn=lambda i, cache=None: (None, []))
    assert outcome == "quarantined"
    assert state.check("kev", "CVE-2026-1111", "abc") == "new"


def test_quarantine_gives_up_after_max_attempts(tmp_path):
    state = State(tmp_path / "s.db")

    def bad(prompt):
        return BAD_NOTE, {"is_error": False}

    for _ in range(run.MAX_QUARANTINE_ATTEMPTS):
        run.process_item(ITEM, state, "skill", "2026-07-15", runner=bad,
                         reputation_fn=lambda i, cache=None: (None, []))
    assert state.check("kev", "CVE-2026-1111", "abc") == "seen"


# --- one failure never takes down the run ---------------------------------

def test_one_bad_source_does_not_stop_the_others(tmp_path, monkeypatch):
    def exploding_source():
        raise RuntimeError("CISA returned 503")

    monkeypatch.setattr(run, "SOURCES", {
        "kev": exploding_source,
        "mta": lambda: [_item("mta", "https://example.com/post")],
    })
    monkeypatch.setattr(run.enrich, "run_claude", _ok_runner)
    monkeypatch.setattr(run.reputation, "default_reputation", lambda i, cache=None: (None, []))

    totals = run.main([])
    assert totals["written"] == 1, "mta must still run after kev explodes"
    assert totals["failed"] >= 1


def test_one_bad_item_does_not_stop_the_rest(tmp_path, monkeypatch):
    calls = []

    def runner(prompt):
        calls.append(prompt)
        if len(calls) == 1:
            raise RuntimeError("transient")
        return VALID_NOTE, {"is_error": False}

    monkeypatch.setattr(run, "SOURCES", {
        "kev": lambda: [_item("kev", "CVE-1"), _item("kev", "CVE-2")],
    })
    monkeypatch.setattr(run.enrich, "run_claude", runner)
    monkeypatch.setattr(run.reputation, "default_reputation", lambda i, cache=None: (None, []))

    totals = run.main([])
    assert totals["failed"] == 1
    assert totals["written"] == 1


def test_dashboards_still_update_after_a_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "SOURCES", {"kev": lambda: [_item("kev", "CVE-1")]})
    monkeypatch.setattr(run.enrich, "run_claude",
                        lambda p: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(run.reputation, "default_reputation", lambda i, cache=None: (None, []))

    run.main([])
    assert (config.VAULT_DIR / "home.md").exists()


def test_main_exits_nonzero_when_something_failed(monkeypatch):
    monkeypatch.setattr(run, "SOURCES", {"kev": lambda: [_item("kev", "CVE-1")]})
    monkeypatch.setattr(run.enrich, "run_claude",
                        lambda p: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(run.reputation, "default_reputation", lambda i, cache=None: (None, []))

    with pytest.raises(SystemExit) as exc:
        run.cli([])
    assert exc.value.code == 1


def test_main_exits_zero_on_a_clean_run(monkeypatch):
    monkeypatch.setattr(run, "SOURCES", {"kev": lambda: [_item("kev", "CVE-1")]})
    monkeypatch.setattr(run.enrich, "run_claude", _ok_runner)
    monkeypatch.setattr(run.reputation, "default_reputation", lambda i, cache=None: (None, []))

    with pytest.raises(SystemExit) as exc:
        run.cli([])
    assert exc.value.code == 0
