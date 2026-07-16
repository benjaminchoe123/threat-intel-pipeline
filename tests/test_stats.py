"""The audit trail was write-only: cost, retry rate, and cache savings were all
recorded and never read back."""

import json
from datetime import date

from pipeline import stats


def _record(**kw):
    base = {"timestamp": "2026-07-15T00:00:00+00:00", "source": "kev",
            "external_id": "CVE-1", "outcome": "written", "attempts": []}
    base.update(kw)
    return base


def _attempt(ok=True, cost=0.10):
    return {"attempt": 1, "validation_ok": ok, "engine": {"total_cost_usd": cost},
            "validation_errors": []}


def _write_log(audit_dir, day, records):
    audit_dir.mkdir(parents=True, exist_ok=True)
    (audit_dir / f"{day}.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


# --- loading ---------------------------------------------------------------

def test_loads_records_within_the_window(tmp_path):
    _write_log(tmp_path, "2026-07-15", [_record()])
    assert len(stats.load_records(tmp_path, days=30, today=date(2026, 7, 15))) == 1


def test_ignores_logs_older_than_the_window(tmp_path):
    _write_log(tmp_path, "2026-01-01", [_record()])
    assert stats.load_records(tmp_path, days=7, today=date(2026, 7, 15)) == []


def test_ignores_non_daily_files(tmp_path):
    """The purge script leaves 2026-07-15.jsonl.corrupted-backup next to the log."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "2026-07-15.jsonl.corrupted-backup").write_text(
        json.dumps(_record()) + "\n", encoding="utf-8")
    assert stats.load_records(tmp_path, days=30, today=date(2026, 7, 15)) == []


def test_unparseable_line_does_not_break_the_report(tmp_path):
    audit = tmp_path
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "2026-07-15.jsonl").write_text(
        json.dumps(_record()) + "\n{ broken\n", encoding="utf-8")
    assert len(stats.load_records(audit, days=30, today=date(2026, 7, 15))) == 1


def test_missing_audit_dir_is_empty_not_an_error(tmp_path):
    assert stats.load_records(tmp_path / "nope", days=30) == []


# --- cost ------------------------------------------------------------------

def test_cost_sums_every_attempt_not_just_the_successful_one():
    """A retried item costs two calls; counting only the winner understates spend."""
    records = [_record(attempts=[_attempt(ok=False, cost=0.18), _attempt(ok=True, cost=0.10)])]
    assert stats.summarize(records)["total_cost_usd"] == 0.28
    assert stats.summarize(records)["claude_calls"] == 2


def test_cost_per_note_divides_by_notes_written_not_calls():
    records = [_record(attempts=[_attempt(ok=False, cost=0.20), _attempt(cost=0.20)])]
    assert stats.summarize(records)["cost_per_note"] == 0.40


def test_cost_per_note_is_none_when_nothing_was_written():
    records = [_record(outcome="failed", attempts=[_attempt(ok=False)])]
    assert stats.summarize(records)["cost_per_note"] is None


def test_missing_cost_field_does_not_crash():
    records = [_record(attempts=[{"attempt": 1, "validation_ok": True, "engine": {}}])]
    assert stats.summarize(records)["total_cost_usd"] == 0.0


# --- quality ---------------------------------------------------------------

def test_counts_first_try_versus_rescued_by_retry():
    records = [
        _record(attempts=[_attempt(ok=True)]),
        _record(attempts=[_attempt(ok=False), _attempt(ok=True)]),
    ]
    s = stats.summarize(records)
    assert s["first_try_ok"] == 1
    assert s["rescued_by_retry"] == 1


def test_quarantine_and_failure_rates():
    records = [_record(), _record(outcome="quarantined"), _record(outcome="failed"),
               _record()]
    s = stats.summarize(records)
    assert s["quarantine_rate"] == 0.25
    assert s["failure_rate"] == 0.25


def test_items_counted_by_source():
    records = [_record(source="kev"), _record(source="kev"), _record(source="threatfox")]
    assert stats.summarize(records)["by_source"] == {"kev": 2, "threatfox": 1}


# --- reputation ------------------------------------------------------------

def test_cache_hit_rate_and_service_breakdown():
    records = [_record(reputation_lookups=[
        {"service": "virustotal", "cached": True},
        {"service": "virustotal"},
        {"service": "epss"},
        {"service": "virustotal", "error": "429", "error_type": "RateLimitError"},
    ])]
    s = stats.summarize(records)
    assert s["reputation_by_service"] == {"virustotal": 3, "epss": 1}
    assert s["cache_hit_rate"] == 0.25
    assert s["lookup_errors"] == 1


def test_weekly_reports_are_counted_separately_from_enrichments():
    records = [_record(), {"type": "weekly_report", "week": "2026-W29"}]
    s = stats.summarize(records)
    assert s["enrichments"] == 1, "a weekly report is not an enrichment"
    assert s["weekly_reports"] == 1


def test_maintenance_records_are_not_enrichments():
    records = [{"type": "maintenance", "action": "purge_test_artifacts"}]
    assert stats.summarize(records)["enrichments"] == 0


# --- legacy records --------------------------------------------------------
#
# Records written before the attempts[] list carry a flat attempt/engine and no
# outcome. Found by running the report against the real log: 12 of 14 records
# came back "unknown" and their cost went uncounted.

LEGACY_WRITTEN = {
    "timestamp": "2026-07-15T06:53:35+00:00", "source": "kev", "external_id": "CVE-1",
    "attempt": 1, "engine": {"total_cost_usd": 0.39, "duration_ms": 35915},
    "validation_ok": True, "validation_errors": [], "claude_output": "---\n...",
    "note_path": r"C:\vault\threats\note.md",
}
LEGACY_QUARANTINED = {
    "timestamp": "2026-07-15T06:54:00+00:00", "source": "mta", "external_id": "x",
    "attempt": 2, "engine": {"total_cost_usd": 0.11}, "validation_ok": False,
    "validation_errors": ["no YAML frontmatter block found"],
    "quarantine_path": r"C:\data\quarantine\x.md",
}


def test_legacy_record_cost_is_counted():
    s = stats.summarize([LEGACY_WRITTEN])
    assert s["total_cost_usd"] == 0.39
    assert s["claude_calls"] == 1


def test_legacy_outcome_is_inferred_from_note_path():
    assert stats.summarize([LEGACY_WRITTEN])["outcomes"] == {"written": 1}


def test_legacy_outcome_is_inferred_from_quarantine_path():
    assert stats.summarize([LEGACY_QUARANTINED])["outcomes"] == {"quarantined": 1}


def test_legacy_record_with_an_error_is_a_failure():
    rec = {"source": "kev", "external_id": "y", "error": "boom",
           "error_type": "RuntimeError"}
    assert stats.summarize([rec])["outcomes"] == {"failed": 1}


def test_legacy_validation_ok_counts_as_first_try():
    assert stats.summarize([LEGACY_WRITTEN])["first_try_ok"] == 1


def test_legacy_and_current_records_mix_cleanly():
    records = [LEGACY_WRITTEN, _record(attempts=[_attempt(cost=0.10)])]
    s = stats.summarize(records)
    assert s["enrichments"] == 2
    assert s["outcomes"] == {"written": 2}
    assert s["total_cost_usd"] == 0.49


def test_record_with_nothing_to_infer_from_stays_unknown():
    assert stats.summarize([{"source": "kev"}])["outcomes"] == {"unknown": 1}


# --- rendering -------------------------------------------------------------

def test_report_renders_without_data():
    text = stats.format_report(stats.summarize([]), 30)
    assert "enrichments        0" in text


def test_report_includes_cost_and_rates():
    records = [_record(attempts=[_attempt(cost=0.25)])]
    text = stats.format_report(stats.summarize(records), 30)
    assert "$0.25" in text
    assert "quarantine rate" in text
