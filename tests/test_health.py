"""Health reporting: does a starved pipeline actually look different from a quiet one?

These tests are written against the real 2026-08 outage. Between 08-02 and 08-18
every enrichment failed, the exit code was correctly non-zero, and every surface a
human looks at still said "quiet week". The regression to prevent is not a crash —
nothing crashed — it is silence.

Every test pins the clock. test_dashboards.py had two tests that passed the week
they were written and failed every week after because they let `today` default;
health is entirely a function of elapsed time, so a floating clock here would be
worse than no test at all.
"""

from datetime import UTC, date, datetime

import pytest

from pipeline import health
from pipeline.notes import update_dashboards

TODAY = date(2026, 8, 23)


def meta(day):
    return {"title": "T", "date": day}


def run(written=0, failed=0, when="2026-08-23T12:00:00+00:00"):
    return {"finished_at": when, "totals": {"written": written, "failed": failed}}


# --- staleness -------------------------------------------------------------


def test_fresh_notes_are_ok():
    state = health.assess([meta("2026-08-23"), meta("2026-08-21")], today=TODAY)
    assert state["status"] == health.OK
    assert state["newest_note_date"] == "2026-08-23"
    assert state["days_stale"] == 0


def test_two_day_gap_is_still_ok():
    """A weekend with the desktop switched off must not cry wolf."""
    state = health.assess([meta("2026-08-21")], today=TODAY)
    assert state["status"] == health.OK
    assert state["days_stale"] == 2


def test_the_actual_outage_reads_stale():
    """The real thing: newest note 2026-08-04, checked on 2026-08-23."""
    state = health.assess([meta("2026-08-04"), meta("2026-08-02")], today=TODAY)
    assert state["status"] == health.STALE
    assert state["newest_note_date"] == "2026-08-04"
    assert state["days_stale"] == 19


@pytest.mark.parametrize("day,expected", [
    ("2026-08-21", health.OK),      # 2 days
    ("2026-08-20", health.STALE),   # 3 days — the threshold itself
])
def test_threshold_boundary(day, expected):
    assert health.assess([meta(day)], today=TODAY)["status"] == expected


def test_unparseable_date_does_not_crash():
    """A hallucinated frontmatter date must degrade, not raise."""
    state = health.assess([meta("not-a-date")], today=TODAY, last_run=run(written=1))
    assert state["days_stale"] is None
    assert state["status"] == health.STALE


def test_empty_vault_with_no_run_is_ok():
    """First run before anything exists is a legitimate state, not an alarm."""
    assert health.assess([], today=TODAY)["status"] == health.OK


def test_empty_vault_after_a_run_is_stale():
    assert health.assess([], today=TODAY, last_run=run(written=1))["status"] == health.STALE


# --- last-run signal -------------------------------------------------------


def test_all_items_failed_is_degraded_even_with_fresh_notes():
    """The 2026-08-02 signature: notes still recent, but the run wrote nothing.

    Staleness alone would have taken three more days to notice this.
    """
    state = health.assess([meta("2026-08-23")], today=TODAY, last_run=run(failed=15))
    assert state["status"] == health.DEGRADED
    assert state["last_run_totals"]["failed"] == 15


def test_partial_success_is_not_degraded():
    """08-04 partially succeeded. Some failures with some output is a normal run."""
    state = health.assess([meta("2026-08-23")], today=TODAY, last_run=run(written=3, failed=2))
    assert state["status"] == health.OK


def test_degraded_outranks_stale():
    state = health.assess([meta("2026-08-04")], today=TODAY, last_run=run(failed=15))
    assert state["status"] == health.DEGRADED


# --- heartbeat -------------------------------------------------------------


def test_heartbeat_survives_a_run_that_wrote_nothing(tmp_path):
    """The run we most need evidence of is the one that leaves no vault trace."""
    totals = {"written": 0, "quarantined": 0, "failed": 15}
    health.record_run(tmp_path, totals, when=datetime(2026, 8, 18, 13, 38, tzinfo=UTC))
    loaded = health.load_last_run(tmp_path)
    assert loaded["totals"]["failed"] == 15
    assert loaded["finished_at"].startswith("2026-08-18T13:38")


def test_missing_heartbeat_returns_none(tmp_path):
    assert health.load_last_run(tmp_path) is None


def test_corrupt_heartbeat_returns_none_rather_than_raising(tmp_path):
    (tmp_path / health.LAST_RUN_FILE).write_text("{ truncated", encoding="utf-8")
    assert health.load_last_run(tmp_path) is None


# --- the surface a human actually reads ------------------------------------


def _home_with(notes, last_run, tmp_path):
    (tmp_path / "threats").mkdir(parents=True)
    for i, day in enumerate(notes):
        (tmp_path / "threats" / f"{day}-n{i}.md").write_text(
            f"---\ntitle: N{i}\ntype: threat\ndate: {day}\nflagged: false\n---\n\n# N{i}\n",
            encoding="utf-8",
        )
    update_dashboards(tmp_path, today=TODAY, last_run=last_run)
    return (tmp_path / "home.md").read_text(encoding="utf-8")


def test_dashboard_shows_ok_when_current(tmp_path):
    home = _home_with(["2026-08-23"], run(written=1), tmp_path)
    assert "Pipeline health: OK" in home


def test_dashboard_announces_the_outage(tmp_path):
    """The negative test that matters: prove the detection fires.

    Seeded with exactly what was on disk on 2026-08-23 — newest note 08-04, last
    run wrote 0 and failed 15. Before this change home.md rendered "*(none in the
    last 7 days)*" and nothing else.
    """
    home = _home_with(["2026-08-04"], run(failed=15), tmp_path)
    assert "Pipeline health: DEGRADED" in home
    assert "2026-08-04" in home
    assert "19 days old" in home
    assert "failed 15" in home


def test_dashboard_without_a_heartbeat_still_flags_staleness(tmp_path):
    """No last_run.json yet (upgrading an existing install) must not mask staleness."""
    home = _home_with(["2026-08-04"], None, tmp_path)
    assert "Pipeline health: STALE" in home
