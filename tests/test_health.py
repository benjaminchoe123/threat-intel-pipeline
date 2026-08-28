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

from datetime import UTC, date, datetime, timedelta

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


# --- run age: the watchdog that only ticked when the dog was alive ----------
#
# The 2026-08-25 near-miss: every surface said OK while the scheduler had not
# fired for two days. Note staleness cannot detect "the pipeline stopped running"
# on its own, because the only code that renders the banner runs *during a run*.
# Stop running and the dashboard freezes mid-sentence, still saying OK. Run age
# is the independent signal, and it is only useful to a reader that does not
# require a run to happen first — hence the CLI below.


def test_old_heartbeat_is_stale_even_when_notes_look_fresh():
    state = health.assess(
        [meta("2026-08-23")],
        today=TODAY,
        last_run=run(written=15, when="2026-08-18T08:00:00+00:00"),
    )
    assert state["days_since_run"] == 5
    assert state["status"] == health.STALE


def test_recent_heartbeat_is_ok():
    state = health.assess([meta("2026-08-23")], today=TODAY, last_run=run(written=15))
    assert state["days_since_run"] == 0
    assert state["status"] == health.OK


def test_run_age_tolerates_the_same_gap_as_notes():
    """Two days is a weekend with the desktop off, for runs as much as notes."""
    state = health.assess(
        [meta("2026-08-23")],
        today=TODAY,
        last_run=run(written=15, when="2026-08-21T08:00:00+00:00"),
    )
    assert state["status"] == health.OK


def test_missing_heartbeat_leaves_run_age_unknown():
    state = health.assess([meta("2026-08-23")], today=TODAY, last_run=None)
    assert state["days_since_run"] is None
    assert state["status"] == health.OK


def test_unparseable_heartbeat_timestamp_does_not_crash():
    """A truncated write must not take the health check down with it."""
    state = health.assess(
        [meta("2026-08-23")],
        today=TODAY,
        last_run={"finished_at": "not-a-date", "totals": {}},
    )
    assert state["days_since_run"] is None
    assert state["status"] == health.OK


def test_banner_names_run_age_when_the_run_is_the_stale_thing():
    state = health.assess(
        [meta("2026-08-23")],
        today=TODAY,
        last_run=run(written=15, when="2026-08-18T08:00:00+00:00"),
    )
    text = health.banner(state)
    assert "5 days" in text
    assert "STALE" in text


# --- external watchdog CLI -------------------------------------------------


def _vault(tmp_path, note_date):
    threats = tmp_path / "vault" / "threats"
    threats.mkdir(parents=True)
    (threats / f"{note_date}-x.md").write_text(
        f"---\ntitle: X\ndate: {note_date}\n---\n\nbody\n", encoding="utf-8"
    )
    return tmp_path / "vault"


def test_cli_exits_zero_when_healthy(tmp_path, capsys):
    vault = _vault(tmp_path, "2026-08-23")
    health.record_run(tmp_path / "data", {"written": 3, "failed": 0},
                      when=datetime(2026, 8, 23, 8, tzinfo=UTC))
    code = health.main([str(vault), str(tmp_path / "data")], today=TODAY)
    assert code == 0
    assert "OK" in capsys.readouterr().out


def test_cli_exits_nonzero_when_the_scheduler_has_stopped(tmp_path, capsys):
    """The case the dashboard structurally cannot report on itself."""
    vault = _vault(tmp_path, "2026-08-23")
    health.record_run(tmp_path / "data", {"written": 3, "failed": 0},
                      when=datetime(2026, 8, 18, 8, tzinfo=UTC))
    code = health.main([str(vault), str(tmp_path / "data")], today=TODAY)
    assert code == 1
    assert "STALE" in capsys.readouterr().out


def test_cli_reports_a_never_run_pipeline_without_crashing(tmp_path, capsys):
    vault = _vault(tmp_path, "2026-08-23")
    code = health.main([str(vault), str(tmp_path / "data")], today=TODAY)
    assert code == 0
    assert "OK" in capsys.readouterr().out


def test_cli_survives_a_cp1252_console(tmp_path, monkeypatch):
    """The banner contains an em-dash and Windows stdout is cp1252 even when
    redirected — scripts/run_daily.ps1 redirects. A watchdog that crashes on its
    own output is worse than no watchdog: it fails exactly when read.
    """
    import io

    vault = _vault(tmp_path, "2026-08-23")
    # The STALE banner is the one that carries U+26A0 WARNING SIGN, which cp1252
    # cannot encode. (The healthy banner's em-dash is cp1252 0x97 and encodes
    # fine — testing that path would prove nothing.)
    health.record_run(
        tmp_path / "data",
        {"written": 3, "failed": 0},
        when=datetime(2026, 8, 18, 8, tzinfo=UTC),
    )
    buf = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    monkeypatch.setattr("sys.stdout", buf)

    code = health.main([str(vault), str(tmp_path / "data")], today=TODAY)

    assert code == 1
    buf.seek(0)
    assert "STALE" in buf.buffer.getvalue().decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# A killed run leaves no trace.
#
# 2026-08-23 and 2026-08-26: the daily run was killed partway, wrote a couple of
# notes, and vanished. Both times the scheduled task reported LastTaskResult 0,
# and both times `last_run.json` was never touched, because it is only written
# when a run *finishes*. So a run that died is byte-for-byte indistinguishable
# from a run that never started, and `pipeline.health` reported OK throughout --
# correctly, by its own rules, which is what makes it a gap rather than a bug.
#
# Recording the heartbeat at start as well as finish makes the difference
# visible: a start with no matching finish, older than any plausible run, is a
# run that died.
# ---------------------------------------------------------------------------

RUN_START = datetime(2026, 8, 26, 11, 13, tzinfo=UTC)


def test_record_start_writes_started_at_and_preserves_the_previous_finish(tmp_path):
    """The previous run's outcome is still the last *completed* run, and losing it
    would trade one blind spot for another."""
    health.record_run(tmp_path, {"written": 15, "failed": 0},
                      when=datetime(2026, 8, 25, 17, 0, tzinfo=UTC))
    health.record_start(tmp_path, when=RUN_START)

    beat = health.load_last_run(tmp_path)
    assert beat["started_at"] == RUN_START.isoformat()
    assert beat["finished_at"] == datetime(2026, 8, 25, 17, 0, tzinfo=UTC).isoformat()
    assert beat["totals"] == {"written": 15, "failed": 0}


def test_record_start_works_with_no_previous_heartbeat(tmp_path):
    health.record_start(tmp_path, when=RUN_START)
    beat = health.load_last_run(tmp_path)
    assert beat["started_at"] == RUN_START.isoformat()
    assert beat.get("finished_at") is None


def test_record_run_after_record_start_leaves_a_finish_newer_than_the_start(tmp_path):
    health.record_start(tmp_path, when=RUN_START)
    health.record_run(tmp_path, {"written": 3, "failed": 0},
                      when=datetime(2026, 8, 26, 11, 25, tzinfo=UTC))

    beat = health.load_last_run(tmp_path)
    assert beat["started_at"] == RUN_START.isoformat()
    assert beat["finished_at"] > beat["started_at"]
    state = health.assess([], today=date(2026, 8, 26), last_run=beat,
                          now=datetime(2026, 8, 26, 12, 0, tzinfo=UTC))
    assert state["interrupted_run"] is False


def test_assess_flags_a_start_with_no_finish_as_an_interrupted_run():
    """The 2026-08-26 shape exactly: started 11:13, never finished."""
    beat = {"started_at": RUN_START.isoformat(),
            "finished_at": datetime(2026, 8, 25, 17, 0, tzinfo=UTC).isoformat(),
            "totals": {"written": 15, "failed": 0}}
    state = health.assess([{"date": "2026-08-26"}], today=date(2026, 8, 26), last_run=beat,
                          now=datetime(2026, 8, 26, 23, 0, tzinfo=UTC))
    assert state["interrupted_run"] is True


def test_a_run_still_within_the_grace_period_is_not_called_interrupted():
    """An in-flight run and a dead one look identical on disk. Only elapsed time
    tells them apart, so a run that started minutes ago is presumed alive."""
    beat = {"started_at": RUN_START.isoformat(), "finished_at": None, "totals": {}}
    state = health.assess([{"date": "2026-08-26"}], today=date(2026, 8, 26), last_run=beat,
                          now=RUN_START + timedelta(minutes=5))
    assert state["interrupted_run"] is False


def test_an_interrupted_run_is_at_least_degraded():
    beat = {"started_at": RUN_START.isoformat(), "finished_at": None, "totals": {}}
    state = health.assess([{"date": "2026-08-26"}], today=date(2026, 8, 26), last_run=beat,
                          now=RUN_START + timedelta(hours=12))
    assert state["status"] == health.DEGRADED


def test_an_old_format_heartbeat_with_no_started_at_is_not_interrupted():
    """Every heartbeat already on disk predates this field. Reading one must not
    suddenly declare a healthy pipeline broken."""
    beat = {"finished_at": datetime(2026, 8, 26, 11, 0, tzinfo=UTC).isoformat(),
            "totals": {"written": 15, "failed": 0}}
    state = health.assess([{"date": "2026-08-26"}], today=date(2026, 8, 26), last_run=beat,
                          now=datetime(2026, 8, 26, 23, 0, tzinfo=UTC))
    assert state["interrupted_run"] is False
    assert state["status"] == health.OK


def test_assess_survives_an_unparseable_started_at():
    """Health reporting is the thing that must still work when everything else
    has stopped -- a hand-edited or truncated stamp must degrade, not raise."""
    beat = {"started_at": "not-a-timestamp", "finished_at": None, "totals": {}}
    state = health.assess([{"date": "2026-08-26"}], today=date(2026, 8, 26), last_run=beat,
                          now=datetime(2026, 8, 26, 23, 0, tzinfo=UTC))
    assert state["interrupted_run"] is False


def test_banner_names_the_interrupted_run():
    beat = {"started_at": RUN_START.isoformat(), "finished_at": None, "totals": {}}
    state = health.assess([{"date": "2026-08-26"}], today=date(2026, 8, 26), last_run=beat,
                          now=RUN_START + timedelta(hours=12))
    text = health.banner(state)
    assert "started" in text.lower()
    assert "never finished" in text.lower()
    assert RUN_START.isoformat() in text


def test_the_advice_matches_the_reason_not_a_fixed_string():
    """The banner used to append "Enrichment output has stopped" to every
    non-OK state. When the only problem is a run killed partway, that is false:
    the notes are current, and it sends the reader looking for an outage that is
    not happening. Observed on 2026-08-27, when a run died on its third item and
    the banner said output had stopped while the newest note was that morning's.
    """
    beat = {"started_at": RUN_START.isoformat(), "finished_at": None, "totals": {}}
    state = health.assess([{"date": "2026-08-26"}], today=date(2026, 8, 26), last_run=beat,
                          now=RUN_START + timedelta(hours=12))
    text = health.banner(state)
    assert "output has stopped" not in text.lower()
    assert "carry over" in text.lower()


def test_stale_output_still_says_output_has_stopped():
    """The original advice was right for the case it was written for."""
    state = health.assess([{"date": "2026-08-01"}], today=date(2026, 8, 26), last_run=None)
    assert "output has stopped" in health.banner(state).lower()


def test_both_problems_at_once_report_both_kinds_of_advice():
    beat = {"started_at": RUN_START.isoformat(), "finished_at": None, "totals": {}}
    state = health.assess([{"date": "2026-08-01"}], today=date(2026, 8, 26), last_run=beat,
                          now=RUN_START + timedelta(hours=12))
    text = health.banner(state).lower()
    assert "output has stopped" in text
    assert "carry over" in text
