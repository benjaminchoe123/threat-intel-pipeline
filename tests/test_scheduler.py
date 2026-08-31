"""What the OS scheduler saw, when the run itself saw nothing.

2026-08-31: ThreatIntel-Daily's last result was 0xC000013A at 12:16:51 and the
run had written no log line and no start stamp. `pipeline.health` said OK.
"""

import pytest

from pipeline import health, scheduler

KILLED = 0xC000013A


def test_a_kill_is_told_apart_from_a_chosen_exit_code():
    # The daily exits 1 whenever a single item fails -- correct, common, and
    # already reported through totals. Treating it as a kill would put the
    # banner in the red most weeks.
    assert not scheduler.was_killed(0)
    assert not scheduler.was_killed(1)
    assert not scheduler.was_killed(2)
    assert scheduler.was_killed(KILLED)


def test_unknown_result_is_never_reported_as_a_failure():
    """Not on Windows, task not registered, PowerShell missing -- none of these
    are evidence that anything went wrong."""
    assert not scheduler.was_killed(None)
    assert scheduler.describe(None) == "unknown"
    assert scheduler.killed_tasks(names=["X"], info=lambda n: (None, None)) == []


def test_the_status_seen_three_times_is_named_not_left_as_hex():
    assert "Ctrl+C" in scheduler.describe(KILLED)
    assert "0xC0000999" in scheduler.describe(0xC0000999)  # unknown one still legible


def test_signed_result_is_folded_back_into_the_unsigned_space():
    """PowerShell reports LastTaskResult signed, so 0xC000013A arrives negative.
    Left as-is it would read as a small negative exit code and never be seen as
    a kill at all."""
    signed = KILLED - (1 << 32)
    out = scheduler.task_info("T", runner=lambda s: f"2026-08-31T12:16:51\n{signed}\n")
    assert out == ("2026-08-31T12:16:51", KILLED)


def test_a_broken_scheduler_read_degrades_to_unknown():
    def boom(_script):
        raise RuntimeError("powershell is not here")

    assert scheduler.task_info("T", runner=boom) == (None, None)
    assert scheduler.task_info("T", runner=lambda s: "garbage") == (None, None)


# --- health acts on it -----------------------------------------------------

NOTE_TODAY = [{"date": "2026-08-31"}]
HEALTHY_RUN = {"started_at": "2026-08-31T05:40:23+00:00",
               "finished_at": "2026-08-31T05:58:00+00:00",
               "totals": {"written": 14, "failed": 0}}


def test_a_killed_task_is_degraded_even_when_every_other_signal_is_green():
    """The exact 2026-08-31 state: fresh notes, a completed run, and a task that
    died at launch eleven hours later. This reported OK."""
    from datetime import date

    state = health.assess(NOTE_TODAY, today=date(2026, 8, 31), last_run=HEALTHY_RUN,
                          killed_tasks=[{"task": "ThreatIntel-Daily",
                                         "last_run": "2026-08-31T12:16:51-04:00",
                                         "result": KILLED,
                                         "detail": "terminated (Ctrl+C / session ended)"}])
    assert state["status"] == health.DEGRADED
    text = health.banner(state)
    assert "ThreatIntel-Daily" in text
    assert "12:16:51" in text
    # The advice must name the cause, not send the reader hunting an outage.
    assert "LogonType" in text
    assert "Enrichment output has stopped" not in text


def test_no_killed_tasks_leaves_a_healthy_pipeline_healthy():
    from datetime import date

    state = health.assess(NOTE_TODAY, today=date(2026, 8, 31), last_run=HEALTHY_RUN,
                          killed_tasks=[])
    assert state["status"] == health.OK


@pytest.mark.parametrize("result", [0, 1])
def test_a_task_that_exited_on_its_own_does_not_flip_the_banner(result):
    """The weekly exited 1 on 2026-08-31 because verification correctly refused
    to publish. That is the gate working, not the machine failing."""
    assert scheduler.killed_tasks(names=["W"], info=lambda n: ("t", result)) == []
