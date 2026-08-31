"""Two overlapping runs both classify an item as "new" and both enrich it:
double cost, duplicate notes, two audit records for one item. Not hypothetical —
register_tasks.ps1 sets -StartWhenAvailable, so a missed daily task fires a
catch-up run that can land on top of a manual one."""

import os

import pytest

from pipeline.runlock import LockHeld, RunLock


def test_acquire_creates_the_lock_file(tmp_path):
    lock = tmp_path / "run.lock"
    with RunLock(lock):
        assert lock.exists()


def test_lock_is_released_on_exit(tmp_path):
    lock = tmp_path / "run.lock"
    with RunLock(lock):
        pass
    assert not lock.exists()


def test_lock_is_released_even_if_the_run_raises(tmp_path):
    lock = tmp_path / "run.lock"
    with pytest.raises(ValueError):
        with RunLock(lock):
            raise ValueError("run blew up")
    assert not lock.exists(), "a crashed run must not wedge the pipeline forever"


def test_second_acquire_is_refused(tmp_path):
    lock = tmp_path / "run.lock"
    with RunLock(lock):
        with pytest.raises(LockHeld, match="another run"):
            RunLock(lock).acquire()


def test_lock_records_the_owning_pid(tmp_path):
    lock = tmp_path / "run.lock"
    with RunLock(lock):
        assert lock.read_text(encoding="ascii").strip() == str(os.getpid())


def test_stale_lock_from_a_dead_process_is_reclaimed(tmp_path, monkeypatch):
    """A killed run leaves the file behind. That must not wedge the pipeline
    permanently — it should be recoverable without manual cleanup."""
    lock = tmp_path / "run.lock"
    lock.write_text("999999", encoding="ascii")  # pid that isn't running
    monkeypatch.setattr("pipeline.runlock._pid_alive", lambda pid: False)
    with RunLock(lock):
        assert lock.read_text(encoding="ascii").strip() == str(os.getpid())
    assert not lock.exists()


def test_live_holder_is_never_stolen(tmp_path, monkeypatch):
    lock = tmp_path / "run.lock"
    lock.write_text("4242", encoding="ascii")
    monkeypatch.setattr("pipeline.runlock._pid_alive", lambda pid: True)
    with pytest.raises(LockHeld):
        RunLock(lock).acquire()


def test_unreadable_owner_is_treated_as_held(tmp_path):
    """Garbage in the lock file means we cannot prove the holder is dead.
    Refusing to start is the safe default — a duplicate run costs real money."""
    lock = tmp_path / "run.lock"
    lock.write_text("not-a-pid", encoding="ascii")
    with pytest.raises(LockHeld):
        RunLock(lock).acquire()


def test_lock_can_be_retaken_after_release(tmp_path):
    lock = tmp_path / "run.lock"
    with RunLock(lock):
        pass
    with RunLock(lock):
        assert lock.exists()


def test_pid_alive_says_yes_for_this_process():
    from pipeline.runlock import _pid_alive
    assert _pid_alive(os.getpid()) is True


def test_pid_alive_rejects_nonsense_pids():
    from pipeline.runlock import _pid_alive
    assert _pid_alive(0) is False
    assert _pid_alive(-1) is False


# --- integration with the CLI ---------------------------------------------

def test_cli_exits_zero_when_another_run_holds_the_lock(monkeypatch, tmp_path):
    """A scheduler catch-up landing on a manual run is not a failure — the work
    is already being done. Exiting non-zero would make it look like a crash."""
    from pipeline import config, run

    ran = []
    monkeypatch.setattr(run, "main", lambda argv=None: ran.append(1) or {"failed": 0})
    with RunLock(config.DATA_DIR / "run.lock"):
        with pytest.raises(SystemExit) as exc:
            run.cli([])
    assert exc.value.code == 0
    assert ran == [], "the second run must not do any work"


def test_cli_takes_the_lock_and_runs_when_free(monkeypatch):
    from pipeline import run

    ran = []
    monkeypatch.setattr(run, "main", lambda argv=None: ran.append(1) or {"failed": 0})
    with pytest.raises(SystemExit) as exc:
        run.cli([])
    assert exc.value.code == 0
    assert ran == [1]


# --- the daily and the weekly need opposite answers to a held lock ---
#
# 2026-08-31: both scheduled tasks were deferred by StartWhenAvailable and fired
# at the identical instant on wake (01:40:22). Only pipeline.run took the lock,
# so the weekly drafted its report from a vault the daily was still writing into:
# 19 notes at draft time, 22 by verification, and every count in the report wrong
# by the difference. -MultipleInstances IgnoreNew does not help -- it is per-task.


def test_waiting_acquire_takes_the_lock_once_the_holder_releases(tmp_path):
    path = tmp_path / "run.lock"
    holder = RunLock(path).acquire()
    clock = iter([0.0, 0.0, 1.0, 1.0, 2.0, 2.0, 3.0, 3.0])
    released = []

    def sleep(_seconds):
        # The daily finishes while the weekly is waiting.
        if not released:
            holder.release()
            released.append(True)

    waiter = RunLock(path, wait_seconds=60)
    assert waiter.acquire(now=lambda: next(clock), sleep=sleep) is waiter
    assert released, "the waiter must actually have waited, not walked straight in"
    waiter.release()


def test_waiting_acquire_gives_up_loudly_rather_than_drafting_from_a_moving_vault(tmp_path):
    """Timing out must raise. A weekly that quietly skipped would reproduce the
    silent-missing-week failure from the other direction."""
    path = tmp_path / "run.lock"
    with RunLock(path):
        clock = iter([0.0, 100.0, 100.0])
        with pytest.raises(LockHeld):
            RunLock(path, wait_seconds=60).acquire(
                now=lambda: next(clock), sleep=lambda _s: None
            )


def test_default_lock_does_not_wait(tmp_path):
    """The daily's policy is unchanged: one attempt, then raise, so run.cli()
    can exit 0 and let the run already in flight do the work."""
    path = tmp_path / "run.lock"
    slept = []
    with RunLock(path):
        with pytest.raises(LockHeld):
            RunLock(path).acquire(sleep=lambda s: slept.append(s))
    assert slept == []
