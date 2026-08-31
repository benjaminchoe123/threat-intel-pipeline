"""Single-run lock.

state.check() and state.record() sit either side of the whole enrichment, so two
overlapping runs both classify the same item as "new" and both enrich it: double
`claude` cost, duplicate notes, two audit records for one item. That is not
hypothetical here — register_tasks.ps1 sets -StartWhenAvailable, so a missed
daily task fires a catch-up run that can land on top of a manual one.

A lock file is the right shape for this: the runs are separate processes on one
machine, and the failure we care about (two runs at once) is exactly what an
exclusive file create prevents. O_CREAT|O_EXCL is atomic on Windows and POSIX
alike, so no two processes can both believe they took it.

The lock records its owner PID so a stale lock left by a killed run is
recoverable rather than a permanent outage.
"""

import errno
import logging
import os
import time
from pathlib import Path

log = logging.getLogger(__name__)


class LockHeld(RuntimeError):
    """Another run holds the lock."""


class RunLock:
    """Exclusive lock for the duration of a run.

    with RunLock(path):
        ...

    `wait_seconds` makes acquisition block instead of raising immediately. The
    two schedulers need opposite answers to "someone else holds this":

      * The daily run should give up (and exit 0). Another run is already doing
        its job; a second one double-enriches and double-bills.
      * The weekly report should wait. Nobody else is going to write it, so
        giving up turns a collision into a silently missing week — the exact
        outage the health work exists to make impossible.

    Same primitive, opposite policy. Do not "tidy" them into agreement.
    """

    def __init__(self, path, wait_seconds=0, poll_seconds=5.0):
        self.path = Path(path)
        self.wait_seconds = wait_seconds
        self.poll_seconds = poll_seconds
        self._fd = None

    def acquire(self, now=time.monotonic, sleep=time.sleep):
        """Take the lock, optionally waiting up to `wait_seconds` for it.

        The deadline is checked *after* a failed attempt so that wait_seconds=0
        behaves exactly as the non-blocking version always has: one try, then
        raise. Timing is injected so the waiting path can be tested without one.
        """
        deadline = now() + self.wait_seconds
        while True:
            try:
                return self._try_acquire()
            except LockHeld:
                if now() >= deadline:
                    raise
                log.info("waiting up to %ss for %s", self.wait_seconds, self.path)
                sleep(min(self.poll_seconds, max(deadline - now(), 0)))

    def _try_acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
            owner = self._read_owner()
            if owner is not None and not _pid_alive(owner):
                # The holder is gone — a killed or crashed run. Reclaim rather
                # than leaving the pipeline wedged until someone deletes a file.
                log.warning("removing stale lock from dead pid %s at %s", owner, self.path)
                self._steal()
                return self
            raise LockHeld(
                f"another run holds {self.path} (pid {owner}); "
                "refusing to start a second one"
            ) from e
        os.write(self._fd, str(os.getpid()).encode("ascii"))
        return self

    def _steal(self):
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass  # another process beat us to the cleanup
        self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(self._fd, str(os.getpid()).encode("ascii"))

    def _read_owner(self):
        try:
            return int(self.path.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return None

    def release(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()
        return False


def _pid_alive(pid):
    """True if a process with this pid exists.

    Conservative: if we cannot tell, assume alive, because wrongly declaring a
    live run dead would let two runs proceed — the exact thing being prevented.
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        import subprocess
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, text=True, timeout=10,
            )
            return str(pid) in out.stdout
        except (OSError, subprocess.SubprocessError):
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    return True
