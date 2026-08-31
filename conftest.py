"""Global test isolation.

Every filesystem path the pipeline writes to is redirected to a per-test tmp dir
before any test runs. This is autouse and repo-wide on purpose: individual tests
opting in one at a time is what failed before — test_run.py redirected its dirs,
test_weekly.py did not, and pytest silently appended records to the production
audit log that CLAUDE.md declares inviolable.

SKILL_FILE is deliberately not redirected: it is read-only pipeline input.
"""

import pytest

from pipeline import config

# config attribute -> path relative to the per-test tmp dir.
_WRITABLE_PATHS = {
    "VAULT_DIR": "vault",
    "DATA_DIR": "data",
    "RAW_DIR": "data/raw",
    "QUARANTINE_DIR": "data/quarantine",
    "STATE_DB": "data/state.db",
    "LOGS_DIR": "logs",
    "AUDIT_DIR": "logs/audit",
}


@pytest.fixture(autouse=True)
def isolate_production_paths(tmp_path, monkeypatch):
    """Point every writable config path at tmp_path for the duration of a test."""
    for attr, relative in _WRITABLE_PATHS.items():
        monkeypatch.setattr(config, attr, tmp_path.joinpath(*relative.split("/")))
    return tmp_path


@pytest.fixture(autouse=True)
def isolate_host_scheduler(monkeypatch):
    """No test may read this machine's real Task Scheduler.

    Same reasoning as the paths above, one layer out. `health.check()` reads the
    OS scheduler because that is the only observer of a run killed before it
    could write anything — but a test asserting "healthy" would then pass or
    fail depending on whether the developer's own ThreatIntel-Daily happened to
    die last night. It did, which is how this fixture came to exist.

    Tests that care about the killed-task path inject their own reading.
    """
    from pipeline import scheduler

    monkeypatch.setattr(scheduler, "killed_tasks", lambda *a, **kw: [])
