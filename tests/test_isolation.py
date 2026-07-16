"""Guard: no test may ever write to production data.

CLAUDE.md makes the audit trail inviolable, but pytest was writing into it —
11 of the 24 records in logs/audit/2026-07-15.jsonl were test artifacts, because
test_weekly.py exercised draft_report() without redirecting config.AUDIT_DIR.
These tests fail if the global isolation fixture in conftest.py ever regresses.
"""

from datetime import date
from pathlib import Path

from pipeline import config
from pipeline.weekly_report import draft_report

# Every config attribute that names a path the pipeline writes to.
WRITABLE_PATH_ATTRS = [
    "VAULT_DIR", "DATA_DIR", "RAW_DIR", "QUARANTINE_DIR",
    "STATE_DB", "LOGS_DIR", "AUDIT_DIR",
]


def test_writable_config_paths_are_redirected_outside_the_repo():
    for attr in WRITABLE_PATH_ATTRS:
        path = Path(getattr(config, attr))
        assert config.ROOT not in path.parents, (
            f"config.{attr} points inside the repo during a test run ({path}); "
            "a test could write to production data"
        )


def test_skill_file_is_still_readable():
    # SKILL_FILE is read-only input, so isolation must NOT redirect it.
    assert config.SKILL_FILE.exists()


def test_draft_report_does_not_write_to_production_audit_log(tmp_path):
    """The exact regression that corrupted the live audit log."""
    (tmp_path / "threats").mkdir(parents=True)
    (tmp_path / "threats" / "n.md").write_text(
        "---\ntitle: T\ntype: threat\nseverity: high\nconfidence: high\n"
        "flagged: false\ndate: 2026-07-14\n---\n\n# T\n",
        encoding="utf-8",
    )
    draft_report(tmp_path, today=date(2026, 7, 15), runner=lambda p: ("# r\n", {}))

    production_audit = Path(__file__).resolve().parents[1] / "logs" / "audit"
    written = list(Path(config.AUDIT_DIR).glob("*.jsonl"))
    assert written, "the weekly report must still write an audit record"
    assert Path(config.AUDIT_DIR) != production_audit
    assert production_audit not in Path(written[0]).parents
