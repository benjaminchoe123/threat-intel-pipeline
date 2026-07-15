"""The purge must remove only pytest artifacts — never a real record.

The live log contains two records that look deletable and are not: a genuine
weekly_report shaped identically to the fake ones, and a genuine enrichment whose
external_id is empty (the ingestion-failure incident). Both are covered here.
"""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "purge_test_records",
    Path(__file__).resolve().parents[1] / "scripts" / "purge_test_records.py",
)
purge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(purge)

FAKE_WEEKLY = {
    "timestamp": "2026-07-15T06:56:16.049050+00:00", "type": "weekly_report",
    "draft_path": r"C:\Users\wi754\AppData\Local\Temp\pytest-of-wi754\pytest-9\test_draft0\r.md",
}
REAL_WEEKLY = {
    "timestamp": "2026-07-15T06:58:01.106020+00:00", "type": "weekly_report",
    "draft_path": r"C:\Claude\threat-intel-pipeline\vault\reports\drafts\2026-W29-DRAFT.md",
}
REAL_EMPTY_MTA = {
    "timestamp": "2026-07-15T06:53:35.612959+00:00", "source": "mta", "external_id": "",
    "raw_snapshot": r"C:\Claude\threat-intel-pipeline\data\raw\mta\.json",
    "note_path": r"C:\Claude\threat-intel-pipeline\vault\threats\2026-07-15-Empty.md",
}
REAL_ENRICHMENT = {
    "timestamp": "2026-07-15T06:50:00+00:00", "source": "kev", "external_id": "CVE-2026-56155",
    "raw_snapshot": r"C:\Claude\threat-intel-pipeline\data\raw\kev\CVE-2026-56155.json",
}


def test_fake_weekly_is_an_artifact():
    assert purge.is_test_artifact(FAKE_WEEKLY)


def test_real_records_are_never_artifacts():
    for record in (REAL_WEEKLY, REAL_EMPTY_MTA, REAL_ENRICHMENT):
        assert not purge.is_test_artifact(record), record["timestamp"]


def test_record_with_no_path_fields_is_kept():
    assert not purge.is_test_artifact({"timestamp": "t", "type": "maintenance"})


def test_purge_file_keeps_real_records_and_logs_the_deletion(tmp_path):
    log = tmp_path / "2026-07-15.jsonl"
    import json
    log.write_text(
        "".join(json.dumps(r) + "\n" for r in [REAL_ENRICHMENT, FAKE_WEEKLY, REAL_WEEKLY]),
        encoding="utf-8",
    )
    removed = purge.purge_file(log, apply=True)
    assert removed == 1

    kept = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    timestamps = [r["timestamp"] for r in kept]
    assert REAL_ENRICHMENT["timestamp"] in timestamps
    assert REAL_WEEKLY["timestamp"] in timestamps
    assert FAKE_WEEKLY["timestamp"] not in timestamps

    # The deletion is itself recorded, naming what was removed.
    maintenance = kept[-1]
    assert maintenance["type"] == "maintenance"
    assert maintenance["removed_timestamps"] == [FAKE_WEEKLY["timestamp"]]
    assert log.with_suffix(".jsonl.corrupted-backup").exists()


def test_dry_run_does_not_modify_the_file(tmp_path):
    import json
    log = tmp_path / "2026-07-15.jsonl"
    original = json.dumps(FAKE_WEEKLY) + "\n"
    log.write_text(original, encoding="utf-8")
    purge.purge_file(log, apply=False)
    assert log.read_text(encoding="utf-8") == original
