"""One-shot repair: remove pytest artifacts from the audit trail.

Before the conftest.py isolation fixture existed, `python -m pytest` appended
records to logs/audit/ — weekly_report.draft_report() logs to the global
config.AUDIT_DIR and test_weekly.py never redirected it. Those records describe
enrichments that never happened, against notes that never existed.

Deleting audit records is normally forbidden (CLAUDE.md: "Never skip or weaken
the audit trail"). This is the exception that serves the rule: fabricated records
are what weaken the trail, and the purge itself is logged as a maintenance record
naming every timestamp removed, so the deletion is auditable.

A record is an artifact only if one of its path fields points into a pytest tmp
dir. That test is deliberately narrow — the live log holds a real weekly_report
record that is otherwise shaped identically to the fakes, and a real enrichment
whose external_id is empty (the ingestion-failure incident). Both must survive.

    python scripts/purge_test_records.py            # dry run, prints the plan
    python scripts/purge_test_records.py --apply    # rewrites the log
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline import config  # noqa: E402

PYTEST_TMP = re.compile(r"pytest-of-[^\\/]+[\\/]+pytest-\d+", re.IGNORECASE)
PATH_FIELDS = ("draft_path", "raw_snapshot", "note_path", "quarantine_path")


def is_test_artifact(record):
    """True only if a path field points into a pytest temp dir."""
    return any(
        isinstance(record.get(f), str) and PYTEST_TMP.search(record[f])
        for f in PATH_FIELDS
    )


def purge_file(path, apply=False):
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    artifacts = [r for r in records if is_test_artifact(r)]
    keep = [r for r in records if not is_test_artifact(r)]
    if not artifacts:
        print(f"{path.name}: clean ({len(records)} records)")
        return 0

    print(f"{path.name}: {len(records)} records -> {len(keep)} kept, {len(artifacts)} artifacts")
    for r in artifacts:
        which = next((f for f in PATH_FIELDS if isinstance(r.get(f), str) and PYTEST_TMP.search(r[f])), "?")
        print(f"  drop {r['timestamp']}  type={r.get('type', 'enrichment')}  via {which}")
    if not apply:
        print("  (dry run — pass --apply to rewrite)")
        return len(artifacts)

    backup = path.with_suffix(path.suffix + ".corrupted-backup")
    backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    keep.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "maintenance",
        "action": "purge_test_artifacts",
        "reason": (
            "pytest wrote these records to the production audit log before the "
            "conftest.py isolation fixture existed; they describe enrichments that "
            "never ran. Removed to restore the trail's accuracy."
        ),
        "removed_count": len(artifacts),
        "removed_timestamps": [r["timestamp"] for r in artifacts],
        "backup": str(backup),
    })
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in keep), encoding="utf-8"
    )
    print(f"  rewritten; backup at {backup.name}")
    return len(artifacts)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--apply", action="store_true", help="rewrite the logs (default: dry run)")
    args = parser.parse_args(argv)

    files = sorted(Path(config.AUDIT_DIR).glob("*.jsonl"))
    if not files:
        print(f"no audit logs in {config.AUDIT_DIR}")
        return 0
    total = sum(purge_file(p, apply=args.apply) for p in files)
    print(f"\ntotal artifacts: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
