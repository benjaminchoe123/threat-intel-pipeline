"""Append-only JSONL audit trail: what the source said vs. what Claude claimed."""

import json
from datetime import datetime, timezone
from pathlib import Path


def log_enrichment(audit_dir, record):
    audit_dir = Path(audit_dir)
    audit_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    record = {"timestamp": now.isoformat(), **record}
    path = audit_dir / f"{now.date().isoformat()}.jsonl"
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path
