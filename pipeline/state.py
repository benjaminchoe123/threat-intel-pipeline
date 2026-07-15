"""Dedupe/state tracking backed by SQLite.

check() classifies an incoming item against what previous runs recorded:
  "new"     — never seen this (source, external_id)
  "updated" — seen, but the source content changed (e.g. CISA edits a KEV entry)
  "seen"    — seen with identical content; skip
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class State:
    def __init__(self, db_path):
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS seen (
                source TEXT NOT NULL,
                external_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (source, external_id)
            )"""
        )
        self._conn.commit()

    def check(self, source, external_id, content_hash):
        row = self._conn.execute(
            "SELECT content_hash FROM seen WHERE source = ? AND external_id = ?",
            (source, external_id),
        ).fetchone()
        if row is None:
            return "new"
        return "seen" if row[0] == content_hash else "updated"

    def record(self, source, external_id, content_hash):
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO seen (source, external_id, content_hash, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(source, external_id)
               DO UPDATE SET content_hash = excluded.content_hash, last_seen = excluded.last_seen""",
            (source, external_id, content_hash, now, now),
        )
        self._conn.commit()
