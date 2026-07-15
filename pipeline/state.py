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
        # timeout: a concurrent run should wait for the lock, not raise instantly.
        # WAL: readers never block the writer, and it survives a mid-write crash.
        self._conn = sqlite3.connect(db_path, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
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
        # Quarantined items are deliberately NOT written to `seen` — they must stay
        # re-processable after a skill or validator fix. This counts attempts so a
        # permanently malformed item can't be retried forever.
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS quarantine (
                source TEXT NOT NULL,
                external_id TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                last_attempt TEXT NOT NULL,
                PRIMARY KEY (source, external_id)
            )"""
        )
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

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

    def record_quarantine(self, source, external_id):
        """Count one failed enrichment attempt. Returns the new attempt total."""
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO quarantine (source, external_id, attempts, last_attempt)
               VALUES (?, ?, 1, ?)
               ON CONFLICT(source, external_id)
               DO UPDATE SET attempts = attempts + 1, last_attempt = excluded.last_attempt""",
            (source, external_id, now),
        )
        self._conn.commit()
        return self.quarantine_attempts(source, external_id)

    def quarantine_attempts(self, source, external_id):
        row = self._conn.execute(
            "SELECT attempts FROM quarantine WHERE source = ? AND external_id = ?",
            (source, external_id),
        ).fetchone()
        return row[0] if row else 0
