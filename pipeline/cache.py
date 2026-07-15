"""Cross-run cache for reputation lookups, in the existing state DB.

There was no caching at any layer. That hurts most on the abuse.ch feeds, whose
external_id is f"{family}:{day}" — every day is a new item *by construction*, so
each run re-looked-up the same long-lived C2 infrastructure from scratch, and the
same IOC appearing under two families paid twice within a single run.

Caching is also what makes the free tiers workable: a cache hit costs no quota and
no pacing delay, so the rate limiter only throttles genuinely new IOCs.
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_TTL_DAYS = 7


class ReputationCache:
    """(service, ioc) -> lookup result, expiring after ttl_days.

    A TTL matters here: reputation is a claim about the present. A verdict from
    six months ago is not evidence about infrastructure today, so stale entries
    expire rather than being served forever.
    """

    def __init__(self, db_path, ttl_days=DEFAULT_TTL_DAYS):
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(days=ttl_days)
        self._conn = sqlite3.connect(db_path, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS reputation_cache (
                service TEXT NOT NULL,
                ioc TEXT NOT NULL,
                result TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                PRIMARY KEY (service, ioc)
            )"""
        )
        self._conn.commit()

    def get(self, service, ioc, now=None):
        """Return the cached result, or None if absent or expired."""
        row = self._conn.execute(
            "SELECT result, fetched_at FROM reputation_cache WHERE service = ? AND ioc = ?",
            (service, ioc),
        ).fetchone()
        if row is None:
            return None
        now = now or datetime.now(timezone.utc)
        try:
            fetched_at = datetime.fromisoformat(row[1])
        except ValueError:
            return None
        if now - fetched_at > self.ttl:
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return None

    def put(self, service, ioc, result, now=None):
        now = now or datetime.now(timezone.utc)
        self._conn.execute(
            """INSERT INTO reputation_cache (service, ioc, result, fetched_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(service, ioc)
               DO UPDATE SET result = excluded.result, fetched_at = excluded.fetched_at""",
            (service, ioc, json.dumps(result, ensure_ascii=False), now.isoformat()),
        )
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
