from datetime import UTC, datetime, timedelta

from pipeline.cache import ReputationCache
from pipeline.ratelimit import RateLimiter

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
RESULT = {"found": True, "malicious": 12, "harmless": 60}


# --- cache ----------------------------------------------------------------

def test_put_then_get_roundtrips(tmp_path):
    with ReputationCache(tmp_path / "c.db") as cache:
        cache.put("virustotal", "1.2.3.4", RESULT, now=NOW)
        assert cache.get("virustotal", "1.2.3.4", now=NOW) == RESULT


def test_miss_returns_none(tmp_path):
    with ReputationCache(tmp_path / "c.db") as cache:
        assert cache.get("virustotal", "9.9.9.9") is None


def test_services_do_not_collide(tmp_path):
    with ReputationCache(tmp_path / "c.db") as cache:
        cache.put("virustotal", "1.2.3.4", {"malicious": 12}, now=NOW)
        cache.put("abuseipdb", "1.2.3.4", {"score": 100}, now=NOW)
        assert cache.get("virustotal", "1.2.3.4", now=NOW) == {"malicious": 12}
        assert cache.get("abuseipdb", "1.2.3.4", now=NOW) == {"score": 100}


def test_entry_expires_after_ttl(tmp_path):
    with ReputationCache(tmp_path / "c.db", ttl_days=7) as cache:
        cache.put("virustotal", "1.2.3.4", RESULT, now=NOW)
        assert cache.get("virustotal", "1.2.3.4", now=NOW + timedelta(days=6)) == RESULT
        # reputation is a claim about the present — stale verdicts must not persist
        assert cache.get("virustotal", "1.2.3.4", now=NOW + timedelta(days=8)) is None


def test_put_overwrites_and_refreshes_timestamp(tmp_path):
    with ReputationCache(tmp_path / "c.db", ttl_days=7) as cache:
        cache.put("virustotal", "1.2.3.4", {"malicious": 1}, now=NOW)
        later = NOW + timedelta(days=6)
        cache.put("virustotal", "1.2.3.4", {"malicious": 99}, now=later)
        assert cache.get("virustotal", "1.2.3.4", now=later + timedelta(days=1)) == {"malicious": 99}


def test_survives_a_new_connection(tmp_path):
    with ReputationCache(tmp_path / "c.db") as cache:
        cache.put("virustotal", "1.2.3.4", RESULT, now=NOW)
    with ReputationCache(tmp_path / "c.db") as reopened:
        assert reopened.get("virustotal", "1.2.3.4", now=NOW) == RESULT


def test_corrupt_row_is_treated_as_a_miss(tmp_path):
    cache = ReputationCache(tmp_path / "c.db")
    cache._conn.execute(
        "INSERT INTO reputation_cache VALUES ('virustotal', 'x', '{bad json', ?)",
        (NOW.isoformat(),),
    )
    cache._conn.commit()
    assert cache.get("virustotal", "x", now=NOW) is None
    cache.close()


# --- rate limiter ---------------------------------------------------------

class FakeClock:
    """A clock that only advances when something sleeps."""

    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.t += seconds

    def __call__(self):
        return self.t


def test_first_call_does_not_wait():
    clock = FakeClock()
    RateLimiter(15, sleep=clock.sleep, clock=clock).wait()
    assert clock.sleeps == []


def test_second_immediate_call_waits_the_full_interval():
    clock = FakeClock()
    limiter = RateLimiter(15, sleep=clock.sleep, clock=clock)
    limiter.wait()
    limiter.wait()
    assert clock.sleeps == [15]


def test_pacing_spans_items_not_just_one_item():
    """The bug: pacing was per-item, so the last lookup of item N and the first of
    item N+1 went out back-to-back, breaching the 4/min free tier."""
    clock = FakeClock()
    limiter = RateLimiter(15, sleep=clock.sleep, clock=clock)
    for _ in range(4):  # item N
        limiter.wait()
    clock.sleeps.clear()
    limiter.wait()  # item N+1's first lookup
    assert clock.sleeps == [15], "must still pace across the item boundary"


def test_no_wait_when_enough_time_already_passed():
    clock = FakeClock()
    limiter = RateLimiter(15, sleep=clock.sleep, clock=clock)
    limiter.wait()
    clock.t += 20  # e.g. a slow claude -p call happened in between
    limiter.wait()
    assert clock.sleeps == []
