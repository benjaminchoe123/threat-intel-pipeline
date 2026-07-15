"""Reputation is prompt context, never a precondition.

A VirusTotal 429 used to propagate out of main() and abandon every remaining item
across every source — an outage at a third-party enrichment service stopped the
whole pipeline. It must degrade the note instead.
"""

import pytest

from pipeline import abuseipdb, reputation, vt
from pipeline.cache import ReputationCache
from pipeline.ratelimit import RateLimiter

from test_vt import THREATFOX_ITEM, FakeResponse

ITEM = THREATFOX_ITEM


def _nolimit():
    return RateLimiter(0, sleep=lambda s: None, clock=lambda: 0.0)


# --- provider failures never escape ---------------------------------------

def test_vt_failure_does_not_stop_abuseipdb():
    def vt_fn(item):
        raise vt.RateLimitError("VirusTotal returned 429", retry_after=60)

    block, results = reputation.reputation_for_item(
        ITEM, vt_fn=vt_fn, abuse_fn=lambda i: ("- 1.2.3.4: abuse confidence 100%", [{"ok": 1}])
    )
    assert "lookup unavailable" in block
    assert "1.2.3.4" in block, "AbuseIPDB must still run after VirusTotal fails"
    assert any(r.get("error_type") == "RateLimitError" for r in results)


def test_both_providers_failing_still_returns_a_block_not_an_exception():
    def boom(item):
        raise RuntimeError("down")

    block, results = reputation.reputation_for_item(ITEM, vt_fn=boom, abuse_fn=boom)
    assert block is not None
    assert block.count("lookup unavailable") == 2
    assert len(results) == 2


def test_unavailable_is_not_presented_as_a_clean_verdict():
    """The model must not read a failed lookup as 'nothing found' — a different claim."""
    block, _ = reputation.reputation_for_item(
        ITEM, vt_fn=lambda i: (_ for _ in ()).throw(RuntimeError("x")),
        abuse_fn=lambda i: (None, []),
    )
    assert "treat as no data, not as a clean verdict" in block


def test_failure_is_recorded_for_the_audit_log():
    block, results = reputation.reputation_for_item(
        ITEM, vt_fn=lambda i: (_ for _ in ()).throw(RuntimeError("boom")),
        abuse_fn=lambda i: (None, []),
    )
    assert results[0]["service"] == "virustotal"
    assert results[0]["error"] == "boom"


# --- 429 is distinguishable and carries Retry-After -----------------------

def test_vt_429_raises_ratelimiterror_with_retry_after():
    class Resp(FakeResponse):
        headers = {"Retry-After": "60"}

    class Session:
        def get(self, url, headers=None, timeout=None):
            return Resp(429)

    with pytest.raises(vt.RateLimitError) as exc:
        vt.lookup("domain", "x.test", api_key="k", session=Session())
    assert exc.value.retry_after == 60


def test_abuseipdb_429_raises_ratelimiterror():
    class Session:
        def get(self, url, headers=None, params=None, timeout=None):
            return FakeResponse(429)

    with pytest.raises(abuseipdb.RateLimitError):
        abuseipdb.check("1.2.3.4", api_key="k", session=Session())


def test_vt_unreadable_200_raises_a_typed_error_not_a_keyerror():
    class Session:
        def get(self, url, headers=None, timeout=None):
            return FakeResponse(200, {"unexpected": "html error page"})

    with pytest.raises(vt.VirusTotalError, match="unreadable"):
        vt.lookup("domain", "x.test", api_key="k", session=Session())


# --- caching --------------------------------------------------------------

def test_cache_hit_skips_the_http_call_and_the_pacing_delay(tmp_path):
    class CountingSession:
        def __init__(self):
            self.calls = 0

        def get(self, url, headers=None, timeout=None):
            self.calls += 1
            return FakeResponse(200, {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 12, "harmless": 60}}}})

    session = CountingSession()
    item = {"source": "threatfox", "raw": {"iocs": [{"ioc": "1.2.3.4", "ioc_type": "ip"}]}}
    with ReputationCache(tmp_path / "c.db") as cache:
        vt.reputation_for_item(item, api_key="k", session=session, cache=cache,
                               limiter=_nolimit())
        assert session.calls == 1

        sleeps = []
        _, results = vt.reputation_for_item(
            item, api_key="k", session=session, cache=cache,
            limiter=RateLimiter(15, sleep=sleeps.append, clock=lambda: 0.0),
        )
        assert session.calls == 1, "second lookup must be served from cache"
        assert sleeps == [], "a cache hit must not burn a pacing delay"
        assert results[0]["cached"] is True
        assert results[0]["malicious"] == 12


def test_cache_shared_across_items_with_the_same_ioc(tmp_path):
    """The same C2 IP appearing under two families should cost one lookup."""
    class CountingSession:
        def __init__(self):
            self.calls = 0

        def get(self, url, headers=None, timeout=None):
            self.calls += 1
            return FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {}}}})

    session = CountingSession()
    a = {"source": "threatfox", "raw": {"family": "A", "iocs": [{"ioc": "1.2.3.4", "ioc_type": "ip"}]}}
    b = {"source": "threatfox", "raw": {"family": "B", "iocs": [{"ioc": "1.2.3.4", "ioc_type": "ip"}]}}
    with ReputationCache(tmp_path / "c.db") as cache:
        vt.reputation_for_item(a, api_key="k", session=session, cache=cache, limiter=_nolimit())
        vt.reputation_for_item(b, api_key="k", session=session, cache=cache, limiter=_nolimit())
    assert session.calls == 1


# --- AbuseIPDB no longer inherits VirusTotal's cap ------------------------

def test_abuseipdb_finds_ips_past_virustotals_cap():
    """VT truncates to 4 before filtering by kind; sharing that list meant an item
    whose first 4 IOCs were domains got no IP checks at all."""
    item = {"source": "threatfox", "raw": {"iocs": [
        {"ioc": "a.test", "ioc_type": "domain"},
        {"ioc": "b.test", "ioc_type": "domain"},
        {"ioc": "c.test", "ioc_type": "domain"},
        {"ioc": "d.test", "ioc_type": "domain"},
        {"ioc": "9.9.9.9", "ioc_type": "ip"},
    ]}}
    assert vt.extract_iocs(item) == [
        ("domain", "a.test"), ("domain", "b.test"),
        ("domain", "c.test"), ("domain", "d.test"),
    ]
    assert abuseipdb.extract_ips(item) == ["9.9.9.9"]


def test_abuseipdb_has_its_own_cap():
    item = {"source": "threatfox", "raw": {
        "iocs": [{"ioc": f"10.0.0.{n}", "ioc_type": "ip"} for n in range(20)]}}
    assert len(abuseipdb.extract_ips(item)) == abuseipdb.MAX_IPS_PER_ITEM


# --- IPv6 port stripping --------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("1.2.3.4:443", "1.2.3.4"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("2001:db8::1", "2001:db8::1"),  # bare IPv6: no port to strip
])
def test_strip_port_handles_ipv6(raw, expected):
    assert vt._strip_port(raw) == expected
