"""GreyNoise separates mass scanners from dedicated infrastructure.

The other sources answer "is this IP bad?". GreyNoise answers "is this IP
spraying the whole internet?" - which changes what a high abuse score means.
"""

import pytest

from pipeline import greynoise
from pipeline.cache import ReputationCache
from pipeline.ratelimit import RateLimiter

ITEM = {"source": "threatfox", "raw": {"iocs": [
    {"ioc": "1.2.3.4:443", "ioc_type": "ip:port"},
    {"ioc": "evil.test", "ioc_type": "domain"},
]}}


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, by_ip=None):
        self.by_ip = by_ip or {}
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        ip = url.rstrip("/").rsplit("/", 1)[-1]
        self.calls.append((url, headers))
        return self.by_ip.get(ip, FakeResponse(404))


def _nolimit():
    return RateLimiter(0, sleep=lambda s: None, clock=lambda: 0.0)


SCANNER = {"seen": True, "classification": "malicious", "name": "unknown",
           "last_seen": "2026-07-14"}
BENIGN = {"seen": True, "classification": "benign", "name": "Shodan.io",
          "last_seen": "2026-07-14"}


def test_check_reports_a_scanner():
    session = FakeSession({"1.2.3.4": FakeResponse(200, SCANNER)})
    result = greynoise.check("1.2.3.4", api_key="k", session=session)
    assert result["seen"] is True
    assert result["classification"] == "malicious"


def test_check_sends_the_key_header():
    session = FakeSession({"1.2.3.4": FakeResponse(200, SCANNER)})
    greynoise.check("1.2.3.4", api_key="secret", session=session)
    assert session.calls[0][1]["key"] == "secret"


def test_404_means_not_seen_not_an_error():
    """Absence from GreyNoise is meaningful: the IP is not mass-scanning."""
    result = greynoise.check("9.9.9.9", api_key="k", session=FakeSession())
    assert result == {"seen": False}


def test_429_raises_ratelimiterror():
    session = FakeSession({"1.2.3.4": FakeResponse(429)})
    with pytest.raises(greynoise.RateLimitError):
        greynoise.check("1.2.3.4", api_key="k", session=session)


def test_error_status_raises():
    session = FakeSession({"1.2.3.4": FakeResponse(401)})
    with pytest.raises(greynoise.GreyNoiseError, match="401"):
        greynoise.check("1.2.3.4", api_key="k", session=session)


# --- the prompt block must not mislead ------------------------------------

def test_unseen_ip_is_not_described_as_clean():
    session = FakeSession()
    block, _ = greynoise.block_for_item(ITEM, api_key="k", session=session,
                                        limiter=_nolimit())
    assert "not a verdict" in block
    assert "dedicated infrastructure" in block


def test_benign_scanner_is_called_out_as_a_likely_false_positive():
    session = FakeSession({"1.2.3.4": FakeResponse(200, BENIGN)})
    block, _ = greynoise.block_for_item(ITEM, api_key="k", session=session,
                                        limiter=_nolimit())
    assert "Shodan.io" in block
    assert "false positive" in block


def test_malicious_scanner_is_framed_as_noise_not_targeting():
    session = FakeSession({"1.2.3.4": FakeResponse(200, SCANNER)})
    block, _ = greynoise.block_for_item(ITEM, api_key="k", session=session,
                                        limiter=_nolimit())
    assert "not necessarily targeting" in block


def test_only_ip_iocs_are_checked():
    session = FakeSession({"1.2.3.4": FakeResponse(200, SCANNER)})
    _, results = greynoise.block_for_item(ITEM, api_key="k", session=session,
                                          limiter=_nolimit())
    assert len(results) == 1  # the domain IOC is not checkable here
    assert results[0]["ioc"] == "1.2.3.4"


def test_no_key_disables_the_lookup():
    assert greynoise.block_for_item(ITEM, api_key="") == (None, [])


def test_no_ips_returns_none():
    item = {"source": "kev", "raw": {"cveID": "CVE-2026-1"}}
    assert greynoise.block_for_item(item, api_key="k") == (None, [])


def test_cache_hit_avoids_the_http_call(tmp_path):
    session = FakeSession({"1.2.3.4": FakeResponse(200, SCANNER)})
    with ReputationCache(tmp_path / "c.db") as cache:
        greynoise.block_for_item(ITEM, api_key="k", session=session, cache=cache,
                                 limiter=_nolimit())
        greynoise.block_for_item(ITEM, api_key="k", session=session, cache=cache,
                                 limiter=_nolimit())
    assert len(session.calls) == 1
