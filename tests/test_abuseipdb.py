import pytest

from pipeline import abuseipdb

from test_vt import THREATFOX_ITEM, FakeResponse


class FakeSession:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append((url, headers, params))
        return self.responses.get(params["ipAddress"], FakeResponse(200, _payload(0, 0)))


def _payload(score, reports):
    return {"data": {"abuseConfidenceScore": score, "totalReports": reports}}


def test_check_summarizes_abuse_report():
    session = FakeSession({"1.2.3.4": FakeResponse(200, _payload(100, 57))})
    result = abuseipdb.check("1.2.3.4", api_key="k", session=session)
    assert result == {"score": 100, "reports": 57}
    url, headers, params = session.calls[0]
    assert url == "https://api.abuseipdb.com/api/v2/check"
    assert headers == {"Key": "k", "Accept": "application/json"}
    assert params == {"ipAddress": "1.2.3.4", "maxAgeInDays": 90}


def test_check_raises_on_error_status():
    session = FakeSession({"1.2.3.4": FakeResponse(429)})
    with pytest.raises(RuntimeError, match="429"):
        abuseipdb.check("1.2.3.4", api_key="k", session=session)


def test_block_for_item_checks_only_ip_iocs():
    session = FakeSession({"1.2.3.4": FakeResponse(200, _payload(100, 57))})
    block, results = abuseipdb.block_for_item(THREATFOX_ITEM, api_key="k", session=session)
    assert "1.2.3.4" in block
    assert "100%" in block
    assert "57 report" in block
    assert len(results) == 1  # item also has domain/url/hash IOCs — not checkable here
    assert results[0] == {"service": "abuseipdb", "ioc": "1.2.3.4", "score": 100, "reports": 57}


def test_block_for_item_without_key_or_ips_returns_none():
    assert abuseipdb.block_for_item(THREATFOX_ITEM, api_key="") == (None, [])
    kev_item = {"source": "kev", "raw": {"cveID": "CVE-2026-1111"}}
    assert abuseipdb.block_for_item(kev_item, api_key="k") == (None, [])
