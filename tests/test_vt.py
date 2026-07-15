import base64

import pytest

from pipeline import vt

THREATFOX_ITEM = {
    "source": "threatfox",
    "external_id": "Lumma Stealer:2026-07-15",
    "raw": {
        "family": "Lumma Stealer",
        "iocs": [
            {"ioc": "1.2.3.4:443", "ioc_type": "ip:port"},
            {"ioc": "evil.test", "ioc_type": "domain"},
            {"ioc": "http://bad.test/a.exe", "ioc_type": "url"},
            {"ioc": "a" * 64, "ioc_type": "sha256_hash"},
        ],
    },
}


def test_extract_iocs_maps_threatfox_types():
    assert vt.extract_iocs(THREATFOX_ITEM) == [
        ("ip", "1.2.3.4"),
        ("domain", "evil.test"),
        ("url", "http://bad.test/a.exe"),
        ("file", "a" * 64),
    ]


def test_extract_iocs_dedupes_same_ip_across_ports_and_caps():
    iocs = [{"ioc": f"1.2.3.4:{port}", "ioc_type": "ip:port"} for port in range(20)]
    iocs += [{"ioc": f"10.0.0.{n}", "ioc_type": "ip"} for n in range(20)]
    item = {"source": "threatfox", "raw": {"iocs": iocs}}
    extracted = vt.extract_iocs(item)
    assert extracted[0] == ("ip", "1.2.3.4")
    assert len(extracted) == vt.MAX_LOOKUPS_PER_ITEM


def test_extract_iocs_empty_for_unstructured_sources():
    kev_item = {"source": "kev", "raw": {"cveID": "CVE-2026-1111"}}
    assert vt.extract_iocs(kev_item) == []


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, headers))
        return self.responses.get(url, FakeResponse(404))


STATS = {"malicious": 12, "suspicious": 1, "harmless": 60, "undetected": 10, "timeout": 0}


def _payload(stats):
    return {"data": {"attributes": {"last_analysis_stats": stats}}}


def test_lookup_ip_summarizes_analysis_stats():
    url = "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"
    session = FakeSession({url: FakeResponse(200, _payload(STATS))})
    result = vt.lookup("ip", "1.2.3.4", api_key="k", session=session)
    assert result == {
        "found": True, "malicious": 12, "suspicious": 1,
        "harmless": 60, "undetected": 10,
    }
    assert session.calls[0][1] == {"x-apikey": "k"}


def test_lookup_url_uses_padless_urlsafe_base64_id():
    target = "http://bad.test/a.exe"
    url_id = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    session = FakeSession({endpoint: FakeResponse(200, _payload(STATS))})
    result = vt.lookup("url", target, api_key="k", session=session)
    assert result["found"] is True
    assert session.calls[0][0] == endpoint


def test_lookup_unknown_ioc_returns_not_found():
    result = vt.lookup("domain", "nowhere.test", api_key="k", session=FakeSession())
    assert result == {"found": False}


def test_lookup_raises_on_unexpected_status():
    session = FakeSession({"https://www.virustotal.com/api/v3/domains/x.test": FakeResponse(429)})
    with pytest.raises(RuntimeError, match="429"):
        vt.lookup("domain", "x.test", api_key="k", session=session)


def test_reputation_for_item_builds_block_and_results():
    session = FakeSession({
        "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4": FakeResponse(200, _payload(STATS)),
    })
    sleeps = []
    block, results = vt.reputation_for_item(
        THREATFOX_ITEM, api_key="k", session=session, sleep=sleeps.append
    )
    assert "1.2.3.4" in block
    assert "12 malicious" in block
    assert "not found" in block  # the other IOCs got 404s
    assert len(results) == 4
    assert results[0] == {"service": "virustotal", "kind": "ip", "ioc": "1.2.3.4",
                          "found": True, "malicious": 12, "suspicious": 1,
                          "harmless": 60, "undetected": 10}
    # free tier is 4 lookups/min: must pace between calls, not after the last
    assert len(sleeps) == 3


def test_reputation_for_item_without_key_or_iocs_returns_none():
    assert vt.reputation_for_item(THREATFOX_ITEM, api_key="") == (None, [])
    kev_item = {"source": "kev", "raw": {"cveID": "CVE-2026-1111"}}
    assert vt.reputation_for_item(kev_item, api_key="k") == (None, [])
