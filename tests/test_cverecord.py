"""The CVE record gives KEV notes the facts KEV itself does not carry.

2026-W42's notes said "affected versions not stated in source" for both CVEs —
true of KEV, false of the world: the CNA's record on CVE.org listed exact ranges
for both, plus CISA's SSVC decision points. Fixtures below are trimmed from the
real records for CVE-2025-61624 and CVE-2024-3400.
"""

from pipeline import cverecord
from pipeline.cache import ReputationCache


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = responses  # cve -> FakeResponse
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append(url)
        cve = url.rsplit("/", 1)[-1]
        return self.responses.get(cve, FakeResponse(404, {"error": "CVE_RECORD_DNE"}))


FORTINET = {
    "cveMetadata": {"cveId": "CVE-2025-61624", "state": "PUBLISHED", "assignerShortName": "fortinet"},
    "containers": {
        "cna": {
            "affected": [
                {"vendor": "Fortinet", "product": "FortiOS", "defaultStatus": "unaffected",
                 "versions": [
                     {"version": "7.6.0", "lessThanOrEqual": "7.6.4", "status": "affected"},
                     {"version": "7.2.0", "lessThan": "7.2.12", "status": "affected"},
                     {"version": "8.0.0", "status": "unaffected"},
                 ]},
            ],
            "metrics": [{"cvssV3_1": {"baseScore": 6.7, "baseSeverity": "MEDIUM",
                                      "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}}],
            "references": [
                {"url": "https://fortiguard.fortinet.com/psirt/FG-IR-26-122", "tags": ["vendor-advisory"]},
                {"url": "https://example.com/blog"},
            ],
        },
        "adp": [{
            "providerMetadata": {"shortName": "CISA-ADP"},
            "metrics": [{"other": {"type": "ssvc", "content": {"options": [
                {"Exploitation": "active"}, {"Automatable": "no"}, {"Technical Impact": "total"},
            ]}}}],
        }],
    },
}

KEV_ITEM = {"source": "kev", "raw": {"cveID": "CVE-2025-61624", "vendorProject": "Fortinet"}}


def test_summary_keeps_affected_ranges_and_drops_unaffected():
    s = cverecord.summarize(FORTINET)
    assert s["affected"] == [{
        "vendor": "Fortinet", "product": "FortiOS",
        "ranges": ["7.6.0 through 7.6.4", "7.2.0 up to (not including) 7.2.12"],
    }]


def test_summary_reads_cvss_ssvc_and_vendor_advisories():
    s = cverecord.summarize(FORTINET)
    assert s["cvss"] == {"version": "3.1", "score": 6.7, "severity": "MEDIUM",
                         "vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "by": "CNA"}
    assert s["ssvc"] == {"Exploitation": "active", "Automatable": "no", "Technical Impact": "total"}
    assert s["advisories"] == ["https://fortiguard.fortinet.com/psirt/FG-IR-26-122"]


def test_open_lower_bound_reads_as_everything_before():
    record = {"containers": {"cna": {"affected": [{"vendor": "BeyondTrust", "product": "Remote Support",
              "versions": [{"version": "0", "lessThanOrEqual": "26.2.3", "status": "affected"}]}]}}}
    assert cverecord.summarize(record)["affected"][0]["ranges"] == ["up to and including 26.2.3"]


def test_cvss_falls_back_to_cisa_adp_when_the_cna_gave_none():
    record = {"containers": {"cna": {}, "adp": [{
        "providerMetadata": {"shortName": "CISA-ADP"},
        "metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "V"}}],
    }]}}
    assert cverecord.summarize(record)["cvss"]["by"] == "CISA-ADP"


def test_block_states_versions_as_record_facts():
    block, results = cverecord.block_for_item(
        KEV_ITEM, session=FakeSession({"CVE-2025-61624": FakeResponse(200, FORTINET)}))
    assert "Fortinet FortiOS: 7.6.0 through 7.6.4" in block
    assert "exploitation=active" in block
    assert "FG-IR-26-122" in block
    assert results[0]["service"] == "cve_record" and results[0]["found"] is True


def test_missing_record_is_unknown_not_unaffected():
    block, results = cverecord.block_for_item(KEV_ITEM, session=FakeSession({}))
    assert "no published CVE record" in block
    assert "unknown" in block.lower()
    assert results[0]["found"] is False


def test_one_failed_cve_does_not_lose_the_others():
    item = {"source": "mta", "raw": {"t": "CVE-2025-61624 and CVE-2024-0001"}}
    session = FakeSession({"CVE-2025-61624": FakeResponse(200, FORTINET),
                           "CVE-2024-0001": FakeResponse(503, None)})
    block, results = cverecord.block_for_item(item, session=session)
    assert "7.6.0 through 7.6.4" in block
    assert "CVE-2024-0001: CVE record lookup failed" in block
    assert {r["ioc"]: r.get("error_type") for r in results}["CVE-2024-0001"] == "CveRecordError"


def test_requests_are_capped_per_item():
    cves = " ".join(f"CVE-2024-{n:04d}" for n in range(1, 10))
    session = FakeSession({})
    cverecord.block_for_item({"source": "mta", "raw": {"t": cves}}, session=session)
    assert len(session.calls) == cverecord.MAX_CVES_PER_ITEM


def test_cache_hit_avoids_a_request_and_is_marked(tmp_path):
    session = FakeSession({"CVE-2025-61624": FakeResponse(200, FORTINET)})
    with ReputationCache(tmp_path / "c.db") as cache:
        cverecord.block_for_item(KEV_ITEM, session=session, cache=cache)
        _, results = cverecord.block_for_item(KEV_ITEM, session=session, cache=cache)
    assert len(session.calls) == 1
    assert results[0]["cached"] is True


def test_no_cves_means_no_block():
    assert cverecord.block_for_item({"source": "threatfox", "raw": {"iocs": []}},
                                    session=FakeSession({})) == (None, [])
