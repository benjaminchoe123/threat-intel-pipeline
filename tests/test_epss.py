"""EPSS gives KEV notes their first piece of independent evidence.

VirusTotal and AbuseIPDB both key off item["raw"]["iocs"], which only the
abuse.ch sources produce — so KEV and MTA items reached the model with no
reputation context at all, and severity rested on model judgment alone.
"""

import pytest

from pipeline import epss
from pipeline.cache import ReputationCache


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, payload=None, status_code=200):
        self.calls = []
        self._payload = payload
        self._status = status_code

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params))
        return FakeResponse(self._status, self._payload)


def _payload(*rows):
    return {"status": "OK", "data": [
        {"cve": c, "epss": e, "percentile": p, "date": "2026-07-15"} for c, e, p in rows
    ]}


# --- CVE extraction -------------------------------------------------------

def test_extract_cves_from_a_kev_item():
    item = {"source": "kev", "raw": {"cveID": "CVE-2026-56155", "vendorProject": "Microsoft"}}
    assert epss.extract_cves(item) == ["CVE-2026-56155"]


def test_extract_cves_from_free_text():
    item = {"source": "mta", "raw": {"title": "Exploit of CVE-2021-44228 seen",
                                     "summary": "also CVE-2023-1234."}}
    assert epss.extract_cves(item) == ["CVE-2021-44228", "CVE-2023-1234"]


def test_extract_cves_dedupes_and_uppercases():
    item = {"source": "mta", "raw": {"a": "cve-2021-44228", "b": "CVE-2021-44228"}}
    assert epss.extract_cves(item) == ["CVE-2021-44228"]


def test_extract_cves_none_for_ioc_only_items():
    item = {"source": "threatfox", "raw": {"family": "Lumma", "iocs": [{"ioc": "1.2.3.4"}]}}
    assert epss.extract_cves(item) == []


# --- scores ---------------------------------------------------------------

def test_scores_parses_floats():
    session = FakeSession(_payload(("CVE-2021-44228", "0.999990000", "1.000000000")))
    result = epss.scores(["CVE-2021-44228"], session=session)
    assert result["CVE-2021-44228"]["epss"] == pytest.approx(0.99999)
    assert result["CVE-2021-44228"]["percentile"] == pytest.approx(1.0)


def test_scores_sends_one_batched_request():
    session = FakeSession(_payload(("CVE-2021-0001", "0.1", "0.5"), ("CVE-2021-0002", "0.2", "0.6")))
    epss.scores(["CVE-2021-0001", "CVE-2021-0002"], session=session)
    assert len(session.calls) == 1
    assert session.calls[0][1]["cve"] == "CVE-2021-0001,CVE-2021-0002"


def test_scores_chunks_beyond_the_api_limit():
    cves = [f"CVE-2026-{n:04d}" for n in range(150)]
    session = FakeSession(_payload())
    epss.scores(cves, session=session)
    assert len(session.calls) == 2  # API caps at 100 per request


def test_unscored_cve_is_simply_absent():
    """A CVE too new for a model run has no score. That is not an error, and must
    not be reported as a zero — 'no score' and 'no exploitation risk' differ."""
    session = FakeSession(_payload())
    assert epss.scores(["CVE-2026-99999"], session=session) == {}


def test_empty_input_makes_no_request():
    session = FakeSession(_payload())
    assert epss.scores([], session=session) == {}
    assert session.calls == []


def test_http_error_raises_typed_error():
    session = FakeSession(status_code=500)
    with pytest.raises(epss.EpssError, match="500"):
        epss.scores(["CVE-2021-0001"], session=session)


def test_unreadable_200_raises_typed_error():
    session = FakeSession(payload={"unexpected": True})
    with pytest.raises(epss.EpssError):
        epss.scores(["CVE-2021-0001"], session=session)


# --- prompt block ---------------------------------------------------------

def test_block_for_item_formats_probability_as_a_percentage():
    session = FakeSession(_payload(("CVE-2021-44228", "0.999990000", "1.000000000")))
    item = {"source": "kev", "raw": {"cveID": "CVE-2021-44228"}}
    block, results = epss.block_for_item(item, session=session)
    assert "CVE-2021-44228" in block
    assert "99.9" in block  # readable probability, not a bare float
    assert "percentile" in block.lower()
    assert results[0]["service"] == "epss"
    assert results[0]["epss"] == pytest.approx(0.99999)


@pytest.mark.parametrize("value,expected", [
    (0.99999, "99.9"),   # must not round up to 100.0 — that claims certainty
    (1.0, "100.0"),      # only a true 1.0 may read as 100.0
    (0.23857, "23.8"),
    (0.0, "0.0"),
])
def test_percentages_are_floored_never_rounded_up(value, expected):
    assert epss._pct(value) == expected


def test_a_near_certain_score_never_reads_as_certain():
    session = FakeSession(_payload(("CVE-2021-44228", "0.999990000", "1.000000000")))
    item = {"source": "kev", "raw": {"cveID": "CVE-2021-44228"}}
    block, _ = epss.block_for_item(item, session=session)
    assert "100.0% probability" not in block


def test_block_for_item_says_so_when_a_cve_has_no_score():
    session = FakeSession(_payload())
    item = {"source": "kev", "raw": {"cveID": "CVE-2026-9999"}}
    block, results = epss.block_for_item(item, session=session)
    assert "no EPSS score" in block
    assert results[0]["found"] is False


def test_block_for_item_none_when_no_cves():
    item = {"source": "threatfox", "raw": {"family": "Lumma"}}
    assert epss.block_for_item(item, session=FakeSession(_payload())) == (None, [])


# --- caching --------------------------------------------------------------

def test_cache_hit_avoids_a_second_request(tmp_path):
    session = FakeSession(_payload(("CVE-2021-0001", "0.5", "0.9")))
    item = {"source": "kev", "raw": {"cveID": "CVE-2021-0001"}}
    with ReputationCache(tmp_path / "c.db") as cache:
        epss.block_for_item(item, session=session, cache=cache)
        epss.block_for_item(item, session=session, cache=cache)
    assert len(session.calls) == 1


def test_only_uncached_cves_are_requested(tmp_path):
    session = FakeSession(_payload(("CVE-2021-0002", "0.2", "0.6")))
    item = {"source": "mta", "raw": {"t": "CVE-2021-0001 and CVE-2021-0002"}}
    with ReputationCache(tmp_path / "c.db") as cache:
        cache.put("epss", "CVE-2021-0001", {"epss": 0.1, "percentile": 0.5, "date": "2026-07-15"})
        block, _ = epss.block_for_item(item, session=session, cache=cache)
    assert session.calls[0][1]["cve"] == "CVE-2021-0002"
    assert "CVE-2021-0001" in block and "CVE-2021-0002" in block
