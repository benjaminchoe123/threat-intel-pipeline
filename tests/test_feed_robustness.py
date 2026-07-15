"""One malformed entry must not cost the whole feed.

Source fetches are isolated from each other now, but inside a parser a single bad
entry still took everything with it: kev.py read vuln["dateAdded"] and
vuln["cveID"] unguarded and called date.fromisoformat on whatever it found, so
one entry CISA published with a typo dropped every KEV item that day.
"""

from datetime import date

from pipeline.sources import kev, mta_rss

GOOD = {"cveID": "CVE-2026-1111", "dateAdded": "2026-07-14",
        "vulnerabilityName": "Good Entry", "shortDescription": "Real."}


def _catalog(*vulns):
    return {"vulnerabilities": list(vulns)}


# --- KEV per-entry isolation ----------------------------------------------

def test_entry_missing_cveid_is_skipped_not_fatal():
    items = kev.parse_kev(_catalog({"dateAdded": "2026-07-14"}, GOOD), 7,
                          today=date(2026, 7, 15))
    assert [i["external_id"] for i in items] == ["CVE-2026-1111"]


def test_entry_missing_dateadded_is_skipped_not_fatal():
    items = kev.parse_kev(_catalog({"cveID": "CVE-2026-9999"}, GOOD), 7,
                          today=date(2026, 7, 15))
    assert [i["external_id"] for i in items] == ["CVE-2026-1111"]


def test_entry_with_unparseable_date_is_skipped_not_fatal():
    bad = {"cveID": "CVE-2026-8888", "dateAdded": "14/07/2026"}  # not ISO
    items = kev.parse_kev(_catalog(bad, GOOD), 7, today=date(2026, 7, 15))
    assert [i["external_id"] for i in items] == ["CVE-2026-1111"]


def test_non_dict_entry_is_skipped_not_fatal():
    items = kev.parse_kev(_catalog("garbage", None, GOOD), 7, today=date(2026, 7, 15))
    assert [i["external_id"] for i in items] == ["CVE-2026-1111"]


def test_a_wholly_broken_catalog_yields_nothing_rather_than_raising():
    assert kev.parse_kev(_catalog({}, {"x": 1}), 7, today=date(2026, 7, 15)) == []


def test_good_entries_still_parse_normally():
    items = kev.parse_kev(_catalog(GOOD), 7, today=date(2026, 7, 15))
    assert items[0]["title"] == "Good Entry"
    assert items[0]["source"] == "kev"
    assert items[0]["raw"] == GOOD


def test_lookback_still_filters():
    old = {"cveID": "CVE-2020-1", "dateAdded": "2020-01-01"}
    items = kev.parse_kev(_catalog(old, GOOD), 7, today=date(2026, 7, 15))
    assert [i["external_id"] for i in items] == ["CVE-2026-1111"]


def test_no_lookback_keeps_everything_dated():
    old = {"cveID": "CVE-2020-1", "dateAdded": "2020-01-01"}
    items = kev.parse_kev(_catalog(old, GOOD), None)
    assert len(items) == 2


# --- MTA: recover a missing date rather than let it bypass the lookback ---
#
# A missing pubDate used to skip the lookback entirely, so an undated entry of
# any age passed. Dropping undated entries is not the fix either: this feed goes
# malformed, and that is exactly when dates go missing — so dropping them would
# lose real writeups in the case the pipeline exists to survive. MTA posts live
# at /YYYY/MM/DD/ and title themselves "YYYY-MM-DD - ...", so the date is
# recoverable and neither trade-off is necessary.

def _rss(*items):
    return ('<?xml version="1.0"?><rss version="2.0"><channel>'
            + "".join(items) + "</channel></rss>")


UNDATED_RECENT = ('<item><title>2026-07-14 - Recent post</title>'
                  '<link>https://www.malware-traffic-analysis.net/2026/07/14/index.html</link>'
                  '</item>')
UNDATED_OLD = ('<item><title>2020-01-02 - Ancient post</title>'
               '<link>https://www.malware-traffic-analysis.net/2020/01/02/index.html</link>'
               '</item>')


def test_undated_recent_entry_is_recovered_from_its_url_and_kept():
    items = mta_rss.parse_mta(_rss(UNDATED_RECENT), 7, today=date(2026, 7, 15))
    assert len(items) == 1
    assert items[0]["raw"]["published"] == "2026-07-14"


def test_undated_old_entry_is_recovered_and_filtered():
    """The actual hole: with no pubDate this passed a 7-day lookback at any age."""
    items = mta_rss.parse_mta(_rss(UNDATED_OLD), 7, today=date(2026, 7, 15))
    assert items == []


def test_pubdate_wins_when_present():
    entry = ('<item><title>2020-01-02 - Misleading title date</title>'
             '<link>https://www.malware-traffic-analysis.net/2026/07/14/index.html</link>'
             '<pubDate>Mon, 13 Jul 2026 20:00:00 GMT</pubDate></item>')
    items = mta_rss.parse_mta(_rss(entry), 7, today=date(2026, 7, 15))
    assert items[0]["raw"]["published"] == "2026-07-13"


def test_title_date_is_used_when_the_url_has_none():
    entry = ('<item><title>2026-07-14 - Post</title><link>https://mta.test/post</link></item>')
    items = mta_rss.parse_mta(_rss(entry), 7, today=date(2026, 7, 15))
    assert items[0]["raw"]["published"] == "2026-07-14"


def test_impossible_url_date_does_not_crash():
    entry = ('<item><title>Post</title>'
             '<link>https://www.malware-traffic-analysis.net/2026/13/45/index.html</link></item>')
    items = mta_rss.parse_mta(_rss(entry), None)
    assert items[0]["raw"]["published"] is None


def test_wholly_undateable_entry_is_kept_not_dropped():
    """Losing a real writeup is worse than enriching one stale post, and the run
    is capped anyway."""
    entry = '<item><title>No date anywhere</title><link>https://mta.test/x</link></item>'
    items = mta_rss.parse_mta(_rss(entry), 7, today=date(2026, 7, 15))
    assert len(items) == 1


def test_entries_without_a_link_are_still_dropped():
    assert mta_rss.parse_mta(_rss("<item><title>No link</title></item>"), None) == []
