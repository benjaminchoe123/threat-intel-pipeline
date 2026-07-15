from datetime import date

from pipeline.sources.mta_rss import parse_mta

RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>Malware-Traffic-Analysis.net - Blog Entries</title>
<item>
  <title>2026-07-14 - Koi Loader infection with follow-up malware</title>
  <link>https://www.malware-traffic-analysis.net/2026/07/14/index.html</link>
  <pubDate>Mon, 14 Jul 2026 20:00:00 GMT</pubDate>
  <description>Koi Loader traffic and IOCs.</description>
</item>
<item>
  <title>2026-01-02 - Old post</title>
  <link>https://www.malware-traffic-analysis.net/2026/01/02/index.html</link>
  <pubDate>Fri, 02 Jan 2026 20:00:00 GMT</pubDate>
  <description>Old.</description>
</item>
</channel></rss>"""


def test_parse_filters_by_lookback_and_shapes_item():
    items = parse_mta(RSS, lookback_days=7, today=date(2026, 7, 15))
    assert len(items) == 1
    item = items[0]
    assert item["source"] == "mta"
    assert item["external_id"] == "https://www.malware-traffic-analysis.net/2026/07/14/index.html"
    assert "Koi Loader" in item["title"]
    assert item["raw"]["published"] == "2026-07-14"
    assert len(item["content_hash"]) == 64


def test_no_lookback_includes_all():
    assert len(parse_mta(RSS, lookback_days=None, today=date(2026, 7, 15))) == 2


# The live feed is malformed XML; feedparser recovers but emits phantom entries
# with no title/link between real ones. Those must never reach enrichment.
RSS_WITH_PHANTOM = RSS.replace(
    "<item>\n  <title>2026-01-02",
    "<item></item>\n<item>\n  <title>2026-01-02",
)


def test_entries_without_link_are_dropped():
    items = parse_mta(RSS_WITH_PHANTOM, lookback_days=None, today=date(2026, 7, 15))
    assert len(items) == 2
    assert all(i["external_id"] for i in items)


def test_undated_entry_with_link_is_kept_despite_lookback():
    rss = RSS.replace(
        "  <pubDate>Mon, 14 Jul 2026 20:00:00 GMT</pubDate>\n", ""
    )
    items = parse_mta(rss, lookback_days=7, today=date(2026, 7, 15))
    assert any("2026/07/14" in i["external_id"] for i in items)
