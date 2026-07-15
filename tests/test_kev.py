from datetime import date

from pipeline.sources.kev import parse_kev

SAMPLE = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.07.15",
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-1111",
            "vendorProject": "ExampleCorp",
            "product": "ExampleServer",
            "vulnerabilityName": "ExampleServer RCE",
            "dateAdded": "2026-07-14",
            "shortDescription": "Remote code execution in ExampleServer.",
            "requiredAction": "Apply updates per vendor instructions.",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://example.com/advisory",
        },
        {
            "cveID": "CVE-2020-9999",
            "vendorProject": "OldCorp",
            "product": "Legacy",
            "vulnerabilityName": "Old bug",
            "dateAdded": "2020-01-01",
            "shortDescription": "Ancient.",
            "requiredAction": "Patch.",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
        },
    ],
}


def test_parse_filters_by_lookback():
    items = parse_kev(SAMPLE, lookback_days=7, today=date(2026, 7, 15))
    assert [i["external_id"] for i in items] == ["CVE-2026-1111"]


def test_parse_includes_everything_with_no_lookback():
    items = parse_kev(SAMPLE, lookback_days=None, today=date(2026, 7, 15))
    assert len(items) == 2


def test_normalized_item_shape():
    item = parse_kev(SAMPLE, lookback_days=7, today=date(2026, 7, 15))[0]
    assert item["source"] == "kev"
    assert item["external_id"] == "CVE-2026-1111"
    assert item["title"] == "ExampleServer RCE"
    assert item["url"].startswith("https://www.cisa.gov")
    assert item["raw"]["cveID"] == "CVE-2026-1111"
    assert len(item["content_hash"]) == 64  # sha256 hex


def test_content_hash_changes_when_entry_changes():
    a = parse_kev(SAMPLE, lookback_days=7, today=date(2026, 7, 15))[0]
    changed = {"vulnerabilities": [dict(SAMPLE["vulnerabilities"][0], notes="edited")]}
    b = parse_kev(changed, lookback_days=7, today=date(2026, 7, 15))[0]
    assert a["content_hash"] != b["content_hash"]
