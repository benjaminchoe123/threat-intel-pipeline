from datetime import date

from pipeline.sources.threatfox import aggregate_threatfox
from pipeline.sources.urlhaus import aggregate_urlhaus

THREATFOX_DATA = {
    "query_status": "ok",
    "data": [
        {"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
         "malware_printable": "Lumma Stealer", "confidence_level": 75,
         "first_seen": "2026-07-15 04:00:01 UTC", "reference": "https://x.test/1"},
        {"ioc": "5.6.7.8:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
         "malware_printable": "Lumma Stealer", "confidence_level": 90,
         "first_seen": "2026-07-15 05:00:01 UTC", "reference": None},
        {"ioc": "evil.test", "ioc_type": "domain", "threat_type": "payload_delivery",
         "malware_printable": "AgentTesla", "confidence_level": 50,
         "first_seen": "2026-07-15 06:00:01 UTC", "reference": None},
    ],
}


def test_threatfox_groups_by_family():
    items = aggregate_threatfox(THREATFOX_DATA, today=date(2026, 7, 15))
    ids = sorted(i["external_id"] for i in items)
    assert ids == ["AgentTesla:2026-07-15", "Lumma Stealer:2026-07-15"]
    lumma = next(i for i in items if "Lumma" in i["external_id"])
    assert lumma["source"] == "threatfox"
    assert lumma["raw"]["ioc_count"] == 2
    assert len(lumma["raw"]["iocs"]) == 2
    assert lumma["raw"]["family"] == "Lumma Stealer"


def test_threatfox_caps_iocs_in_raw():
    data = {"query_status": "ok", "data": [
        {"ioc": f"10.0.0.{n}:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
         "malware_printable": "BigFamily", "confidence_level": 50,
         "first_seen": "2026-07-15 04:00:01 UTC", "reference": None}
        for n in range(200)
    ]}
    item = aggregate_threatfox(data, today=date(2026, 7, 15))[0]
    assert item["raw"]["ioc_count"] == 200
    assert len(item["raw"]["iocs"]) == 50  # capped so prompts stay bounded


URLHAUS_DATA = {
    "query_status": "ok",
    "urls": [
        {"url": "http://bad.test/a.exe", "url_status": "online", "threat": "malware_download",
         "date_added": "2026-07-15 04:00:01 UTC", "tags": ["Mozi", "elf"]},
        {"url": "http://bad2.test/b.exe", "url_status": "online", "threat": "malware_download",
         "date_added": "2026-07-15 05:00:01 UTC", "tags": ["Mozi"]},
        {"url": "http://bad3.test/c.doc", "url_status": "online", "threat": "malware_download",
         "date_added": "2026-07-15 06:00:01 UTC", "tags": None},
    ],
}


def test_urlhaus_groups_by_first_tag_and_defaults_unclassified():
    items = aggregate_urlhaus(URLHAUS_DATA, today=date(2026, 7, 15))
    ids = sorted(i["external_id"] for i in items)
    assert ids == ["Mozi:2026-07-15", "unclassified:2026-07-15"]
    mozi = next(i for i in items if i["external_id"].startswith("Mozi"))
    assert mozi["source"] == "urlhaus"
    assert mozi["raw"]["ioc_count"] == 2
