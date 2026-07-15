from pipeline import reputation

from test_vt import THREATFOX_ITEM


def test_combines_vt_and_abuseipdb_sections():
    block, results = reputation.reputation_for_item(
        THREATFOX_ITEM,
        vt_fn=lambda item: ("VT-LINES", [{"service": "virustotal", "ioc": "1.2.3.4"}]),
        abuse_fn=lambda item: ("ABUSE-LINES", [{"service": "abuseipdb", "ioc": "1.2.3.4"}]),
    )
    assert "VirusTotal:\nVT-LINES" in block
    assert "AbuseIPDB:\nABUSE-LINES" in block
    assert [r["service"] for r in results] == ["virustotal", "abuseipdb"]


def test_single_service_block_has_no_empty_sections():
    block, results = reputation.reputation_for_item(
        THREATFOX_ITEM,
        vt_fn=lambda item: ("VT-LINES", [{"service": "virustotal"}]),
        abuse_fn=lambda item: (None, []),
    )
    assert "VT-LINES" in block
    assert "AbuseIPDB" not in block
    assert len(results) == 1


def test_returns_none_when_no_service_has_data():
    assert reputation.reputation_for_item(
        THREATFOX_ITEM, vt_fn=lambda item: (None, []), abuse_fn=lambda item: (None, [])
    ) == (None, [])
