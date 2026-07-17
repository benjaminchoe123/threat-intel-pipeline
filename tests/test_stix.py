"""STIX 2.1 bundle export: turn the vault's structured claims (frontmatter +
the Observed IOCs table) into an industry-interchange artifact, without
inventing anything the note doesn't already assert."""

import json

from pipeline import stix

NOTE_TEMPLATE = """---
title: {title}
type: threat
source: {source}
date: 2026-07-15
severity: high
confidence: medium
flagged: false
cve: [{cve}]
family: [{family}]
attack_techniques: [{techniques}]
actors: []
tags: [threat]
---

# {title}

## Observed IOCs
{ioc_table}
"""

IOC_TABLE = """| type | value | context |
|---|---|---|
| ip:port | 96.9.231.213:8080 | botnet_cc, confidence 100 |
| domain | evil.example.com | botnet_cc |
| url | http://evil.example.com/payload | payload delivery |
| sha256_hash | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | dropped sample |
| carrier_pigeon | n/a | an ioc type nothing maps to |"""


def _write(vault, name, title="Test Threat", source="threatfox", cve="", family="",
          techniques="", ioc_table="None in source."):
    (vault / "threats").mkdir(parents=True, exist_ok=True)
    (vault / "threats" / name).write_text(
        NOTE_TEMPLATE.format(title=title, source=source, cve=cve, family=family,
                             techniques=techniques, ioc_table=ioc_table),
        encoding="utf-8",
    )


# --- IOC table parsing -----------------------------------------------------

def test_parses_a_well_formed_ioc_table():
    rows = stix.parse_ioc_table(IOC_TABLE)
    assert len(rows) == 5
    assert rows[0] == {"type": "ip:port", "value": "96.9.231.213:8080",
                       "context": "botnet_cc, confidence 100"}


def test_none_in_source_yields_no_rows():
    assert stix.parse_ioc_table("None in source.") == []


def test_missing_ioc_section_yields_no_rows():
    assert stix.parse_ioc_table("no table here at all") == []


# --- IOC -> STIX pattern -----------------------------------------------------

def test_ip_port_becomes_an_ipv4_pattern_with_port_stripped():
    assert stix.ioc_pattern("ip:port", "96.9.231.213:8080") == \
        "[ipv4-addr:value = '96.9.231.213']"


def test_domain_becomes_a_domain_name_pattern():
    assert stix.ioc_pattern("domain", "evil.example.com") == \
        "[domain-name:value = 'evil.example.com']"


def test_url_becomes_a_url_pattern():
    assert stix.ioc_pattern("url", "http://evil.example.com/payload") == \
        "[url:value = 'http://evil.example.com/payload']"


def test_sha256_becomes_a_file_hash_pattern():
    v = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert stix.ioc_pattern("sha256_hash", v) == f"[file:hashes.'SHA-256' = '{v}']"


def test_unmapped_ioc_type_returns_none_rather_than_guessing():
    assert stix.ioc_pattern("carrier_pigeon", "n/a") is None


def test_bare_ipv6_is_not_misread_as_ipv4():
    # _strip_port only strips a trailing :port when what's left of the last
    # colon looks like IPv4 — a bare IPv6 address must not be mangled.
    assert stix.ioc_pattern("ip", "2001:db8::1") is None


# --- per-note bundle building ------------------------------------------------

def test_cve_only_note_yields_a_vulnerability_object(tmp_path):
    _write(tmp_path, "kev.md", title="Some RCE", source="kev", cve="CVE-2026-1111")
    bundle = stix.build_bundle(*stix._read_note(tmp_path / "threats" / "kev.md"))
    types = [o["type"] for o in bundle["objects"]]
    assert types == ["vulnerability"]
    assert bundle["objects"][0]["external_references"][0]["external_id"] == "CVE-2026-1111"


def test_note_with_nothing_stix_worthy_is_skipped(tmp_path):
    _write(tmp_path, "empty.md", title="Nothing here")
    result = stix.build_bundle(*stix._read_note(tmp_path / "threats" / "empty.md"))
    assert result is None


def test_full_note_yields_malware_technique_indicator_and_relationships(tmp_path):
    _write(tmp_path, "cluster.md", title="AdaptixC2 cluster", source="threatfox",
          family="AdaptixC2", techniques="T1071.001", ioc_table=IOC_TABLE)
    bundle = stix.build_bundle(*stix._read_note(tmp_path / "threats" / "cluster.md"))
    types = [o["type"] for o in bundle["objects"]]
    assert "malware" in types
    assert "attack-pattern" in types
    # 4 of 5 rows map to a pattern; the carrier_pigeon row is dropped, not guessed.
    assert types.count("indicator") == 4
    assert "relationship" in types


def test_malware_object_is_flagged_as_a_family(tmp_path):
    _write(tmp_path, "cluster.md", family="AdaptixC2")
    bundle = stix.build_bundle(*stix._read_note(tmp_path / "threats" / "cluster.md"))
    malware = next(o for o in bundle["objects"] if o["type"] == "malware")
    assert malware["is_family"] is True
    assert malware["name"] == "AdaptixC2"


def test_attack_pattern_carries_the_real_technique_name(tmp_path):
    _write(tmp_path, "t.md", family="X", techniques="T1190")
    bundle = stix.build_bundle(*stix._read_note(tmp_path / "threats" / "t.md"))
    ap = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
    assert ap["name"] == "Exploit Public-Facing Application"
    assert ap["external_references"][0]["external_id"] == "T1190"


def test_same_family_gets_the_same_id_across_two_notes(tmp_path):
    _write(tmp_path, "a.md", title="A", family="AdaptixC2")
    _write(tmp_path, "b.md", title="B", family="AdaptixC2")
    bundle_a = stix.build_bundle(*stix._read_note(tmp_path / "threats" / "a.md"))
    bundle_b = stix.build_bundle(*stix._read_note(tmp_path / "threats" / "b.md"))
    id_a = next(o["id"] for o in bundle_a["objects"] if o["type"] == "malware")
    id_b = next(o["id"] for o in bundle_b["objects"] if o["type"] == "malware")
    assert id_a == id_b


def test_malware_exploiting_a_cve_gets_an_exploits_relationship(tmp_path):
    _write(tmp_path, "both.md", cve="CVE-2026-2222", family="AdaptixC2")
    bundle = stix.build_bundle(*stix._read_note(tmp_path / "threats" / "both.md"))
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert any(r["relationship_type"] == "exploits" for r in rels)


# --- vault-wide export --------------------------------------------------------

def test_export_writes_one_bundle_per_nonempty_note(tmp_path):
    _write(tmp_path, "a.md", title="A", cve="CVE-2026-1111")
    _write(tmp_path, "b.md", title="B")  # nothing stix-worthy
    written = stix.export(tmp_path)
    assert len(written) == 1
    assert written[0].parent == tmp_path / "docs" / "stix"


def test_export_on_empty_vault_writes_nothing(tmp_path):
    assert stix.export(tmp_path) == []


def test_export_output_is_valid_json(tmp_path):
    _write(tmp_path, "a.md", cve="CVE-2026-1111")
    [path] = stix.export(tmp_path)
    bundle = json.loads(path.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"
    assert bundle["objects"][0]["spec_version"] == "2.1"


def test_export_isolates_a_note_that_blows_up_building_its_bundle(tmp_path):
    # A malformed date can't be parsed into an Indicator's valid_from — this
    # note must not take the rest of the export down with it.
    (tmp_path / "threats").mkdir(parents=True)
    (tmp_path / "threats" / "broken.md").write_text(
        NOTE_TEMPLATE.format(title="Broken", source="threatfox", cve="", family="X",
                             techniques="", ioc_table=IOC_TABLE)
        .replace("date: 2026-07-15", "date: not-a-date"),
        encoding="utf-8",
    )
    _write(tmp_path, "ok.md", title="OK", cve="CVE-2026-1111")
    written = stix.export(tmp_path)
    assert len(written) == 1
    assert written[0].stem == "ok"
