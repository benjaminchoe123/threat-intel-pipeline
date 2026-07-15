"""ATT&CK IDs must exist, not merely look like IDs.

ATTACK_ID_RE checks the shape T#### / T####.###, so T9999 and T1234.567 both
passed validation — a hallucinated technique reached the vault, created a stub
page, and joined the graph as though it were real.
"""

import json

import pytest

from pipeline import attack, enrich

CATALOG = {"T1190": "Exploit Public-Facing Application", "T1059": "Command and Scripting Interpreter",
           "T1059.001": "PowerShell"}


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    path = tmp_path / "attack_techniques.json"
    path.write_text(json.dumps(CATALOG), encoding="utf-8")
    monkeypatch.setattr(attack, "CATALOG_FILE", path)
    attack.load.cache_clear()
    yield path
    attack.load.cache_clear()


# --- catalog loading ------------------------------------------------------

def test_load_reads_the_catalog(catalog):
    assert attack.load()["T1190"] == "Exploit Public-Facing Application"


def test_load_is_cached(catalog):
    attack.load()
    catalog.unlink()  # a second read would now fail
    assert attack.load()["T1190"]


def test_missing_catalog_degrades_to_empty_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(attack, "CATALOG_FILE", tmp_path / "absent.json")
    attack.load.cache_clear()
    assert attack.load() == {}
    attack.load.cache_clear()


def test_corrupt_catalog_degrades_to_empty(tmp_path, monkeypatch):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(attack, "CATALOG_FILE", bad)
    attack.load.cache_clear()
    assert attack.load() == {}
    attack.load.cache_clear()


# --- validation -----------------------------------------------------------

def test_real_techniques_are_valid(catalog):
    assert attack.is_known("T1190")
    assert attack.is_known("T1059.001")


def test_invented_techniques_are_not(catalog):
    assert not attack.is_known("T9999")
    assert not attack.is_known("T1234.567")


def test_unknown_when_catalog_is_absent_everything_is_permitted(tmp_path, monkeypatch):
    """Offline safety: with no catalog, fall back to the regex rather than
    rejecting every technique and quarantining every note."""
    monkeypatch.setattr(attack, "CATALOG_FILE", tmp_path / "absent.json")
    attack.load.cache_clear()
    assert attack.is_known("T9999") is True
    attack.load.cache_clear()


def test_name_for_returns_the_official_name(catalog):
    assert attack.name_for("T1059.001") == "PowerShell"
    assert attack.name_for("T9999") is None


# --- integration with validate_note ---------------------------------------

NOTE = """---
title: T
type: threat
source: kev
source_url: https://example.com
date: 2026-07-15
severity: high
confidence: high
flagged: false
cve: []
family: []
attack_techniques: [{techniques}]
actors: []
tags: [t]
---

# T
"""


def test_validate_note_rejects_a_hallucinated_technique(catalog):
    ok, errors, _ = enrich.validate_note(NOTE.format(techniques="T9999"))
    assert not ok
    assert any("T9999" in e and "not a known" in e for e in errors)


def test_validate_note_accepts_a_real_technique(catalog):
    ok, errors, _ = enrich.validate_note(NOTE.format(techniques="T1059.001"))
    assert ok, errors


def test_malformed_id_still_reported_as_malformed(catalog):
    ok, errors, _ = enrich.validate_note(NOTE.format(techniques="'not-an-id'"))
    assert not ok
    assert any("expected T####" in e for e in errors)


# --- catalog extraction from the STIX bundle ------------------------------

BUNDLE = {"objects": [
    {"type": "attack-pattern", "name": "Exploit Public-Facing Application",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}]},
    {"type": "attack-pattern", "name": "Deprecated Thing", "x_mitre_deprecated": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1111"}]},
    {"type": "attack-pattern", "name": "Revoked Thing", "revoked": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T2222"}]},
    {"type": "intrusion-set", "name": "Some Group",
     "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}]},
]}


def test_extract_takes_active_techniques_only():
    assert attack.extract_techniques(BUNDLE) == {"T1190": "Exploit Public-Facing Application"}


def test_extract_ignores_non_technique_objects():
    assert "G0001" not in attack.extract_techniques(BUNDLE)
