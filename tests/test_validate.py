from pipeline.enrich import validate_note

VALID_NOTE = """---
title: Test Threat
type: threat
source: kev
source_url: https://example.com/kev
date: 2026-07-15
severity: high
confidence: high
flagged: false
cve: [CVE-2026-1234]
family: []
attack_techniques: [T1190, T1059.001]
actors: []
tags: [threat, kev, severity/high]
---

# Test Threat

## What it is
A test threat.

## Severity assessment
**high** — because reasons.
"""


def test_valid_note_passes():
    ok, errors, meta = validate_note(VALID_NOTE)
    assert ok, errors
    assert meta["severity"] == "high"
    assert meta["attack_techniques"] == ["T1190", "T1059.001"]


def test_missing_required_field_fails():
    bad = VALID_NOTE.replace("severity: high\n", "")
    ok, errors, _ = validate_note(bad)
    assert not ok
    assert any("severity" in e for e in errors)


def test_invalid_severity_enum_fails():
    bad = VALID_NOTE.replace("severity: high", "severity: catastrophic")
    ok, errors, _ = validate_note(bad)
    assert not ok
    assert any("severity" in e for e in errors)


def test_invalid_attack_id_fails():
    bad = VALID_NOTE.replace("T1190", "TA0001")
    ok, errors, _ = validate_note(bad)
    assert not ok
    assert any("attack" in e.lower() for e in errors)


def test_unparseable_frontmatter_fails():
    ok, errors, _ = validate_note("no frontmatter here\njust text\n")
    assert not ok


def test_wrapping_code_fence_is_stripped():
    fenced = "```markdown\n" + VALID_NOTE + "```\n"
    ok, errors, meta = validate_note(fenced)
    assert ok, errors
    assert meta["title"] == "Test Threat"


def test_flagged_low_confidence_note_is_valid():
    note = VALID_NOTE.replace("confidence: high", "confidence: low").replace(
        "flagged: false", "flagged: true"
    )
    ok, errors, meta = validate_note(note)
    assert ok, errors
    assert meta["flagged"] is True
