import pytest

from pipeline.verify_report import (
    VerificationError,
    check_entities,
    extract_and_verify_claims,
    extract_entities,
)

WEEK_NOTES = [
    {"cve": ["CVE-2026-1111"], "attack_techniques": ["T1059"], "family": ["AdaptixC2"],
     "_body": "# AdaptixC2\n\nUses T1059 execution. CVE-2026-1111 exploited in the wild."},
]


def test_extract_entities_finds_cve_and_attack_ids():
    text = "This week features CVE-2026-1111 and technique T1059.001 heavily."
    entities = extract_entities(text)
    assert entities["cve"] == {"CVE-2026-1111"}
    assert entities["attack_techniques"] == {"T1059.001"}


def test_extract_entities_empty_on_no_matches():
    entities = extract_entities("Nothing structured mentioned here.")
    assert entities["cve"] == set()
    assert entities["attack_techniques"] == set()


def test_check_entities_passes_when_all_cited_ids_are_known():
    entities = {"cve": {"CVE-2026-1111"}, "attack_techniques": {"T1059"}}
    assert check_entities(entities, WEEK_NOTES) == []


def test_check_entities_flags_unknown_cve():
    entities = {"cve": {"CVE-2026-9999"}, "attack_techniques": set()}
    mismatches = check_entities(entities, WEEK_NOTES)
    assert len(mismatches) == 1
    assert "CVE-2026-9999" in mismatches[0]


def test_check_entities_flags_unknown_attack_id():
    entities = {"cve": set(), "attack_techniques": {"T9999"}}
    mismatches = check_entities(entities, WEEK_NOTES)
    assert len(mismatches) == 1
    assert "T9999" in mismatches[0]


def test_extract_and_verify_claims_parses_runner_response():
    def fake_runner(prompt):
        assert "AdaptixC2" in prompt  # week's note bodies are in the prompt
        return (
            '[{"claim": "AdaptixC2 uses T1059", "supported": true, "reason": "matches note"}]',
            {},
        )
    results = extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)
    assert results == [
        {"claim": "AdaptixC2 uses T1059", "supported": True, "reason": "matches note"}
    ]


def test_extract_and_verify_claims_strips_code_fence():
    def fake_runner(prompt):
        return ('```json\n[{"claim": "x", "supported": false, "reason": "no source"}]\n```', {})
    results = extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)
    assert results[0]["supported"] is False


def test_extract_and_verify_claims_raises_on_invalid_json():
    def fake_runner(prompt):
        return ("not json", {})
    with pytest.raises(VerificationError):
        extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)


def test_extract_and_verify_claims_raises_on_non_list():
    def fake_runner(prompt):
        return ('{"claim": "x"}', {})
    with pytest.raises(VerificationError):
        extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)


def test_extract_and_verify_claims_raises_on_malformed_entry():
    def fake_runner(prompt):
        return ('[{"claim": "x"}]', {})  # missing "supported"
    with pytest.raises(VerificationError):
        extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)
