import pytest

from pipeline import enrich
from pipeline.verify_report import (
    VERIFICATION_ROUNDS,
    VerificationError,
    check_entities,
    extract_and_verify_claims,
    extract_entities,
    split_advice_section,
    verify,
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


def test_extract_and_verify_claims_raises_on_non_boolean_supported():
    def fake_runner(prompt):
        return ('[{"claim": "x", "supported": "false", "reason": "not a real bool"}]', {})
    with pytest.raises(VerificationError):
        extract_and_verify_claims("draft text", WEEK_NOTES, runner=fake_runner)


def test_verify_passes_when_entities_and_claims_are_supported():
    def fake_runner(prompt):
        return ('[{"claim": "AdaptixC2 uses T1059", "supported": true, "reason": "ok"}]', {})
    result = verify("CVE-2026-1111 and T1059 seen this week.", WEEK_NOTES, runner=fake_runner)
    assert result.passed is True
    assert result.entity_mismatches == []
    assert result.error is None


def test_verify_fails_on_entity_mismatch():
    def fake_runner(prompt):
        return ("[]", {})
    result = verify("CVE-2099-0000 is new.", WEEK_NOTES, runner=fake_runner)
    assert result.passed is False
    assert "CVE-2099-0000" in result.report()


def test_verify_fails_on_unsupported_claim():
    def fake_runner(prompt):
        return (
            '[{"claim": "Ransomware doubled", "supported": false, "reason": "not in notes"}]',
            {},
        )
    result = verify("Ransomware activity doubled this week.", WEEK_NOTES, runner=fake_runner)
    assert result.passed is False
    assert "Ransomware doubled" in result.report()


def test_verify_fails_when_claim_call_is_unusable():
    def broken_runner(prompt):
        return ("not json", {})
    result = verify("CVE-2026-1111 seen.", WEEK_NOTES, runner=broken_runner)
    assert result.passed is False
    assert result.error is not None


def test_verify_fails_when_runner_raises_enrichment_error():
    """run_claude (the real production runner) raises enrich.EnrichmentError on a
    subprocess timeout, non-zero exit, or an is_error response payload -- not just
    VerificationError. verify() must catch that too, or an unattended auto-publish
    run crashes with zero audit trail instead of recording a failed check."""
    def exploding_runner(prompt):
        raise enrich.EnrichmentError("claude -p timed out after 300s")
    result = verify("CVE-2026-1111 seen.", WEEK_NOTES, runner=exploding_runner)
    assert result.passed is False
    assert result.error is not None


def test_verify_report_text_says_passed_when_clean():
    def fake_runner(prompt):
        return ("[]", {})
    result = verify("CVE-2026-1111 seen.", WEEK_NOTES, runner=fake_runner)
    assert result.passed is True
    assert "passed" in result.report().lower()


# ---------------------------------------------------------------------------
# Section-aware verification.
#
# The gate used to ask one question of the whole draft: "is this claim directly
# supported by the source notes?" That is the right question for the factual
# sections and the wrong question for "What a small organization should actually
# do", whose entire purpose is analyst judgement that goes beyond any single
# note. As written, the advice section could only pass by saying nothing new --
# which is why 2026-W35 shipped with its advice stripped out by hand.
#
# The fix is not a lower bar for advice. It is a different, still-strict
# question: advice fails if it asserts a fact the notes do not carry, if it
# contradicts a note, or if it acts on a product the week's notes never mention.
# ---------------------------------------------------------------------------

DRAFT_WITH_ADVICE = """# Weekly Threat Report — 2026-W35

## TL;DR

- CVE-2026-1111 is exploited in the wild.

## Top threats this week

**1. AdaptixC2 (high)**

Uses T1059 for execution.

## What changed vs. prior weeks

Activity baseline is still being established.

## What a small organization should actually do

**This week, in this order:**

1. Patch CVE-2026-1111 today.

## Sources

- CISA KEV
"""


def test_split_advice_section_separates_judgement_from_fact():
    factual, advice = split_advice_section(DRAFT_WITH_ADVICE)
    assert "Patch CVE-2026-1111 today" in advice
    assert "Patch CVE-2026-1111 today" not in factual
    # everything else, including Sources, stays on the factual side
    assert "## TL;DR" in factual
    assert "## Top threats this week" in factual
    assert "## Sources" in factual
    assert "CISA KEV" in factual


def test_split_advice_section_puts_whole_draft_in_factual_when_no_advice_heading():
    draft = "# Report\n\n## TL;DR\n\n- CVE-2026-1111 seen.\n"
    factual, advice = split_advice_section(draft)
    assert factual == draft
    assert advice == ""


def test_advice_section_is_checked_with_a_different_question_than_facts():
    """The two sections must not be judged by the same prompt -- that identity is
    the whole bug. The advice prompt asks about contradiction and invented fact;
    the factual prompt asks about direct support."""
    prompts = []

    def recording_runner(prompt):
        prompts.append(prompt)
        return ("[]", {})

    verify(DRAFT_WITH_ADVICE, WEEK_NOTES, runner=recording_runner)

    factual_prompts = [p for p in prompts if "## Top threats this week" in p]
    advice_prompts = [p for p in prompts if "Patch CVE-2026-1111 today" in p
                      and "## Top threats this week" not in p]
    assert factual_prompts, "factual sections were never verified"
    assert advice_prompts, "advice section was never verified"
    assert "directly supported" in factual_prompts[0]
    assert "directly supported" not in advice_prompts[0]
    assert "contradict" in advice_prompts[0].lower()


def test_no_advice_call_is_made_when_the_draft_has_no_advice_section():
    """Don't pay for a verification call on an empty string."""
    calls = []

    def counting_runner(prompt):
        calls.append(prompt)
        return ("[]", {})

    verify("# Report\n\n## TL;DR\n\n- CVE-2026-1111 seen.\n", WEEK_NOTES,
           runner=counting_runner)
    assert len(calls) == VERIFICATION_ROUNDS


def test_unsound_advice_fails_verification_and_is_named_as_advice():
    def fake_runner(prompt):
        if "Patch CVE-2026-1111 today" in prompt and "## Top threats" not in prompt:
            return ('[{"claim": "Patch CVE-2026-1111 today", "supported": false, '
                    '"reason": "the notes give no such deadline"}]', {})
        return ("[]", {})

    result = verify(DRAFT_WITH_ADVICE, WEEK_NOTES, runner=fake_runner)
    assert result.passed is False
    assert "UNSOUND RECOMMENDATION" in result.report()
    assert "Patch CVE-2026-1111 today" in result.report()


def test_sound_advice_passes_even_though_it_is_not_stated_in_the_notes():
    """The regression that broke 2026-W35: advice that goes beyond the notes is
    the point of the section, not a defect."""
    def fake_runner(prompt):
        return ("[]", {})

    result = verify(DRAFT_WITH_ADVICE, WEEK_NOTES, runner=fake_runner)
    assert result.passed is True


# ---------------------------------------------------------------------------
# Convergence. A single verification pass was observed to flag different subsets
# on different runs -- a claim passed rounds 1-8 and failed round 9. One pass
# therefore means "passed this roll of the dice", not "passed". Running N times
# and taking the union of failures is strictly stricter than one pass and makes
# a green result mean something stable.
# ---------------------------------------------------------------------------

def test_verification_runs_the_configured_number_of_rounds():
    calls = []

    def counting_runner(prompt):
        calls.append(prompt)
        return ("[]", {})

    verify("# Report\n\n## TL;DR\n\n- CVE-2026-1111 seen.\n", WEEK_NOTES,
           runner=counting_runner)
    assert len(calls) == VERIFICATION_ROUNDS
    assert VERIFICATION_ROUNDS > 1


def test_a_claim_flagged_in_only_one_round_fails_the_whole_verification():
    """This is the entire point of the union: the flaky round is the one that
    caught something, not the one that was wrong."""
    rounds = {"n": 0}

    def flaky_runner(prompt):
        rounds["n"] += 1
        if rounds["n"] == VERIFICATION_ROUNDS:  # only the last round objects
            return ('[{"claim": "Ransomware doubled", "supported": false, '
                    '"reason": "no such count in the notes"}]', {})
        return ('[{"claim": "Ransomware doubled", "supported": true, '
                '"reason": "looks fine"}]', {})

    result = verify("# R\n\n## TL;DR\n\n- Ransomware doubled.\n", WEEK_NOTES,
                    runner=flaky_runner)
    assert result.passed is False
    assert "Ransomware doubled" in result.report()


def test_a_claim_supported_in_every_round_passes():
    def steady_runner(prompt):
        return ('[{"claim": "CVE-2026-1111 is exploited", "supported": true, '
                '"reason": "stated in the note"}]', {})

    result = verify("# R\n\n## TL;DR\n\n- CVE-2026-1111 is exploited.\n", WEEK_NOTES,
                    runner=steady_runner)
    assert result.passed is True


def test_union_keeps_the_reason_from_the_round_that_objected():
    rounds = {"n": 0}

    def flaky_runner(prompt):
        rounds["n"] += 1
        if rounds["n"] == 1:
            return ('[{"claim": "X", "supported": false, '
                    '"reason": "the specific objection"}]', {})
        return ('[{"claim": "X", "supported": true, "reason": "fine"}]', {})

    result = verify("# R\n\n## TL;DR\n\n- X.\n", WEEK_NOTES, runner=flaky_runner)
    assert result.passed is False
    assert "the specific objection" in result.report()


def test_one_broken_round_fails_the_whole_verification():
    """A checker that breaks must look like a failed check, not a clean one --
    and that holds per round, not just for the first round."""
    rounds = {"n": 0}

    def half_broken_runner(prompt):
        rounds["n"] += 1
        if rounds["n"] == VERIFICATION_ROUNDS:
            return ("not json", {})
        return ("[]", {})

    result = verify("# R\n\n## TL;DR\n\n- CVE-2026-1111 seen.\n", WEEK_NOTES,
                    runner=half_broken_runner)
    assert result.passed is False
    assert result.error is not None
