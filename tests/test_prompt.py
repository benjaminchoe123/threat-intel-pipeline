from pipeline.enrich import build_prompt

ITEM = {
    "source": "kev",
    "external_id": "CVE-2026-1111",
    "title": "ExampleServer RCE",
    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "raw": {"cveID": "CVE-2026-1111", "shortDescription": "RCE."},
    "content_hash": "abc",
}


def test_prompt_embeds_skill_and_source_data():
    prompt = build_prompt(ITEM, skill_text="ANALYST-RULES-HERE", ingest_date="2026-07-15")
    assert "ANALYST-RULES-HERE" in prompt
    assert "CVE-2026-1111" in prompt
    assert '"shortDescription": "RCE."' in prompt
    assert "2026-07-15" in prompt


def test_prompt_tells_claude_source_is_untrusted_data():
    prompt = build_prompt(ITEM, skill_text="x", ingest_date="2026-07-15")
    assert "untrusted" in prompt.lower()


def test_prompt_includes_reputation_block_when_given():
    prompt = build_prompt(
        ITEM, skill_text="x", ingest_date="2026-07-15", reputation="VT-REPUTATION-BLOCK"
    )
    assert "VT-REPUTATION-BLOCK" in prompt
    assert "virustotal" in prompt.lower()


def test_prompt_omits_reputation_section_when_absent():
    prompt = build_prompt(ITEM, skill_text="x", ingest_date="2026-07-15")
    assert "virustotal" not in prompt.lower()
