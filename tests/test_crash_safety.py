"""Crash-safety fixes for defects confirmed against the live install."""

import json

import pytest

from pipeline import enrich, notes

# --- _strip_code_fence ----------------------------------------------------

@pytest.mark.parametrize("text", ["```", "```markdown", "   ```   "])
def test_bare_fence_does_not_raise(text):
    """text.index("\\n") raised ValueError on a fence with no newline, turning a
    validation failure (-> quarantine) into a run-killing exception."""
    enrich._strip_code_fence(text)  # must not raise


def test_fenced_note_still_unwraps():
    fenced = "```markdown\n---\ntitle: x\n---\n\nbody\n```"
    assert enrich._strip_code_fence(fenced).startswith("---\ntitle: x")


def test_truncated_model_output_quarantines_instead_of_crashing():
    ok, errors, meta = enrich.validate_note("```")
    assert ok is False
    assert errors


# --- run_claude output guards ---------------------------------------------

class FakeCompleted:
    def __init__(self, stdout, returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


def test_non_json_stdout_raises_typed_error(monkeypatch):
    monkeypatch.setattr(enrich.subprocess, "run",
                        lambda *a, **k: FakeCompleted("not json at all"))
    with pytest.raises(enrich.EnrichmentError, match="not valid JSON"):
        enrich.run_claude("prompt")


def test_is_error_true_is_acted_on_not_just_recorded(monkeypatch):
    """is_error was captured into engine_meta and ignored; the error string then
    flowed into validation, failed, and burned the retry before quarantining."""
    payload = '{"is_error": true, "result": "Error: credit balance too low"}'
    monkeypatch.setattr(enrich.subprocess, "run", lambda *a, **k: FakeCompleted(payload))
    with pytest.raises(enrich.EnrichmentError, match="credit balance"):
        enrich.run_claude("prompt")


def test_timeout_raises_typed_error(monkeypatch):
    def boom(*a, **k):
        raise enrich.subprocess.TimeoutExpired(cmd="claude", timeout=300)

    monkeypatch.setattr(enrich.subprocess, "run", boom)
    with pytest.raises(enrich.EnrichmentError, match="timed out"):
        enrich.run_claude("prompt")


# --- slugify --------------------------------------------------------------

def test_empty_title_does_not_produce_a_dotfile():
    """slugify("") produced data/raw/mta/.json — every empty-id item collided on
    one file. Confirmed in the live audit log."""
    assert notes.slugify("") == notes.FALLBACK_SLUG
    assert notes.slugify("   ") == notes.FALLBACK_SLUG
    assert notes.slugify("///") == notes.FALLBACK_SLUG


def test_slug_is_length_capped():
    slug = notes.slugify("word " * 100)
    assert len(slug) <= notes.MAX_SLUG_LEN


def test_a_real_kev_title_is_not_truncated():
    """Found by a live run: an 80-char cap cut this mid-CVE, leaving a filename
    ending in "(CVE-2026-46" — which reads as data corruption."""
    title = "Oracle E-Business Suite Improper Privilege Management Vulnerability (CVE-2026-46817)"
    assert notes.slugify(title).endswith("(CVE-2026-46817)")


def test_truncation_prefers_a_word_boundary():
    slug = notes.slugify("Some-Very-Long-Threat-Title " + "segment " * 40)
    assert len(slug) <= notes.MAX_SLUG_LEN
    assert not slug.endswith("-")
    assert "segmen" not in slug.split("-")[-1] or slug.split("-")[-1] == "segment"


def test_slug_strips_trailing_dots_and_spaces():
    # Windows silently drops these, so "x." and "x" collide on one file.
    assert not notes.slugify("Report v1.").endswith(".")
    assert not notes.slugify("trailing   ").endswith(" ")


@pytest.mark.parametrize("name", ["CON", "PRN", "NUL", "AUX", "COM1", "LPT1", "con"])
def test_reserved_windows_device_names_are_escaped(name):
    """Creating CON.md fails on Windows regardless of extension."""
    assert notes.slugify(name).lower() != name.lower()


def test_normal_titles_are_unchanged():
    assert notes.slugify("SonicWall SMA1000 Code Injection") == "SonicWall-SMA1000-Code-Injection"


# --- note filename collisions ---------------------------------------------

def test_two_notes_with_the_same_slug_do_not_overwrite(tmp_path):
    """Titles are model-chosen and free-form; two same-day items slugifying alike
    silently overwrote each other, with both audit records citing one file."""
    meta_a = {"title": "Same Title", "date": "2026-07-15", "_body": "---\nx: 1\n---\nA\n"}
    meta_b = {"title": "Same Title", "date": "2026-07-15", "_body": "---\nx: 2\n---\nB\n"}
    a = notes.write_threat_note(tmp_path, meta_a)
    b = notes.write_threat_note(tmp_path, meta_b)
    assert a != b
    assert a.read_text(encoding="utf-8").endswith("A\n")
    assert b.read_text(encoding="utf-8").endswith("B\n")


def test_rewriting_identical_content_reuses_the_same_file(tmp_path):
    meta = {"title": "T", "date": "2026-07-15", "_body": "---\nx: 1\n---\nbody\n"}
    assert notes.write_threat_note(tmp_path, meta) == notes.write_threat_note(tmp_path, meta)


# --- stub wikilink parity -------------------------------------------------

def test_stub_filename_matches_the_wikilink_text(tmp_path):
    """_UNSAFE.sub("") deleted characters from the filename while the note body
    kept the raw name, so [[families/Win32/Foo]] pointed at families/Win32Foo.md."""
    meta = {"family": ["Win32/Foo"], "attack_techniques": [], "actors": []}
    created = notes.ensure_stubs(tmp_path, meta)
    assert len(created) == 1
    link_text = notes.wikilink_name("Win32/Foo")
    assert created[0].stem == link_text


def test_stub_with_an_all_unsafe_name_does_not_create_a_dotfile(tmp_path):
    meta = {"family": ["///"], "attack_techniques": [], "actors": []}
    created = notes.ensure_stubs(tmp_path, meta)
    assert all(p.stem for p in created), "must never create families/.md"


def test_normal_family_name_keeps_its_spaces(tmp_path):
    meta = {"family": ["Lumma Stealer"], "attack_techniques": [], "actors": []}
    created = notes.ensure_stubs(tmp_path, meta)
    assert created[0].name == "Lumma Stealer.md"


# --- semantic validation --------------------------------------------------

VALID = """---
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
attack_techniques: [T1190]
actors: []
tags: [threat]
---

# Test Threat
"""


def test_source_mismatch_is_rejected():
    """meta["source"] flows into the note; a hallucinated value was schema-valid."""
    item = {"source": "threatfox", "external_id": "x"}
    ok, errors, _ = enrich.validate_note(VALID, item=item, today="2026-07-15")
    assert not ok
    assert any("source" in e for e in errors)


def test_date_mismatch_is_rejected():
    """meta["date"] drives the filename and the dashboard's 7-day window."""
    item = {"source": "kev", "external_id": "x"}
    ok, errors, _ = enrich.validate_note(VALID, item=item, today="2026-07-20")
    assert not ok
    assert any("date" in e for e in errors)


def test_matching_source_and_date_pass():
    item = {"source": "kev", "external_id": "x"}
    ok, errors, _ = enrich.validate_note(VALID, item=item, today="2026-07-15")
    assert ok, errors


def test_validation_without_item_context_still_works():
    ok, errors, _ = enrich.validate_note(VALID)
    assert ok, errors


# --- a non-zero exit must report what the engine said, not the first 300 bytes ---


def test_failure_reports_the_message_not_a_truncated_json_head(monkeypatch):
    """The 2026-08-31 DCRat failure recorded a `usage` block and nothing about
    why. `is_error` and `result` sit late in the payload, so a 300-character head
    of raw JSON cuts off just before the only part worth reading."""
    payload = json.dumps({
        "duration_api_ms": 0, "stop_reason": "stop_sequence",
        "session_id": "0d04a18d-e42b-43bf-823c-43d99c2dcdce",
        "total_cost_usd": 0,
        "usage": {"output_tokens_details": {"thinking_tokens": 0}, "input_tokens": 400,
                  "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
                  "output_tokens": 12, "server_tool_use": {"web_search_requests": 0}},
        "result": "Error: the model refused the request",
    })
    assert len(payload) > 300, "the message must sit past the old truncation point"
    monkeypatch.setattr(enrich.subprocess, "run",
                        lambda *a, **k: FakeCompleted(payload, returncode=1))
    with pytest.raises(enrich.EnrichmentError, match="the model refused the request"):
        enrich.run_claude("prompt")


def test_zero_token_failure_is_typed_as_the_engine_being_unavailable(monkeypatch):
    """A malformed prompt still burns input tokens. Zero in and zero out means
    nothing was ever asked of the model -- auth, quota or a usage limit -- and
    the next fifteen items will fail identically."""
    payload = json.dumps({
        "stop_reason": "stop_sequence", "total_cost_usd": 0,
        "usage": {"input_tokens": 0, "output_tokens": 0},
        "result": "",
    })
    monkeypatch.setattr(enrich.subprocess, "run",
                        lambda *a, **k: FakeCompleted(payload, returncode=1))
    with pytest.raises(enrich.EngineUnavailable, match="did no work"):
        enrich.run_claude("prompt")


def test_a_failure_that_did_work_is_not_typed_as_unavailable(monkeypatch):
    """The other half: tokens were spent, so the engine is answering and the next
    item is worth trying. Must not abort the run."""
    payload = json.dumps({
        "usage": {"input_tokens": 900, "output_tokens": 4},
        "result": "Error: could not complete",
    })
    monkeypatch.setattr(enrich.subprocess, "run",
                        lambda *a, **k: FakeCompleted(payload, returncode=1))
    with pytest.raises(enrich.EnrichmentError) as caught:
        enrich.run_claude("prompt")
    assert not isinstance(caught.value, enrich.EngineUnavailable)


def test_unparseable_stdout_still_falls_back_to_both_raw_streams(monkeypatch):
    """The 2026-08 outage was stderr-only reporting. Losing the raw fallback when
    the payload will not parse would reintroduce it."""
    monkeypatch.setattr(enrich.subprocess, "run",
                        lambda *a, **k: FakeCompleted("<html>502</html>", returncode=1,
                                                      stderr="proxy exploded"))
    with pytest.raises(enrich.EnrichmentError, match="502"):
        enrich.run_claude("prompt")
