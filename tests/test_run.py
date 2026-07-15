from pipeline import config, run
from pipeline.state import State

from test_validate import VALID_NOTE

ITEM = {
    "source": "kev",
    "external_id": "CVE-2026-1111",
    "title": "ExampleServer RCE",
    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "raw": {"cveID": "CVE-2026-1111", "shortDescription": "RCE."},
    "content_hash": "abc",
}


def _redirect_dirs(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(config, "QUARANTINE_DIR", tmp_path / "quarantine")
    monkeypatch.setattr(config, "VAULT_DIR", tmp_path / "vault")
    monkeypatch.setattr(config, "AUDIT_DIR", tmp_path / "audit")


def test_process_item_embeds_reputation_block_in_prompt(tmp_path, monkeypatch):
    _redirect_dirs(monkeypatch, tmp_path)
    prompts = []

    def runner(prompt):
        prompts.append(prompt)
        return VALID_NOTE, {"is_error": False}

    outcome = run.process_item(
        ITEM, State(tmp_path / "state.db"), "skill", "2026-07-15",
        runner=runner, reputation_fn=lambda item: ("VT-REPUTATION-BLOCK", [{"kind": "ip"}]),
    )
    assert outcome == "written"
    assert "VT-REPUTATION-BLOCK" in prompts[0]


def test_process_item_audit_records_vt_lookups(tmp_path, monkeypatch):
    _redirect_dirs(monkeypatch, tmp_path)

    def runner(prompt):
        return VALID_NOTE, {"is_error": False}

    lookups = [{"kind": "ip", "ioc": "1.2.3.4", "found": True, "malicious": 12}]
    run.process_item(
        ITEM, State(tmp_path / "state.db"), "skill", "2026-07-15",
        runner=runner, reputation_fn=lambda item: ("block", lookups),
    )
    audit_text = next((tmp_path / "audit").glob("*.jsonl")).read_text(encoding="utf-8")
    assert '"1.2.3.4"' in audit_text


def test_process_item_works_without_reputation(tmp_path, monkeypatch):
    _redirect_dirs(monkeypatch, tmp_path)
    prompts = []

    def runner(prompt):
        prompts.append(prompt)
        return VALID_NOTE, {"is_error": False}

    outcome = run.process_item(
        ITEM, State(tmp_path / "state.db"), "skill", "2026-07-15",
        runner=runner, reputation_fn=lambda item: (None, []),
    )
    assert outcome == "written"
    assert "reputation" not in prompts[0].lower()
