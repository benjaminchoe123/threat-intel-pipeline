import json

from pipeline.audit import log_enrichment


def test_appends_one_json_line_per_record(tmp_path):
    log_enrichment(tmp_path, {"source": "kev", "external_id": "CVE-1", "ok": True})
    log_enrichment(tmp_path, {"source": "kev", "external_id": "CVE-2", "ok": False})
    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 1  # one file per day
    lines = files[0].read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["external_id"] == "CVE-1"
    assert "timestamp" in first
