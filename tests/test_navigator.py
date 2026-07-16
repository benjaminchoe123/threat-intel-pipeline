"""The vault's ATT&CK mappings existed but were never visualized."""

import json
from datetime import date

from pipeline import navigator

NOTE = """---
title: {title}
type: threat
date: 2026-07-15
attack_techniques: [{techniques}]
---

# {title}
"""


def _write(vault, name, title, techniques):
    (vault / "threats").mkdir(parents=True, exist_ok=True)
    (vault / "threats" / name).write_text(
        NOTE.format(title=title, techniques=techniques), encoding="utf-8"
    )


def test_counts_techniques_across_notes(tmp_path):
    _write(tmp_path, "a.md", "A", "T1190, T1059.001")
    _write(tmp_path, "b.md", "B", "T1190")
    counts = navigator.collect_technique_counts(tmp_path)
    assert counts == {"T1190": 2, "T1059.001": 1}


def test_empty_vault_yields_no_counts(tmp_path):
    assert navigator.collect_technique_counts(tmp_path) == {}


def test_notes_without_techniques_are_ignored(tmp_path):
    (tmp_path / "threats").mkdir(parents=True)
    (tmp_path / "threats" / "x.md").write_text(
        "---\ntitle: X\ntype: threat\n---\n\n# X\n", encoding="utf-8")
    assert navigator.collect_technique_counts(tmp_path) == {}


def test_layer_is_sorted_most_frequent_first():
    layer = navigator.build_layer({"T1190": 1, "T1059": 5, "T1105": 3})
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1059", "T1105", "T1190"]


def test_layer_gradient_scales_to_the_busiest_technique():
    layer = navigator.build_layer({"T1190": 7})
    assert layer["gradient"]["maxValue"] == 7


def test_empty_layer_is_still_valid():
    layer = navigator.build_layer({})
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1  # a zero-width gradient breaks Navigator


def test_layer_declares_the_schema_navigator_expects():
    layer = navigator.build_layer({"T1190": 1})
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == navigator.LAYER_VERSION
    for key in ("name", "techniques", "gradient", "versions", "description"):
        assert key in layer


def test_comment_carries_the_official_technique_name():
    layer = navigator.build_layer({"T1190": 2})
    assert "Exploit Public-Facing Application" in layer["techniques"][0]["comment"]
    assert "2 note(s)" in layer["techniques"][0]["comment"]


def test_export_writes_parseable_json(tmp_path):
    _write(tmp_path, "a.md", "A", "T1190")
    out = navigator.export(tmp_path, today=date(2026, 7, 15))
    assert out.name == "attack-layer.json"
    layer = json.loads(out.read_text(encoding="utf-8"))
    assert layer["techniques"][0]["techniqueID"] == "T1190"
    assert "2026-07-15" in layer["name"]


def test_export_on_an_empty_vault_does_not_crash(tmp_path):
    out = navigator.export(tmp_path, today=date(2026, 7, 15))
    assert json.loads(out.read_text(encoding="utf-8"))["techniques"] == []
