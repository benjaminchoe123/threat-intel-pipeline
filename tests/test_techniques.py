"""Exporting observed ATT&CK techniques, with the honesty of each sighting attached.

`ruleproof gap` ranks undetected techniques by how often they were observed, and
that ranking decides which detection gets written next. It is only as good as the
word "observed". Roughly half this vault's notes carry `flagged: true`, meaning
the enrichment itself said something in the note goes beyond the source -- and for
several techniques the mapping *is* the thing that went beyond it: Agent Tesla's
keylogging is family knowledge, not behaviour in a ThreatFox IOC dump.

Only the pipeline can draw that line, because only the pipeline knows its own
schema. So the split is exported here, and ruleproof keeps reading plain text.
"""

from pipeline import techniques

NOTE = """---
title: {title}
type: threat
date: 2026-07-15
flagged: {flagged}
attack_techniques: [{ids}]
---

# {title}
"""


def _write(vault, name, ids, flagged=False, title="T"):
    (vault / "threats").mkdir(parents=True, exist_ok=True)
    (vault / "threats" / name).write_text(
        NOTE.format(title=title, ids=ids, flagged=str(flagged).lower()),
        encoding="utf-8",
    )


def test_counts_every_sighting_and_the_confirmed_subset(tmp_path):
    _write(tmp_path, "a.md", "T1190", flagged=False)
    _write(tmp_path, "b.md", "T1190", flagged=True)
    counts = techniques.collect(tmp_path)
    assert counts["T1190"] == {"all": 2, "confirmed": 1}


def test_a_technique_seen_only_in_flagged_notes_still_appears(tmp_path):
    """Dropping it would hide the finding. The point is to show how thin the
    evidence is, not to pretend the sighting never happened."""
    _write(tmp_path, "a.md", "T1056.001", flagged=True)
    assert techniques.collect(tmp_path)["T1056.001"] == {"all": 1, "confirmed": 0}


def test_a_note_with_no_flagged_field_counts_as_confirmed(tmp_path):
    """Absent is not the same as flagged. Treating a missing field as suspect
    would silently reclassify every note written before the field existed."""
    (tmp_path / "threats").mkdir(parents=True)
    (tmp_path / "threats" / "a.md").write_text(
        "---\ntitle: A\ntype: threat\nattack_techniques: [T1071]\n---\n\n# A\n",
        encoding="utf-8")
    assert techniques.collect(tmp_path)["T1071"] == {"all": 1, "confirmed": 1}


def test_the_same_technique_twice_in_one_note_is_one_sighting(tmp_path):
    """Sightings measure how widely a technique appears, not how verbose one
    writeup was -- the same rule ruleproof.observed follows for directories."""
    (tmp_path / "threats").mkdir(parents=True)
    (tmp_path / "threats" / "a.md").write_text(
        "---\ntitle: A\ntype: threat\nattack_techniques: [T1071, T1071]\n---\n\n"
        "# A\n\nSee T1071 and T1071 again.\n", encoding="utf-8")
    assert techniques.collect(tmp_path)["T1071"]["all"] == 1


def _sightings(path):
    """The ids a consumer sees: one per line, inline `# xN` annotation stripped.

    That annotation is part of the established sample format -- `ruleproof`
    counts identifiers per line, so the comment rides along without changing the
    count.
    """
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if line:
            out.append(line)
    return out


def test_export_writes_one_line_per_sighting(tmp_path):
    _write(tmp_path, "a.md", "T1190", flagged=False)
    _write(tmp_path, "b.md", "T1190", flagged=True)
    out = tmp_path / "obs.txt"
    techniques.export(tmp_path, out)
    assert _sightings(out) == ["T1190", "T1190"]


def test_confirmed_only_export_drops_flagged_sightings(tmp_path):
    _write(tmp_path, "a.md", "T1190", flagged=False)
    _write(tmp_path, "b.md", "T1190", flagged=True)
    out = tmp_path / "obs.txt"
    techniques.export(tmp_path, out, confirmed_only=True)
    assert _sightings(out) == ["T1190"]


def test_export_header_states_how_much_of_the_data_is_flagged(tmp_path):
    """The caveat travels with the file. A consumer that reads only the numbers
    still cannot avoid seeing what they rest on."""
    _write(tmp_path, "a.md", "T1190", flagged=False)
    _write(tmp_path, "b.md", "T1190", flagged=True)
    out = tmp_path / "obs.txt"
    techniques.export(tmp_path, out)
    header = out.read_text(encoding="utf-8")
    assert "2 sighting" in header
    assert "1" in header and "flagged" in header


def test_empty_vault_exports_nothing_rather_than_crashing(tmp_path):
    out = tmp_path / "obs.txt"
    techniques.export(tmp_path, out)
    assert _sightings(out) == []


def test_export_names_the_technique_when_the_catalog_knows_it(tmp_path):
    """The old hand-made sample carried names and was readable because of it.
    This repo has the ATT&CK catalog, so annotating is free here and impossible
    downstream -- ruleproof deliberately has no catalog to look them up in."""
    _write(tmp_path, "a.md", "T1190")
    out = tmp_path / "obs.txt"
    techniques.export(tmp_path, out)
    first = [ln for ln in out.read_text(encoding="utf-8").splitlines()
             if ln.startswith("T1190")][0]
    assert "Exploit Public-Facing Application" in first


def test_an_unknown_identifier_is_left_unnamed_rather_than_guessed(tmp_path):
    _write(tmp_path, "a.md", "T9999")
    out = tmp_path / "obs.txt"
    techniques.export(tmp_path, out)
    first = [ln for ln in out.read_text(encoding="utf-8").splitlines()
             if ln.startswith("T9999")][0]
    assert first.strip() == "T9999  # x1"
