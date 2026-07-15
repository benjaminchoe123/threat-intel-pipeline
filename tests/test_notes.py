from pipeline.notes import ensure_stubs, slugify, write_threat_note

META = {
    "title": "CVE-2026-1234: Example RCE",
    "date": "2026-07-15",
    "family": ["Lumma Stealer"],
    "attack_techniques": ["T1190"],
    "actors": ["FIN7"],
    "_body": "---\ntitle: x\n---\n\n# body\n",
}


def test_slugify_makes_safe_filenames():
    assert slugify("CVE-2026-1234: Example RCE") == "CVE-2026-1234-Example-RCE"
    assert slugify('bad/\\:*?"<>| name') == "bad-name"


def test_write_threat_note_creates_file(tmp_path):
    path = write_threat_note(tmp_path, META)
    assert path.exists()
    assert path.parent.name == "threats"
    assert path.name == "2026-07-15-CVE-2026-1234-Example-RCE.md"
    assert path.read_text(encoding="utf-8") == META["_body"]


def test_ensure_stubs_creates_family_technique_actor(tmp_path):
    created = ensure_stubs(tmp_path, META)
    assert (tmp_path / "families" / "Lumma Stealer.md").exists()
    technique = tmp_path / "techniques" / "T1190.md"
    assert technique.exists()
    assert "attack.mitre.org/techniques/T1190" in technique.read_text(encoding="utf-8")
    assert (tmp_path / "actors" / "FIN7.md").exists()
    assert len(created) == 3


def test_ensure_stubs_does_not_overwrite_existing(tmp_path):
    stub = tmp_path / "families" / "Lumma Stealer.md"
    stub.parent.mkdir(parents=True)
    stub.write_text("hand-curated content", encoding="utf-8")
    ensure_stubs(tmp_path, META)
    assert stub.read_text(encoding="utf-8") == "hand-curated content"


def test_subtechnique_stub_links_parent_page(tmp_path):
    meta = dict(META, attack_techniques=["T1059.001"], family=[], actors=[])
    ensure_stubs(tmp_path, meta)
    text = (tmp_path / "techniques" / "T1059.001.md").read_text(encoding="utf-8")
    assert "attack.mitre.org/techniques/T1059/001" in text
