from pipeline.state import State


def test_unseen_item_is_new(tmp_path):
    state = State(tmp_path / "state.db")
    assert state.check("kev", "CVE-2026-1234", "hash-a") == "new"


def test_recorded_item_is_seen(tmp_path):
    state = State(tmp_path / "state.db")
    state.record("kev", "CVE-2026-1234", "hash-a")
    assert state.check("kev", "CVE-2026-1234", "hash-a") == "seen"


def test_recorded_item_with_changed_hash_is_updated(tmp_path):
    state = State(tmp_path / "state.db")
    state.record("kev", "CVE-2026-1234", "hash-a")
    assert state.check("kev", "CVE-2026-1234", "hash-b") == "updated"


def test_same_id_different_source_is_new(tmp_path):
    state = State(tmp_path / "state.db")
    state.record("kev", "CVE-2026-1234", "hash-a")
    assert state.check("threatfox", "CVE-2026-1234", "hash-a") == "new"


def test_record_is_persistent_across_instances(tmp_path):
    db = tmp_path / "state.db"
    State(db).record("kev", "CVE-2026-1234", "hash-a")
    assert State(db).check("kev", "CVE-2026-1234", "hash-a") == "seen"
