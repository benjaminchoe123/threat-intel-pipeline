"""Turn the pipeline's own STIX bundles into MISP events via PyMISP.

event_from_bundle/attribute mapping is unit-tested against PyMISP's data
model classes only (no network). push()/export_all() are tested with the
client mocked out — this pipeline has no live MISP instance to verify
against yet (Tier 2 infra is pending), so nothing here claims to have been
exercised against a real server.
"""

import json

from pipeline import misp

STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--x",
    "objects": [
        {"type": "malware", "id": "malware--a", "name": "AdaptixC2", "is_family": True},
        {"type": "attack-pattern", "id": "attack-pattern--b", "name": "Web Protocols",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1071.001"}]},
        {"type": "indicator", "id": "indicator--c", "name": "ip:port: 1.2.3.4:80",
         "pattern": "[ipv4-addr:value = '1.2.3.4']", "description": "botnet_cc"},
        {"type": "indicator", "id": "indicator--d", "name": "domain: evil.example.com",
         "pattern": "[domain-name:value = 'evil.example.com']", "description": ""},
        {"type": "indicator", "id": "indicator--e", "name": "url",
         "pattern": "[url:value = 'http://evil.example.com/x']", "description": ""},
        {"type": "indicator", "id": "indicator--f", "name": "sha256",
         "pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
         "description": ""},
        {"type": "relationship", "id": "relationship--g", "relationship_type": "indicates",
         "source_ref": "indicator--c", "target_ref": "malware--a"},
    ],
}


def _attr_values(event, misp_type):
    return [a.value for a in event.attributes if a.type == misp_type]


def test_builds_an_ip_attribute_from_an_ipv4_indicator():
    event = misp.event_from_bundle(STIX_BUNDLE, info="test")
    assert _attr_values(event, "ip-dst") == ["1.2.3.4"]


def test_builds_domain_url_and_hash_attributes():
    event = misp.event_from_bundle(STIX_BUNDLE, info="test")
    assert _attr_values(event, "domain") == ["evil.example.com"]
    assert _attr_values(event, "url") == ["http://evil.example.com/x"]
    assert _attr_values(event, "sha256") == \
        ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]


def test_malware_and_technique_become_tags_not_attributes():
    event = misp.event_from_bundle(STIX_BUNDLE, info="test")
    tags = {t.name for t in event.tags}
    assert "malware:AdaptixC2" in tags
    assert "mitre-attack-pattern:T1071.001" in tags


def test_relationship_objects_are_ignored_not_erroring():
    # Relationships don't map to a MISP attribute/tag on their own; they must
    # not raise or otherwise break the conversion.
    event = misp.event_from_bundle(STIX_BUNDLE, info="test")
    assert event is not None


def test_cve_only_bundle_yields_a_vulnerability_attribute():
    bundle = {"type": "bundle", "objects": [
        {"type": "vulnerability", "id": "vulnerability--a", "name": "CVE-2026-1111",
         "external_references": [{"source_name": "cve", "external_id": "CVE-2026-1111"}]},
    ]}
    event = misp.event_from_bundle(bundle, info="test")
    assert _attr_values(event, "vulnerability") == ["CVE-2026-1111"]


def test_empty_bundle_yields_no_event():
    assert misp.event_from_bundle({"type": "bundle", "objects": []}, info="test") is None


def test_bundle_with_only_a_relationship_yields_no_event():
    bundle = {"type": "bundle", "objects": [
        {"type": "relationship", "id": "relationship--z", "relationship_type": "uses",
         "source_ref": "malware--a", "target_ref": "attack-pattern--b"},
    ]}
    assert misp.event_from_bundle(bundle, info="test") is None


def test_event_info_is_set_from_the_given_title():
    event = misp.event_from_bundle(STIX_BUNDLE, info="AdaptixC2 cluster")
    assert event.info == "AdaptixC2 cluster"


# --- push() is optional, same pattern as every other API key in this pipeline --

def test_push_no_ops_without_url_or_key(monkeypatch):
    monkeypatch.setattr(misp.config, "MISP_URL", "")
    monkeypatch.setattr(misp.config, "MISP_API_KEY", "")
    assert misp.push(misp.event_from_bundle(STIX_BUNDLE, info="t")) is None


def test_push_calls_add_event_when_configured(monkeypatch):
    calls = []

    class FakeClient:
        def __init__(self, url, key, ssl):
            calls.append((url, key, ssl))

        def add_event(self, event):
            calls.append(("add_event", event.info))
            return {"Event": {"id": "1"}}

    monkeypatch.setattr(misp, "_client", lambda url, key, ssl: FakeClient(url, key, ssl))
    event = misp.event_from_bundle(STIX_BUNDLE, info="t")
    misp.push(event, url="https://misp.local", key="deadbeef", verify_ssl=False)
    assert calls[0] == ("https://misp.local", "deadbeef", False)
    assert calls[1] == ("add_event", "t")


# --- export_all: read vault/docs/stix/*.json, push each, isolate failures ----

def _write_bundle(vault, name, bundle):
    stix_dir = vault / "docs" / "stix"
    stix_dir.mkdir(parents=True, exist_ok=True)
    (stix_dir / name).write_text(json.dumps(bundle), encoding="utf-8")


def test_export_all_no_ops_without_config(tmp_path, monkeypatch):
    monkeypatch.setattr(misp.config, "MISP_URL", "")
    monkeypatch.setattr(misp.config, "MISP_API_KEY", "")
    _write_bundle(tmp_path, "a.json", STIX_BUNDLE)
    assert misp.export_all(tmp_path) == []


def test_export_all_pushes_every_nonempty_bundle(tmp_path, monkeypatch):
    pushed = []
    monkeypatch.setattr(misp, "push", lambda event, **kw: pushed.append(event.info))
    _write_bundle(tmp_path, "a.json", STIX_BUNDLE)
    _write_bundle(tmp_path, "b.json", {"type": "bundle", "objects": []})  # empty: skipped
    written = misp.export_all(tmp_path, url="https://misp.local", key="k")
    assert len(written) == 1
    assert pushed == ["a"]


def test_export_all_isolates_a_bundle_that_fails_to_push(tmp_path, monkeypatch):
    def flaky_push(event, **kw):
        if event.info == "broken":
            raise RuntimeError("MISP unreachable")

    monkeypatch.setattr(misp, "push", flaky_push)
    _write_bundle(tmp_path, "broken.json", STIX_BUNDLE)
    _write_bundle(tmp_path, "ok.json", STIX_BUNDLE)
    written = misp.export_all(tmp_path, url="https://misp.local", key="k")
    assert len(written) == 1


def test_export_all_on_missing_stix_dir_returns_empty(tmp_path):
    assert misp.export_all(tmp_path, url="https://misp.local", key="k") == []
