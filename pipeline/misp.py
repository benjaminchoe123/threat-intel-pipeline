"""Push the pipeline's own STIX bundles into MISP as events, via PyMISP.

Reuses vault/docs/stix/*.json (pipeline/stix.py) as the single source of
truth rather than re-deriving attributes from notes a second way: notes ->
STIX bundle -> MISP event, each stage independently tested.

Entirely optional, same pattern as VirusTotal/AbuseIPDB/GreyNoise: unset
MISP_URL/MISP_API_KEY and every function here no-ops. event_from_bundle() is
unit-tested against PyMISP's data model classes only (no network needed to
construct a MISPEvent/MISPAttribute). push() is the only function that
touches a real server — client construction is factored into _client() so
tests can replace it without a live MISP instance.

Not yet live-verified against a running MISP: this machine's Tier 2 setup
(Docker Desktop / WSL2) is pending, see CLAUDE.md. Verify against a real
instance before trusting this in production.
"""

import json
import logging
import re
from pathlib import Path

from pymisp import MISPEvent

from . import config

log = logging.getLogger(__name__)

# Reverse of pipeline/stix.py's _PATTERN_BUILDERS: our own STIX patterns are
# deterministic, so parsing them back out is exact, not a guess.
_ATTR_PATTERNS = [
    (re.compile(r"^\[ipv4-addr:value = '([^']+)'\]$"), "ip-dst"),
    (re.compile(r"^\[domain-name:value = '([^']+)'\]$"), "domain"),
    (re.compile(r"^\[url:value = '([^']+)'\]$"), "url"),
    (re.compile(r"^\[file:hashes\.'MD5' = '([^']+)'\]$"), "md5"),
    (re.compile(r"^\[file:hashes\.'SHA-1' = '([^']+)'\]$"), "sha1"),
    (re.compile(r"^\[file:hashes\.'SHA-256' = '([^']+)'\]$"), "sha256"),
]


def _attribute_type(pattern):
    for regex, misp_type in _ATTR_PATTERNS:
        match = regex.match(pattern or "")
        if match:
            return misp_type, match.group(1)
    return None, None


def _technique_id(attack_pattern):
    return next(
        (r.get("external_id") for r in attack_pattern.get("external_references") or []
         if r.get("source_name") == "mitre-attack"),
        None,
    )


def event_from_bundle(bundle, info):
    """A MISPEvent from one of our own STIX bundles, or None if it has
    nothing MISP-representable (an empty or relationship-only bundle)."""
    event = MISPEvent()
    event.info = info
    added = False

    for obj in bundle.get("objects", []):
        kind = obj.get("type")
        if kind == "indicator":
            misp_type, value = _attribute_type(obj.get("pattern"))
            if not misp_type:
                continue
            event.add_attribute(misp_type, value, comment=obj.get("description") or "")
            added = True
        elif kind == "vulnerability":
            cve = obj.get("name")
            if cve:
                event.add_attribute("vulnerability", cve)
                added = True
        elif kind == "malware":
            event.add_tag(f"malware:{obj['name']}")
        elif kind == "attack-pattern":
            tid = _technique_id(obj)
            if tid:
                event.add_tag(f"mitre-attack-pattern:{tid}")

    return event if added else None


def _client(url, key, verify_ssl):
    from pymisp import PyMISP  # imported lazily: unit tests never need this
    return PyMISP(url, key, verify_ssl)


def push(event, url=None, key=None, verify_ssl=None):
    """Push one event to MISP. No-ops (returns None) if unconfigured."""
    url = url or config.MISP_URL
    key = key or config.MISP_API_KEY
    if not url or not key:
        return None
    verify_ssl = config.MISP_VERIFY_SSL if verify_ssl is None else verify_ssl
    client = _client(url, key, verify_ssl)
    return client.add_event(event)


def export_all(vault_dir, url=None, key=None, verify_ssl=None):
    """Push every non-empty STIX bundle in vault/docs/stix/ to MISP.

    No-ops on an unconfigured instance. A bundle that fails to convert or
    push is logged and skipped — one bad event must not stop the rest,
    same isolation rule as everywhere else in this pipeline.
    """
    url = url or config.MISP_URL
    key = key or config.MISP_API_KEY
    if not url or not key:
        return []

    stix_dir = Path(vault_dir) / "docs" / "stix"
    if not stix_dir.exists():
        return []

    pushed = []
    for path in sorted(stix_dir.glob("*.json")):
        try:
            bundle = json.loads(path.read_text(encoding="utf-8"))
            event = event_from_bundle(bundle, info=path.stem)
            if event is None:
                continue
            push(event, url=url, key=key, verify_ssl=verify_ssl)
        except Exception:
            log.exception("MISP push failed for %s — skipping", path.name)
            continue
        pushed.append(path)

    log.info("pushed %d event(s) to MISP", len(pushed))
    return pushed
