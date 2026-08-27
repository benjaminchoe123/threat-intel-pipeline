"""Export the vault's threat notes as STIX 2.1 bundles — the industry
interchange format most CTI tooling (MISP, TheHive/Cortex, TIPs) can import.

Built only from what a note already asserts: frontmatter (cve/family/
attack_techniques, all schema-validated at write time) and the Observed IOCs
table, which is part of the enrichment prompt contract in
skills/threat-analyst.md. Nothing here infers or invents a relationship the
note doesn't already state — an IOC type this module doesn't recognize is
dropped, not guessed at, the same "don't guess" rule the enrichment itself
follows.

    python -m pipeline.stix
"""

import argparse
import logging
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import stix2

from . import attack, config
from .notes import _read_frontmatter
from .vt import _strip_port

log = logging.getLogger(__name__)

_URN = "threat-intel-pipeline"  # namespace for deterministic object ids

_IOC_ROW_RE = re.compile(r"^\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*$")

# STIX Cyber Observable pattern builders, keyed by the abuse.ch ioc_type
# vocabulary the enrichment prompt echoes verbatim from source data.
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _ip_pattern(value):
    ip = _strip_port(value)
    if not _IPV4_RE.match(ip):
        return None  # bare IPv6 or anything else: don't guess the SCO type
    return f"[ipv4-addr:value = '{ip}']"


_PATTERN_BUILDERS = {
    "ip": _ip_pattern,
    "ip:port": _ip_pattern,
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url": lambda v: f"[url:value = '{v}']",
    "md5_hash": lambda v: f"[file:hashes.'MD5' = '{v}']",
    "sha1_hash": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "sha256_hash": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
}


def ioc_pattern(ioc_type, value):
    """A STIX pattern string for one Observed-IOCs row, or None if the type
    isn't in the known abuse.ch vocabulary — never invented."""
    builder = _PATTERN_BUILDERS.get(ioc_type)
    return builder(value) if builder else None


def parse_ioc_table(body):
    """Rows of the note's IOC markdown table as {type, value, context}.

    Best-effort: the table is part of the prompt contract, not schema-validated
    like frontmatter, so a row that doesn't parse is simply skipped. A note has
    at most one markdown table (Observed IOCs), so scanning the whole body for
    `| a | b | c |` lines is enough — no section-scoping needed.
    """
    rows = []
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = _IOC_ROW_RE.match(line)
        if not cells:
            continue
        type_, value, context = (c.strip() for c in cells.groups())
        if type_.lower() in ("type", "---") or set(type_) <= {"-"}:
            continue  # header / separator row
        rows.append({"type": type_, "value": value, "context": context})
    return rows


def _stix_id(stix_type, key):
    """Deterministic id: the same family/technique/CVE gets the same STIX id
    everywhere, so bundles from different notes reference one shared object
    instead of minting a duplicate every time it's seen."""
    return f"{stix_type}--{uuid.uuid5(uuid.NAMESPACE_URL, f'{_URN}:{stix_type}:{key}')}"


def _note_time(meta):
    """The note's own date as the timestamp every object in its bundle carries.

    Not the clock. `python -m pipeline.stix` rebuilds all bundles from scratch
    after every ingest, so a wall-clock `created`/`modified` restamps 77
    unchanged notes as modified today — and STIX consumers (MISP, TIPs) dedupe
    and diff on `modified`, so that is a false claim a machine will act on, not
    just diff noise. Raises on an unparseable date, which `export` isolates to
    the one bad note.
    """
    return datetime.strptime(str(meta["date"]), "%Y-%m-%d").replace(tzinfo=UTC)


def _read_note(path):
    text = Path(path).read_text(encoding="utf-8")
    meta = _read_frontmatter(path)
    body = re.sub(r"^---\n.*?\n---\n", "", text, count=1, flags=re.DOTALL)
    return meta, body


def build_bundle(meta, body):
    """A stix2 Bundle for one threat note, or None if it asserts nothing
    STIX-worthy (no CVE, no family, no technique, no parseable IOC)."""
    objects = []
    vuln_by_cve, malware_by_family, ap_by_technique = {}, {}, {}
    seen_at = _note_time(meta) if meta.get("date") else datetime.now(UTC)
    stamp = {"created": seen_at, "modified": seen_at}

    for cve in meta.get("cve") or []:
        vuln = stix2.Vulnerability(
            **stamp,
            id=_stix_id("vulnerability", cve),
            name=cve,
            external_references=[{"source_name": "cve", "external_id": cve}],
        )
        vuln_by_cve[cve] = vuln
        objects.append(vuln)

    for family in meta.get("family") or []:
        malware = stix2.Malware(
            **stamp,
            id=_stix_id("malware", family),
            name=family,
            is_family=True,
        )
        malware_by_family[family] = malware
        objects.append(malware)

    for tid in meta.get("attack_techniques") or []:
        name = attack.name_for(tid) or tid
        ap = stix2.AttackPattern(
            **stamp,
            id=_stix_id("attack-pattern", tid),
            name=name,
            external_references=[{
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid}",
            }],
        )
        ap_by_technique[tid] = ap
        objects.append(ap)

    indicators = []
    for row in parse_ioc_table(body):
        pattern = ioc_pattern(row["type"], row["value"])
        if not pattern:
            continue
        indicators.append(stix2.Indicator(
            **stamp,
            id=_stix_id("indicator", f"{row['type']}:{row['value']}"),
            name=f"{row['type']}: {row['value']}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=seen_at,
            description=row["context"] or None,
        ))
    objects.extend(indicators)

    for indicator in indicators:
        for malware in malware_by_family.values():
            objects.append(stix2.Relationship(
                **stamp,
                id=_stix_id("relationship", f"{indicator.id}:indicates:{malware.id}"),
                relationship_type="indicates", source_ref=indicator.id, target_ref=malware.id,
            ))
    for malware in malware_by_family.values():
        for ap in ap_by_technique.values():
            objects.append(stix2.Relationship(
                **stamp,
                id=_stix_id("relationship", f"{malware.id}:uses:{ap.id}"),
                relationship_type="uses", source_ref=malware.id, target_ref=ap.id,
            ))
        for vuln in vuln_by_cve.values():
            objects.append(stix2.Relationship(
                **stamp,
                id=_stix_id("relationship", f"{malware.id}:exploits:{vuln.id}"),
                relationship_type="exploits", source_ref=malware.id, target_ref=vuln.id,
            ))

    if not objects:
        return None
    # Content-addressed, because stix2.Bundle otherwise mints a random uuid4 per
    # call: the container's identity is what it contains, so an unchanged note
    # re-exports to the same bundle instead of a new one every run.
    contents = ":".join(sorted(o.id for o in objects))
    return stix2.Bundle(id=_stix_id("bundle", contents), objects=objects)


def export(vault_dir, out_dir=None):
    """Write one bundle per non-empty threat note to vault/docs/stix/.

    Rebuilt from scratch every call, like navigator.export — a note that
    fails to convert is logged and skipped, never taking the rest down.
    """
    vault_dir = Path(vault_dir)
    out_dir = Path(out_dir) if out_dir else vault_dir / "docs" / "stix"
    threats = vault_dir / "threats"
    if not threats.exists():
        return []

    written = []
    for path in sorted(threats.glob("*.md")):
        try:
            bundle = build_bundle(*_read_note(path))
        except Exception:
            log.exception("stix export failed for %s — skipping", path.name)
            continue
        if bundle is None:
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{path.stem}.json"
        out_path.write_text(bundle.serialize(pretty=True), encoding="utf-8")
        written.append(out_path)

    log.info("wrote %d STIX bundle(s) to %s", len(written), out_dir)
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    written = export(config.VAULT_DIR)
    print(f"wrote {len(written)} STIX bundle(s) to {config.VAULT_DIR / 'docs' / 'stix'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
