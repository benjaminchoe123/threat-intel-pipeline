"""MITRE ATT&CK technique catalog: validate IDs against the real thing.

enrich.ATTACK_ID_RE only checks the *shape* T#### / T####.###, so T9999 and
T1234.567 passed validation — an invented technique reached the vault, got a stub
page, and joined the graph indistinguishable from a real one. In a knowledge base
whose stated purpose is honest analysis, a plausible-looking fake technique is
worse than an obvious error.

The catalog is a committed 24KB snapshot of ID -> name, distilled from MITRE's
50MB enterprise-attack STIX bundle. Committing it rather than depending on
mitreattack-python keeps the check offline-safe, fast, dependency-free, and
reviewable in git — the library exists to parse STIX and drive Navigator layers,
neither of which is needed to answer "is this ID real".

Refresh after an ATT&CK release:
    python -m pipeline.attack --refresh
"""

import argparse
import json
import logging
import sys
from functools import lru_cache
from pathlib import Path

from .http import default_session

log = logging.getLogger(__name__)

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
CATALOG_FILE = Path(__file__).resolve().parent / "data" / "attack_techniques.json"


def extract_techniques(bundle):
    """{technique_id: name} for active techniques in a STIX bundle.

    Deprecated and revoked techniques are excluded: a note citing one is stale
    analysis, and flagging it is the point.
    """
    out = {}
    for obj in bundle.get("objects") or []:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        for ref in obj.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                out[ref["external_id"]] = obj.get("name")
    return out


@lru_cache(maxsize=1)
def load():
    """The technique catalog, or {} if unavailable.

    Returning {} rather than raising is deliberate — see is_known().
    """
    try:
        return json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        log.warning("ATT&CK catalog unavailable (%s) — technique IDs will only be "
                    "shape-checked. Run: python -m pipeline.attack --refresh", e)
        return {}


def is_known(tid):
    """True if tid is a real ATT&CK technique.

    With no catalog on disk, everything is permitted: falling back to the regex
    is a weaker check, but rejecting every technique would quarantine every note,
    which is a worse failure than the one we are fixing.
    """
    catalog = load()
    if not catalog:
        return True
    return str(tid) in catalog


def name_for(tid):
    return load().get(str(tid))


def refresh(session=None, timeout=120):
    """Re-download the bundle and rewrite the catalog snapshot."""
    http = session or default_session()
    log.info("fetching %s", BUNDLE_URL)
    resp = http.get(BUNDLE_URL, timeout=timeout)
    resp.raise_for_status()
    techniques = extract_techniques(resp.json())
    if not techniques:
        raise RuntimeError("no techniques found in the ATT&CK bundle — refusing to write")
    CATALOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CATALOG_FILE.write_text(
        json.dumps(dict(sorted(techniques.items())), indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    load.cache_clear()
    return techniques


def main(argv=None):
    parser = argparse.ArgumentParser(description="ATT&CK technique catalog")
    parser.add_argument("--refresh", action="store_true", help="re-download the catalog")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if args.refresh:
        techniques = refresh()
        print(f"wrote {len(techniques)} techniques to {CATALOG_FILE}")
    else:
        print(f"{len(load())} techniques loaded from {CATALOG_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
