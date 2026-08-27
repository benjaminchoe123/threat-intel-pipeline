"""Export the vault's ATT&CK coverage as a Navigator layer.

The vault already records which techniques each threat note maps to, but nothing
ever visualized it — README.md still carries an empty screenshot slot. A layer
file turns those mappings into a heatmap at https://mitre-attack.github.io/attack-navigator/
(Open Existing Layer -> Upload from Local), with no install and no new dependency.

Scores are note counts, so the heatmap answers "what am I actually seeing?" — not
"what does ATT&CK contain?". A technique's colour is how often it showed up in
real notes, which is the only claim this data supports.

    python -m pipeline.navigator
"""

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import date
from pathlib import Path

from . import attack, config
from .notes import _read_frontmatter

log = logging.getLogger(__name__)

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"


def collect_technique_counts(vault_dir):
    """{technique_id: number of threat notes citing it}."""
    counts = Counter()
    threats = Path(vault_dir) / "threats"
    if not threats.exists():
        return counts
    for path in sorted(threats.glob("*.md")):
        meta = _read_frontmatter(path)
        for tid in meta.get("attack_techniques") or []:
            counts[str(tid)] += 1
    return counts


def newest_note_date(vault_dir):
    """The date of the most recent threat note, or None on an empty vault.

    The layer is committed and rebuilt after every ingest, so naming it after
    the run date churns the file daily while asserting a coverage snapshot that
    did not actually move. Dating it by the data means the file changes when
    the coverage does — and only then.
    """
    dates = []
    threats = Path(vault_dir) / "threats"
    if not threats.exists():
        return None
    for path in sorted(threats.glob("*.md")):
        raw = (_read_frontmatter(path) or {}).get("date")
        if not raw:
            continue
        try:
            dates.append(date.fromisoformat(str(raw)))
        except ValueError:
            continue  # a malformed date dates nothing; it must not crash the layer
    return max(dates) if dates else None


def build_layer(counts, name=None, today=None):
    """A Navigator layer dict. Empty counts still produce a valid layer."""
    today = today or date.today()
    name = name or f"Threat vault coverage — {today.isoformat()}"
    top = max(counts.values()) if counts else 1
    techniques = [
        {
            "techniqueID": tid,
            "score": n,
            "comment": _comment(tid, n),
            "enabled": True,
        }
        for tid, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    return {
        "name": name,
        "versions": {"layer": LAYER_VERSION, "navigator": NAVIGATOR_VERSION,
                     "attack": "17"},
        "domain": "enterprise-attack",
        "description": (
            "Techniques observed in the threat-intel vault. Score = number of threat "
            "notes citing the technique, so this shows observed activity, not ATT&CK "
            "coverage in the abstract."
        ),
        "filters": {"platforms": []},
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#ff6666"],
            "minValue": 0,
            "maxValue": top,
        },
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
    }


def _comment(tid, count):
    name = attack.name_for(tid)
    label = f"{name}: " if name else ""
    return f"{label}{count} note(s) in the vault"


def export(vault_dir, out_path=None, today=None):
    vault_dir = Path(vault_dir)
    out_path = Path(out_path) if out_path else vault_dir / "docs" / "attack-layer.json"
    counts = collect_technique_counts(vault_dir)
    layer = build_layer(counts, today=newest_note_date(vault_dir) or today)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(layer, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    log.info("wrote %d technique(s) to %s", len(counts), out_path)
    return out_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default=None, help="output path for the layer JSON")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    path = export(config.VAULT_DIR, out_path=args.out)
    print(f"layer written: {path}")
    print("Open https://mitre-attack.github.io/attack-navigator/ -> "
          "Open Existing Layer -> Upload from Local")
    return 0


if __name__ == "__main__":
    sys.exit(main())
