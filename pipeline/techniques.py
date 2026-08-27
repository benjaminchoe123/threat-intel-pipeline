"""Export the ATT&CK techniques this vault has observed, with the strength of
each sighting attached.

`ruleproof gap` ranks undetected techniques by observed frequency and that
ranking decides which detection gets written next, so the ranking is only as
good as the word *observed*. About half of this vault's notes carry
`flagged: true`, which the enrichment contract in `skills/threat-analyst.md`
defines as "something here goes beyond the source" -- and for several techniques
the ATT&CK mapping is precisely the thing that went beyond it. Agent Tesla's
keylogging (T1056.001) is well-documented family behaviour; it is not behaviour
present in a ThreatFox IOC dump, and the notes say so in as many words.

Only this repo can draw that line, because only this repo knows its own
frontmatter. So the split is exported here as plain text and ruleproof keeps
reading *a file containing ATT&CK identifiers*, with no schema and no import --
the one-way dependency stays one-way.

Counts here come from the schema-validated `attack_techniques` frontmatter, which
is the note's actual *claim*. A plain text scan of the same vault reads slightly
higher, because a technique can be named in prose without being asserted as a
mapping -- that is the difference between this export's 127 sightings and the 128
a regex finds. The frontmatter number is the one to trust; the looser one is what
`ruleproof.observed` sees when pointed at raw notes, which is a fair default for
a tool that must also read SIEM exports and hand-written lists.

`flagged` is a property of the **note**, not of the individual mapping: an
analyst flags a note when anything in it is uncertain, which may be the severity
rather than the technique. So `confirmed` is a conservative floor, not a precise
count of well-evidenced mappings, and `--confirmed-only` will discard some good
mappings along with the weak ones. Both numbers are reported for that reason.
Presenting either one alone would be the kind of single flattering figure this
project exists to argue against.

    python -m pipeline.techniques                  # every sighting, to stdout
    python -m pipeline.techniques -o observed.txt  # ...to a file
    python -m pipeline.techniques --confirmed-only # drop sightings from flagged notes
    python -m pipeline.techniques --report         # side-by-side counts
"""

import argparse
import logging
import sys
from pathlib import Path

from . import config
from .notes import _read_frontmatter

log = logging.getLogger(__name__)


def collect(vault_dir):
    """{technique_id: {"all": n, "confirmed": n}} counted per note.

    One note citing a technique five times is one sighting -- the measure is how
    widely a technique appears, not how verbose any single writeup was. That is
    the same rule `ruleproof.observed` applies to a directory, and the two must
    agree or the exported file would rank differently from the live vault.
    """
    counts = {}
    threats = Path(vault_dir) / "threats"
    if not threats.exists():
        return counts
    for path in sorted(threats.glob("*.md")):
        meta = _read_frontmatter(path) or {}
        confirmed = not bool(meta.get("flagged"))
        for tid in {str(t) for t in (meta.get("attack_techniques") or [])}:
            entry = counts.setdefault(tid, {"all": 0, "confirmed": 0})
            entry["all"] += 1
            entry["confirmed"] += confirmed
    return counts


def _ordered(counts, confirmed_only):
    key = "confirmed" if confirmed_only else "all"
    return sorted(((t, c[key]) for t, c in counts.items() if c[key]),
                  key=lambda tc: (-tc[1], tc[0]))


def render(counts, confirmed_only=False):
    total = sum(c["all"] for c in counts.values())
    confirmed = sum(c["confirmed"] for c in counts.values())
    flagged = total - confirmed
    rows = _ordered(counts, confirmed_only)
    lines = [
        "# ATT&CK techniques observed in this vault's threat notes.",
        "#",
        f"# {len(rows)} technique(s), {sum(n for _, n in rows)} sighting(s)."
        + (" Sightings from flagged notes excluded." if confirmed_only else ""),
        f"# Across the whole vault: {total} sighting(s), of which {flagged} come from notes"
        " the",
        "# enrichment flagged as going beyond their source. `flagged` is a property of the",
        "# note rather than of the individual mapping, so that count is an upper bound on",
        "# inference, and --confirmed-only is a conservative floor that discards some sound",
        "# mappings too. Neither number alone is the honest one.",
        "#",
        "# One line per sighting; the repetition is what ranks a coverage gap.",
        "",
    ]
    for tid, n in rows:
        lines.append(f"{tid}  # x{n}")
        lines.extend([tid] * (n - 1))
    return "\n".join(lines) + "\n"


def export(vault_dir, out_path, confirmed_only=False):
    counts = collect(vault_dir)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(counts, confirmed_only), encoding="utf-8", newline="\n")
    log.info("wrote %d technique(s) to %s", len(counts), out_path)
    return out_path


def report(counts):
    """Every technique, with how much of its count survives the flagged filter."""
    lines = [f"{'technique':<14}{'sightings':>10}{'confirmed':>11}{'flagged':>9}"]
    for tid, c in sorted(counts.items(), key=lambda tc: (-tc[1]["all"], tc[0])):
        lines.append(f"{tid:<14}{c['all']:>10}{c['confirmed']:>11}"
                     f"{c['all'] - c['confirmed']:>9}")
    total = sum(c["all"] for c in counts.values())
    confirmed = sum(c["confirmed"] for c in counts.values())
    lines.append("")
    lines.append(f"{'TOTAL':<14}{total:>10}{confirmed:>11}{total - confirmed:>9}")
    if total:
        lines.append(f"\n{(total - confirmed) / total:.0%} of sightings come from notes the "
                     "enrichment flagged as going beyond their source.")
        lines.append("A ranking built on this is a ranking built on that mix. `flagged` is "
                     "note-level,")
        lines.append("so treat it as an upper bound on inference rather than a count of it.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("-o", "--out", default=None, help="write to a file instead of stdout")
    parser.add_argument("--confirmed-only", action="store_true",
                        help="drop sightings from notes the enrichment flagged")
    parser.add_argument("--report", action="store_true",
                        help="side-by-side counts instead of the sighting list")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    counts = collect(config.VAULT_DIR)
    if args.report:
        print(report(counts))
        return 0
    if args.out:
        export(config.VAULT_DIR, args.out, args.confirmed_only)
        print(f"wrote {args.out}")
        return 0
    print(render(counts, args.confirmed_only), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
