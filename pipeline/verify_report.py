"""Automated draft verification: catch a wrong claim before it reaches GitHub
unattended, the way a human review used to be the only thing that did.

Two past incidents in this repo were caught by a human looking at output, not
by any test: the README's "flagship anecdote" was actually a mis-filed bug,
and EPSS scores of 0.99999 rendered as "100.0% probability" — a certainty the
model never claimed. This module is the automated stand-in for that human
catch when nobody is at the keyboard to publish.

FActScore-style, not SelfCheckGPT-style: this pipeline has real ground truth
for every report claim (the week's audit-logged, ATT&CK/EPSS/VT-validated
threat notes), so verification means checking claims against that reference,
not sampling the model against itself.
"""

import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_entities(draft_text):
    """Structured IDs cited in the draft — the only entities with a fixed
    enough shape to check without semantic judgment. See the deviation note
    in the plan for why family names and severity aren't handled here."""
    return {
        "cve": set(CVE_RE.findall(draft_text)),
        "attack_techniques": set(ATTACK_ID_RE.findall(draft_text)),
    }


def check_entities(entities, week_notes):
    """Every cited CVE/ATT&CK ID must trace to one of this week's real notes."""
    known_cves = set()
    known_techniques = set()
    for note in week_notes:
        known_cves.update(note.get("cve") or [])
        known_techniques.update(str(t) for t in (note.get("attack_techniques") or []))

    mismatches = []
    for cve in sorted(entities["cve"] - known_cves):
        mismatches.append(f"draft cites {cve}, which is not in any of this week's notes")
    for tid in sorted(entities["attack_techniques"] - known_techniques):
        mismatches.append(f"draft cites {tid}, which is not in any of this week's notes")
    return mismatches
