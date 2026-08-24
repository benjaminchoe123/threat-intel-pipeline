"""Write validated enrichment notes into the Obsidian vault and maintain
stub pages for families / ATT&CK techniques / actors so wikilinks resolve
and the graph view shows relationships."""

import hashlib
import os
import re
from datetime import date, timedelta
from pathlib import Path

import yaml

from . import attack, health

_UNSAFE = re.compile(r'[/\\:*?"<>|#^\[\]]+')

FALLBACK_SLUG = "untitled"
# Keeps a full path clear of Windows' 260-char MAX_PATH while leaving room for a
# typical CVE title. An 80-char cap cut "…Vulnerability-(CVE-2026-46817)" mid-CVE.
MAX_SLUG_LEN = 120

# Reserved on Windows regardless of extension: CON.md cannot be created.
_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{n}" for n in range(1, 10)),
    *(f"LPT{n}" for n in range(1, 10)),
}


def _truncate(slug):
    """Cap length, preferring a word boundary.

    A hard cut left "…Vulnerability-(CVE-2026-46" — a filename ending in half a
    CVE id reads as data corruption. Backing up to the last separator only when
    it costs little keeps the name honest about where it stops.
    """
    if len(slug) <= MAX_SLUG_LEN:
        return slug
    cut = slug[:MAX_SLUG_LEN]
    last_sep = cut.rfind("-")
    if last_sep >= int(MAX_SLUG_LEN * 0.6):
        cut = cut[:last_sep]
    return cut.rstrip("-")


def slugify(title):
    """Filesystem-safe slug. Never empty, never a Windows reserved name.

    slugify("") returned "" — which produced data/raw/mta/.json, a single file
    every empty-id item collided on (confirmed in the live audit log).
    """
    slug = _UNSAFE.sub(" ", str(title))
    slug = re.sub(r"\s+", "-", slug.strip())
    slug = re.sub(r"-{2,}", "-", slug)
    slug = _truncate(slug)
    # Windows silently drops trailing dots/spaces, so "x." and "x" collide.
    slug = slug.strip(". ")
    if not slug:
        return FALLBACK_SLUG
    if slug.upper() in _RESERVED:
        return f"{slug}-note"
    return slug


def wikilink_name(name):
    """The stub filename, which must equal the wikilink text in the note body.

    _UNSAFE.sub("") deleted the characters from the filename while the body kept
    the raw name, so [[families/Win32/Foo]] pointed at families/Win32Foo.md and
    dangled. Both sides now derive from this one function.
    """
    safe = re.sub(r"\s+", " ", _UNSAFE.sub("-", str(name))).strip(" -")
    safe = safe.strip(". ")
    if len(safe) > MAX_SLUG_LEN:
        safe = safe[:MAX_SLUG_LEN].strip(" -")
    safe = safe.strip(". ")
    if not safe:
        return FALLBACK_SLUG
    if safe.upper() in _RESERVED:
        return f"{safe}-note"
    return safe


def _write_atomic(path, text):
    """Write via a temp file + os.replace.

    home.md and the notes live in a directory Obsidian is actively watching; a
    crash mid-write left a truncated note there.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path


def write_threat_note(vault_dir, meta):
    vault_dir = Path(vault_dir)
    note_date = meta.get("date") or date.today().isoformat()
    body = meta["_body"]
    base = f"{note_date}-{slugify(meta['title'])}"
    path = _unique_note_path(vault_dir / "threats", base, body)
    return _write_atomic(path, body)


def _unique_note_path(directory, base, body):
    """Avoid silently overwriting a different note that slugifies identically.

    Titles are model-chosen and free-form, so two same-day items can collide;
    the second write used to clobber the first, with both audit records pointing
    at the one surviving file. Re-writing identical content reuses the path.
    """
    path = directory / f"{base}.md"
    if not path.exists() or path.read_text(encoding="utf-8") == body:
        return path
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()[:8]
    return directory / f"{base}-{digest}.md"


_STUB_KINDS = {"families": "family", "techniques": "technique", "actors": "actor"}

# Live queries over note frontmatter. Dataview is a community plugin, so until it
# is installed these render as plain code blocks — inert, never broken. The static
# lists above stay regardless, so the dashboard is useful either way.
DATAVIEW_SECTION = """
## Live queries

*(These need the [Dataview](https://github.com/blacksmithgu/obsidian-dataview)
community plugin: Settings → Community plugins → Browse → "Dataview" → Install →
Enable. Until then they show as code blocks.)*

### Everything by severity

```dataview
TABLE severity, confidence, choice(flagged, "yes", "no") AS flagged, date
FROM "threats"
SORT choice(severity = "critical", 0, choice(severity = "high", 1,
     choice(severity = "medium", 2, 3))) ASC, date DESC
```

### Needs review (low confidence or flagged)

```dataview
TABLE severity, confidence, date
FROM "threats"
WHERE flagged = true OR confidence = "low"
SORT date DESC
```

### High and critical in the last 30 days

```dataview
TABLE severity, family, cve, date
FROM "threats"
WHERE (severity = "high" OR severity = "critical")
  AND date >= date(today) - dur(30 days)
SORT date DESC
```

### Most-seen ATT&CK techniques

```dataview
TABLE length(rows) AS notes
FROM "threats"
FLATTEN attack_techniques AS technique
GROUP BY technique
SORT length(rows) DESC
```

### Malware families seen

```dataview
TABLE length(rows) AS notes, min(rows.date) AS "first seen"
FROM "threats"
FLATTEN family AS fam
GROUP BY fam
SORT length(rows) DESC
```
"""


def _technique_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/")


def _technique_extra(tid):
    """Stub body for a technique. Filename stays the bare ID so [[techniques/T1190]]
    resolves; the official name goes in the body, where it aids reading the graph."""
    name = attack.name_for(tid)
    heading = f"**{name}**\n\n" if name else ""
    return f"{heading}MITRE ATT&CK: {_technique_url(tid)}\n\n"


def _stub(title, kind, extra=""):
    today = date.today().isoformat()
    return (
        f"---\ntitle: {title}\ntype: {kind}\ntags: [{kind}]\n"
        f"created: {today}\nupdated: {today}\n---\n\n# {title}\n\n"
        f"{extra}Auto-created stub — threat notes linking here appear as backlinks.\n"
    )


def ensure_stubs(vault_dir, meta):
    """Create missing stub notes for everything the threat note wikilinks.
    Returns list of created paths; never touches existing notes."""
    vault_dir = Path(vault_dir)
    created = []
    wanted = (
        [("families", name, "") for name in meta.get("family") or []]
        + [
            ("techniques", tid, _technique_extra(tid))
            for tid in meta.get("attack_techniques") or []
        ]
        + [("actors", name, "") for name in meta.get("actors") or []]
    )
    for folder, name, extra in wanted:
        # Filename and wikilink text both come from wikilink_name, so they cannot
        # drift apart. Spaces are kept: [[families/Lumma Stealer]] resolves to
        # families/Lumma Stealer.md.
        path = vault_dir / folder / f"{wikilink_name(name)}.md"
        if path.exists():
            continue
        kind = _STUB_KINDS[folder]
        _write_atomic(path, _stub(name, kind, extra))
        created.append(path)
    return created


def _read_frontmatter(path):
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not match:
        return {}
    try:
        meta = yaml.safe_load(match.group(1))
        return meta if isinstance(meta, dict) else {}
    except yaml.YAMLError:
        return {}


def update_dashboards(vault_dir, today=None, last_run=None):
    """Regenerate home.md and review-queue.md from vault contents.

    last_run: the heartbeat dict from health.load_last_run(), or None. Passed in
    rather than read here so this module stays free of config/path knowledge:
    it takes a vault_dir and touches nothing else.
    """
    vault_dir = Path(vault_dir)
    # A run in which every item failed still reaches here with no vault on disk.
    (vault_dir / "threats").mkdir(parents=True, exist_ok=True)
    today = today or date.today()
    threats = []
    for path in sorted((vault_dir / "threats").glob("*.md"), reverse=True):
        meta = _read_frontmatter(path)
        meta["_link"] = f"[[threats/{path.stem}]]"
        threats.append(meta)

    def count(folder):
        d = vault_dir / folder
        return len(list(d.glob("*.md"))) if d.exists() else 0

    cutoff = (today - timedelta(days=7)).isoformat()
    recent = [t for t in threats if str(t.get("date", "")) >= cutoff]
    recent_lines = [
        f"- {t['_link']} — **{t.get('severity', '?')}**"
        + (" ⚑ flagged" if t.get("flagged") else "")
        for t in recent
    ] or ["*(none in the last 7 days)*"]

    flagged = [t for t in threats if t.get("flagged")]
    flagged_lines = [
        f"- {t['_link']} — confidence: {t.get('confidence', '?')}" for t in flagged
    ] or ["*(empty)*"]

    home = (
        f"---\ntitle: Threat Intel Home\ntype: dashboard\ntags: [dashboard]\n"
        f"updated: {today.isoformat()}\n---\n\n"
        "# Threat Intel Dashboard\n\n"
        + health.banner(health.assess(threats, today=today, last_run=last_run))
        + "\n\n"
        "Auto-generated each pipeline run. Do not hand-edit — see `pipeline/notes.py`.\n\n"
        "## Last 7 days\n\n" + "\n".join(recent_lines) + "\n\n"
        f"## Review queue\n\nSee [[review-queue]] — {len(flagged)} flagged item(s).\n\n"
        "## Stats\n\n"
        "| metric | value |\n|---|---|\n"
        f"| total threat notes | {len(threats)} |\n"
        f"| malware families tracked | {count('families')} |\n"
        f"| ATT&CK techniques seen | {count('techniques')} |\n"
        f"| last run | {today.isoformat()} |\n"
        + DATAVIEW_SECTION
    )
    _write_atomic(vault_dir / "home.md", home)

    queue = (
        f"---\ntitle: Review Queue\ntype: dashboard\ntags: [dashboard, review]\n"
        f"updated: {today.isoformat()}\n---\n\n"
        "# Review Queue — flagged low-confidence notes\n\n"
        "Notes where Claude flagged uncertainty instead of guessing (per the low-confidence\n"
        "rule in `skills/threat-analyst.md`). Review each, correct or confirm, then remove\n"
        "`flagged: true` from the note's frontmatter; the next run drops it from this list.\n\n"
        + "\n".join(flagged_lines)
        + "\n"
    )
    _write_atomic(vault_dir / "review-queue.md", queue)
