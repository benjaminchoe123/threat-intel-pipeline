"""Write validated enrichment notes into the Obsidian vault and maintain
stub pages for families / ATT&CK techniques / actors so wikilinks resolve
and the graph view shows relationships."""

import hashlib
import os
import re
from datetime import date, timedelta
from pathlib import Path

import yaml

_UNSAFE = re.compile(r'[/\\:*?"<>|#^\[\]]+')

FALLBACK_SLUG = "untitled"
MAX_SLUG_LEN = 80  # keep full paths clear of Windows' MAX_PATH

# Reserved on Windows regardless of extension: CON.md cannot be created.
_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{n}" for n in range(1, 10)),
    *(f"LPT{n}" for n in range(1, 10)),
}


def slugify(title):
    """Filesystem-safe slug. Never empty, never a Windows reserved name.

    slugify("") returned "" — which produced data/raw/mta/.json, a single file
    every empty-id item collided on (confirmed in the live audit log).
    """
    slug = _UNSAFE.sub(" ", str(title))
    slug = re.sub(r"\s+", "-", slug.strip())
    slug = re.sub(r"-{2,}", "-", slug)
    if len(slug) > MAX_SLUG_LEN:
        slug = slug[:MAX_SLUG_LEN].rstrip("-")
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


def _technique_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/")


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
            ("techniques", tid, f"MITRE ATT&CK: {_technique_url(tid)}\n\n")
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


def update_dashboards(vault_dir, today=None):
    """Regenerate home.md and review-queue.md from vault contents."""
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
        "Auto-generated each pipeline run. Do not hand-edit — see `pipeline/notes.py`.\n\n"
        "## Last 7 days\n\n" + "\n".join(recent_lines) + "\n\n"
        f"## Review queue\n\nSee [[review-queue]] — {len(flagged)} flagged item(s).\n\n"
        "## Stats\n\n"
        "| metric | value |\n|---|---|\n"
        f"| total threat notes | {len(threats)} |\n"
        f"| malware families tracked | {count('families')} |\n"
        f"| ATT&CK techniques seen | {count('techniques')} |\n"
        f"| last run | {today.isoformat()} |\n"
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
