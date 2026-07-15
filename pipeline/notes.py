"""Write validated enrichment notes into the Obsidian vault and maintain
stub pages for families / ATT&CK techniques / actors so wikilinks resolve
and the graph view shows relationships."""

import re
from datetime import date, timedelta
from pathlib import Path

import yaml

_UNSAFE = re.compile(r'[/\\:*?"<>|#^\[\]]+')


def slugify(title):
    slug = _UNSAFE.sub(" ", title)
    slug = re.sub(r"\s+", "-", slug.strip())
    return re.sub(r"-{2,}", "-", slug)


def write_threat_note(vault_dir, meta):
    vault_dir = Path(vault_dir)
    note_date = meta.get("date") or date.today().isoformat()
    path = vault_dir / "threats" / f"{note_date}-{slugify(meta['title'])}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(meta["_body"], encoding="utf-8")
    return path


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
        # Stub filename must equal the wikilink text ([[families/Lumma Stealer]]),
        # so keep spaces — only strip characters Windows/Obsidian forbid.
        safe_name = re.sub(r"\s+", " ", _UNSAFE.sub("", name)).strip()
        path = vault_dir / folder / f"{safe_name}.md"
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        kind = folder.rstrip("s")  # families -> familie… use explicit map below
        kind = {"families": "family", "techniques": "technique", "actors": "actor"}[folder]
        path.write_text(_stub(name, kind, extra), encoding="utf-8")
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
    (vault_dir / "home.md").write_text(home, encoding="utf-8")

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
    (vault_dir / "review-queue.md").write_text(queue, encoding="utf-8")
