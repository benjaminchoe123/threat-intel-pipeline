"""Daily pipeline entry point: fetch feeds -> dedupe -> enrich -> vault notes.

Usage:
  python -m pipeline.run                     # all configured sources
  python -m pipeline.run --source kev --limit 3
"""

import argparse
import json
from datetime import date

from . import audit, config, enrich, notes, reputation
from .sources import kev, mta_rss, threatfox, urlhaus
from .state import State

# Priority order: KEV first, then analysis writeups, then IOC clusters.
SOURCES = {
    "kev": lambda: kev.fetch(config.LOOKBACK_DAYS),
    "mta": lambda: mta_rss.fetch(config.LOOKBACK_DAYS),
    "threatfox": lambda: threatfox.fetch(config.ABUSECH_AUTH_KEY),
    "urlhaus": lambda: urlhaus.fetch(config.ABUSECH_AUTH_KEY),
}


def _save_raw(item):
    raw_dir = config.RAW_DIR / item["source"]
    raw_dir.mkdir(parents=True, exist_ok=True)
    path = raw_dir / f"{notes.slugify(item['external_id'])}.json"
    path.write_text(json.dumps(item["raw"], indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _quarantine(item, note_text, errors):
    config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    path = config.QUARANTINE_DIR / f"{notes.slugify(item['external_id'])}.md"
    path.write_text(
        f"<!-- validation errors: {errors} -->\n{note_text}", encoding="utf-8"
    )
    return path


def process_item(item, state, skill_text, today, runner=enrich.run_claude,
                 reputation_fn=reputation.default_reputation):
    """Enrich one new item into a vault note. Returns 'written' or 'quarantined'."""
    raw_path = _save_raw(item)
    reputation_block, reputation_lookups = reputation_fn(item)
    prompt = enrich.build_prompt(item, skill_text, today, reputation=reputation_block)
    record = {
        "source": item["source"],
        "external_id": item["external_id"],
        "content_hash": item["content_hash"],
        "raw_snapshot": str(raw_path),
    }
    if reputation_lookups:
        record["reputation_lookups"] = reputation_lookups

    note_text, engine_meta, ok, errors, meta = "", {}, False, ["not run"], {}
    for attempt in (1, 2):  # one retry on validation failure
        note_text, engine_meta = runner(prompt)
        ok, errors, meta = enrich.validate_note(note_text)
        record.update(
            {"attempt": attempt, "engine": engine_meta, "validation_ok": ok,
             "validation_errors": errors, "claude_output": note_text}
        )
        if ok:
            break

    if ok:
        note_path = notes.write_threat_note(config.VAULT_DIR, meta)
        notes.ensure_stubs(config.VAULT_DIR, meta)
        record["note_path"] = str(note_path)
        outcome = "written"
    else:
        record["quarantine_path"] = str(_quarantine(item, note_text, errors))
        outcome = "quarantined"

    audit.log_enrichment(config.AUDIT_DIR, record)
    state.record(item["source"], item["external_id"], item["content_hash"])
    return outcome


def main(argv=None):
    parser = argparse.ArgumentParser(description="Threat intel daily run")
    parser.add_argument("--source", choices=sorted(SOURCES), default=None)
    parser.add_argument("--limit", type=int, default=config.MAX_ENRICH_PER_RUN)
    args = parser.parse_args(argv)

    skill_text = config.SKILL_FILE.read_text(encoding="utf-8")
    state = State(config.STATE_DB)
    today = date.today().isoformat()
    sources = [args.source] if args.source else list(SOURCES)  # dict order = priority

    totals = {"written": 0, "quarantined": 0, "seen": 0, "updated": 0}
    enriched = 0
    for name in sources:
        for item in SOURCES[name]():
            status = state.check(item["source"], item["external_id"], item["content_hash"])
            if status == "seen":
                totals["seen"] += 1
                continue
            if status == "updated":
                # Source edited an existing entry — record it, skip re-enrichment for now.
                state.record(item["source"], item["external_id"], item["content_hash"])
                totals["updated"] += 1
                continue
            if enriched >= args.limit:
                print(f"enrichment cap ({args.limit}) reached — remaining items carry over")
                break
            print(f"enriching {item['source']}:{item['external_id']} — {item['title']}")
            totals[process_item(item, state, skill_text, today)] += 1
            enriched += 1

    notes.update_dashboards(config.VAULT_DIR)
    print(f"done: {totals}")
    return totals


if __name__ == "__main__":
    main()
