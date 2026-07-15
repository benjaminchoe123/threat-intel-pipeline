"""Daily pipeline entry point: fetch feeds -> dedupe -> enrich -> vault notes.

Usage:
  python -m pipeline.run                     # all configured sources
  python -m pipeline.run --source kev --limit 3
"""

import argparse
import json
import logging
import sys
import traceback
from datetime import date

from . import audit, config, enrich, notes, reputation
from .cache import ReputationCache
from .sources import kev, mta_rss, threatfox, urlhaus
from .state import State

log = logging.getLogger(__name__)

# Priority order: KEV first, then analysis writeups, then IOC clusters.
SOURCES = {
    "kev": lambda: kev.fetch(config.LOOKBACK_DAYS),
    "mta": lambda: mta_rss.fetch(config.LOOKBACK_DAYS),
    "threatfox": lambda: threatfox.fetch(config.ABUSECH_AUTH_KEY),
    "urlhaus": lambda: urlhaus.fetch(config.ABUSECH_AUTH_KEY),
}

# A quarantined item stays re-processable so a skill/validator fix can rescue it,
# but not forever — after this many failed runs it is marked seen and left alone.
MAX_QUARANTINE_ATTEMPTS = 3


def _utf8_stream():
    """Log to UTF-8 stdout.

    Windows stdout here is cp1252 even when redirected, and scripts/run_daily.ps1
    redirects. A ThreatFox family name or MTA title containing CJK, an em-dash, or
    an emoji therefore crashed the run on the log line itself — before enrichment,
    with nothing written anywhere.
    """
    stream = sys.stdout
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass  # not a real tty (pytest capture); the default is fine
    return stream


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


def process_item(item, state, skill_text, today, runner=None, reputation_fn=None):
    """Enrich one new item into a vault note.

    Returns 'written', 'quarantined', or 'failed'. Never raises: an item that
    blows up must not take the rest of the run with it. The audit record is
    written in a finally, so a `claude` call that was made and billed always
    leaves a trace — including when it is the thing that threw.

    runner/reputation_fn resolve at call time, not as default arguments: bound as
    defaults they captured the real `claude -p` at import, so monkeypatching the
    module attribute silently had no effect and tests billed live API calls.
    """
    runner = runner or enrich.run_claude
    reputation_fn = reputation_fn or reputation.default_reputation
    record = {
        "source": item["source"],
        "external_id": item["external_id"],
        "content_hash": item["content_hash"],
        "attempts": [],
    }
    outcome, ok = "failed", False
    try:
        record["raw_snapshot"] = str(_save_raw(item))
        reputation_block, reputation_lookups = reputation_fn(item)
        if reputation_lookups:
            record["reputation_lookups"] = reputation_lookups

        prompt = enrich.build_prompt(item, skill_text, today, reputation=reputation_block)
        note_text, errors, meta = "", ["not run"], {}
        for attempt in (1, 2):
            note_text, engine_meta = runner(prompt)
            ok, errors, meta = enrich.validate_note(note_text)
            record["attempts"].append({
                "attempt": attempt, "engine": engine_meta, "validation_ok": ok,
                "validation_errors": errors, "claude_output": note_text,
            })
            if ok:
                break
            prompt = enrich.build_retry_prompt(prompt, errors)

        record["validation_ok"] = ok
        if ok:
            record["note_path"] = str(notes.write_threat_note(config.VAULT_DIR, meta))
            notes.ensure_stubs(config.VAULT_DIR, meta)
            outcome = "written"
        else:
            record["quarantine_path"] = str(_quarantine(item, note_text, errors))
            outcome = "quarantined"
    except Exception as e:
        record["error"] = str(e)
        record["error_type"] = type(e).__name__
        record["traceback"] = traceback.format_exc()
        log.exception("enrichment failed for %s:%s", item["source"], item["external_id"])
        outcome = "failed"
    finally:
        record["outcome"] = outcome
        audit.log_enrichment(config.AUDIT_DIR, record)

    _update_state(item, state, outcome)
    return outcome


def _update_state(item, state, outcome):
    """Mark an item seen only once there is nothing more to try.

    'failed' is transient (network, timeout) and 'quarantined' may be rescued by
    a skill or validator fix, so neither is recorded — both carry over to the next
    run. Previously every outcome was recorded, which made quarantine a dead end.
    """
    source, ext, digest = item["source"], item["external_id"], item["content_hash"]
    if outcome == "written":
        state.record(source, ext, digest)
        return
    if outcome == "quarantined":
        attempts = state.record_quarantine(source, ext)
        if attempts >= MAX_QUARANTINE_ATTEMPTS:
            log.warning("%s:%s quarantined %d times — giving up", source, ext, attempts)
            state.record(source, ext, digest)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Threat intel daily run")
    parser.add_argument("--source", choices=sorted(SOURCES), default=None)
    parser.add_argument("--limit", type=int, default=config.MAX_ENRICH_PER_RUN)
    args = parser.parse_args(argv)

    skill_text = config.SKILL_FILE.read_text(encoding="utf-8")
    today = date.today().isoformat()
    sources = [args.source] if args.source else list(SOURCES)  # dict order = priority

    totals = {"written": 0, "quarantined": 0, "seen": 0, "updated": 0, "failed": 0}
    enriched = 0
    with State(config.STATE_DB) as state, ReputationCache(config.STATE_DB) as rep_cache:
        reputation_fn = lambda item: reputation.default_reputation(item, cache=rep_cache)  # noqa: E731
        for name in sources:
            if enriched >= args.limit:
                break  # cap already hit: don't pay the HTTP cost of more feeds
            try:
                items = list(SOURCES[name]())
            except Exception:
                # One feed being down must not cost us the others: KEV is first in
                # SOURCES, so a CISA 5xx used to mean nothing else ran that day.
                log.exception("source %s failed to fetch — skipping", name)
                totals["failed"] += 1
                continue

            for item in items:
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
                    log.info("enrichment cap (%d) reached — remaining items carry over",
                             args.limit)
                    break
                log.info("enriching %s:%s — %s", item["source"], item["external_id"],
                         item["title"])
                totals[process_item(item, state, skill_text, today,
                                    reputation_fn=reputation_fn)] += 1
                enriched += 1

    notes.update_dashboards(config.VAULT_DIR)
    log.info("done: %s", totals)
    return totals


def cli(argv=None):
    """Entry point: exit non-zero if anything failed, so the scheduler can tell.

    main() used to return totals that __main__ discarded, so the process exited 0
    even when every item failed — a broken run looked exactly like a quiet day.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=_utf8_stream(),
    )
    totals = main(argv)
    sys.exit(1 if totals["failed"] else 0)


if __name__ == "__main__":
    cli()
