"""Read the audit log back: cost, outcomes, quarantine rate, feed activity.

Every enrichment already records total_cost_usd, per-attempt validation results,
and which reputation services answered — and nothing ever read any of it back.
The audit trail was write-only, which makes it evidence you can subpoena but not
evidence you can learn from.

The questions this answers are the ones you cannot otherwise ask:
  - what is this actually costing?
  - how often does the model fail validation on the first try?
  - is a feed quietly dead? (zero items for a week looks exactly like a quiet week)
  - how much is the reputation cache saving?

    python -m pipeline.stats            # last 30 days
    python -m pipeline.stats --days 7
"""

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

from . import config

log = logging.getLogger(__name__)


def load_records(audit_dir, days=30, today=None):
    """Audit records from the last `days` daily logs."""
    today = today or date.today()
    cutoff = today - timedelta(days=days)
    records = []
    for path in sorted(Path(audit_dir).glob("*.jsonl")):
        try:
            if date.fromisoformat(path.stem) < cutoff:
                continue
        except ValueError:
            continue  # not a daily log (e.g. a .corrupted-backup)
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                log.warning("skipping unparseable line in %s", path.name)
    return records


def _normalize(record):
    """Bring pre-`attempts[]` audit records up to the current shape.

    Records written before the attempts list existed carry a single flat
    attempt/engine/validation_ok and no outcome. They are real enrichments with
    real cost, so a summary that skipped them would under-report spend and file
    most of the history under "unknown" — a reporting tool that quietly ignores
    the majority of its input is worse than no tool.
    """
    if record.get("attempts") is not None and record.get("outcome"):
        return record
    r = dict(record)
    if r.get("attempts") is None:
        r["attempts"] = [{
            "attempt": r.get("attempt", 1),
            "engine": r.get("engine") or {},
            "validation_ok": r.get("validation_ok"),
            "validation_errors": r.get("validation_errors") or [],
        }] if ("engine" in r or "validation_ok" in r) else []
    if not r.get("outcome"):
        # Infer from what the record actually shows happened.
        if r.get("error"):
            r["outcome"] = "failed"
        elif r.get("note_path"):
            r["outcome"] = "written"
        elif r.get("quarantine_path"):
            r["outcome"] = "quarantined"
        else:
            r["outcome"] = "unknown"
    return r


def summarize(records):
    """Aggregate raw audit records into reportable numbers."""
    enrichments = [_normalize(r) for r in records if r.get("type") is None]
    outcomes = Counter(r.get("outcome", "unknown") for r in enrichments)
    by_source = Counter(r["source"] for r in enrichments if r.get("source"))

    cost = 0.0
    calls = 0
    first_try = 0
    retried = 0
    for r in enrichments:
        attempts = r.get("attempts") or []
        for a in attempts:
            calls += 1
            cost += (a.get("engine") or {}).get("total_cost_usd") or 0.0
        if attempts:
            if attempts[0].get("validation_ok"):
                first_try += 1
            elif len(attempts) > 1:
                retried += 1

    lookups = [x for r in enrichments for x in (r.get("reputation_lookups") or [])]
    by_service = Counter(x.get("service") for x in lookups if x.get("service"))
    cached = sum(1 for x in lookups if x.get("cached"))
    lookup_errors = sum(1 for x in lookups if x.get("error"))

    written = outcomes.get("written", 0)
    return {
        "enrichments": len(enrichments),
        "outcomes": dict(outcomes),
        "by_source": dict(by_source),
        "claude_calls": calls,
        "total_cost_usd": round(cost, 4),
        "cost_per_note": round(cost / written, 4) if written else None,
        "first_try_ok": first_try,
        "rescued_by_retry": retried,
        "quarantine_rate": _rate(outcomes.get("quarantined", 0), len(enrichments)),
        "failure_rate": _rate(outcomes.get("failed", 0), len(enrichments)),
        "reputation_lookups": len(lookups),
        "reputation_by_service": dict(by_service),
        "cache_hit_rate": _rate(cached, len(lookups)),
        "lookup_errors": lookup_errors,
        "weekly_reports": sum(1 for r in records if r.get("type") == "weekly_report"),
    }


def _rate(part, whole):
    return round(part / whole, 3) if whole else None


def format_report(summary, days):
    lines = [f"Audit summary — last {days} days", "=" * 34, ""]
    lines.append(f"enrichments        {summary['enrichments']}")
    for outcome, n in sorted(summary["outcomes"].items(), key=lambda kv: -kv[1]):
        lines.append(f"  {outcome:<17}{n}")
    lines.append("")
    lines.append(f"claude calls       {summary['claude_calls']}")
    lines.append(f"total cost         ${summary['total_cost_usd']:.2f}")
    if summary["cost_per_note"] is not None:
        lines.append(f"cost per note      ${summary['cost_per_note']:.2f}")
    lines.append("")
    lines.append(f"valid first try    {summary['first_try_ok']}")
    lines.append(f"rescued by retry   {summary['rescued_by_retry']}")
    if summary["quarantine_rate"] is not None:
        lines.append(f"quarantine rate    {summary['quarantine_rate']:.1%}")
        lines.append(f"failure rate       {summary['failure_rate']:.1%}")
    lines.append("")
    lines.append("items by source")
    for source, n in sorted(summary["by_source"].items(), key=lambda kv: -kv[1]) or []:
        lines.append(f"  {source:<17}{n}")
    if not summary["by_source"]:
        lines.append("  (none)")
    lines.append("")
    lines.append(f"reputation lookups {summary['reputation_lookups']}")
    for service, n in sorted(summary["reputation_by_service"].items(), key=lambda kv: -kv[1]):
        lines.append(f"  {service:<17}{n}")
    if summary["cache_hit_rate"] is not None:
        lines.append(f"  cache hit rate   {summary['cache_hit_rate']:.1%}")
    if summary["lookup_errors"]:
        lines.append(f"  lookup errors    {summary['lookup_errors']}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Summarize the audit trail")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    records = load_records(config.AUDIT_DIR, days=args.days)
    summary = summarize(records)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_report(summary, args.days))
    return 0


if __name__ == "__main__":
    sys.exit(main())
