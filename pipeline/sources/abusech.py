"""Shared helpers for abuse.ch sources (ThreatFox, URLhaus).

Both feeds are high-volume IOC streams, so items are aggregated into one
normalized item per (malware family, day) with a bounded IOC sample.
"""

import hashlib
import json

IOC_SAMPLE_CAP = 50  # keep enrichment prompts bounded


class FeedError(RuntimeError):
    """abuse.ch reported a problem in its response envelope."""


class FeedAuthError(FeedError):
    """The Auth-Key was missing, rejected, or expired."""


# abuse.ch answers HTTP 200 and puts the real outcome in query_status, so
# raise_for_status() never fires. Anything not listed here is treated as an error
# rather than an empty result: a feed that silently returns nothing is
# indistinguishable from a quiet day, which is the failure we cannot afford.
_AUTH_STATUSES = {"illegal_auth_key", "unauthorized", "auth_key_required"}
_EMPTY_STATUSES = {"no_result", "no_results"}


def check_query_status(data, feed):
    """Validate the envelope. Returns True if there is data, False if legitimately
    empty; raises FeedAuthError/FeedError otherwise."""
    status = str(data.get("query_status") or "").strip().lower()
    if not status:
        raise FeedError(f"{feed}: abuse.ch response had no query_status field")
    if status in _AUTH_STATUSES:
        raise FeedAuthError(
            f"{feed}: abuse.ch rejected the Auth-Key (query_status={status!r}) — "
            "check ABUSECH_AUTH_KEY in .env"
        )
    if status in _EMPTY_STATUSES:
        return False
    if status != "ok":
        raise FeedError(f"{feed}: abuse.ch returned query_status={status!r}")
    return True


def family_day_items(groups, source, day, url):
    items = []
    for family, iocs in sorted(groups.items()):
        raw = {
            "family": family,
            "day": day,
            "ioc_count": len(iocs),
            "iocs": iocs[:IOC_SAMPLE_CAP],
        }
        items.append(
            {
                "source": source,
                "external_id": f"{family}:{day}",
                "title": f"{family} — {len(iocs)} new IOC(s) on {day}",
                "url": url,
                "raw": raw,
                "content_hash": hashlib.sha256(
                    json.dumps(raw, sort_keys=True).encode("utf-8")
                ).hexdigest(),
            }
        )
    return items
