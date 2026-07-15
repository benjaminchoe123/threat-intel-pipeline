"""Shared helpers for abuse.ch sources (ThreatFox, URLhaus).

Both feeds are high-volume IOC streams, so items are aggregated into one
normalized item per (malware family, day) with a bounded IOC sample.
"""

import hashlib
import json

IOC_SAMPLE_CAP = 50  # keep enrichment prompts bounded


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
