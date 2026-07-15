"""malware-traffic-analysis.net blog RSS — traffic-analysis writeups."""

import hashlib
import json
from datetime import date, timedelta

import feedparser
import requests

FEED_URL = "https://www.malware-traffic-analysis.net/blog-entries.rss"


def parse_mta(rss_text, lookback_days, today=None):
    today = today or date.today()
    feed = feedparser.parse(rss_text)
    items = []
    for entry in feed.entries:
        # The live feed is malformed XML; feedparser recovers but emits phantom
        # empty entries. No link = no identity = drop.
        if not entry.get("link"):
            continue
        published = None
        if getattr(entry, "published_parsed", None):
            t = entry.published_parsed
            published = date(t.tm_year, t.tm_mon, t.tm_mday)
        if lookback_days is not None and published is not None:
            if published < today - timedelta(days=lookback_days):
                continue
        raw = {
            "title": entry.get("title", ""),
            "link": entry.get("link", ""),
            "published": published.isoformat() if published else None,
            "summary": entry.get("summary", ""),
        }
        items.append(
            {
                "source": "mta",
                "external_id": raw["link"],
                "title": raw["title"],
                "url": raw["link"],
                "raw": raw,
                "content_hash": hashlib.sha256(
                    json.dumps(raw, sort_keys=True).encode("utf-8")
                ).hexdigest(),
            }
        )
    return items


def fetch(lookback_days, today=None, session=None):
    http = session or requests
    resp = http.get(FEED_URL, timeout=60)
    resp.raise_for_status()
    return parse_mta(resp.text, lookback_days, today)
