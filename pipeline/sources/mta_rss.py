"""malware-traffic-analysis.net blog RSS — traffic-analysis writeups."""

import hashlib
import json
import logging
import re
from datetime import date, timedelta

import feedparser

from ..http import default_session

FEED_URL = "https://www.malware-traffic-analysis.net/blog-entries.rss"

log = logging.getLogger(__name__)

# MTA posts live at /YYYY/MM/DD/index.html and title themselves "YYYY-MM-DD - ...",
# so a missing pubDate is recoverable from either.
_URL_DATE = re.compile(r"/(\d{4})/(\d{2})/(\d{2})/")
_TITLE_DATE = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})")


def _entry_date(entry):
    """Publish date, falling back to the URL then the title.

    pubDate alone is not enough: this feed goes malformed (see below), and when
    it does the dates are what go missing — exactly when the lookback stops
    filtering. Dropping undated entries isn't the answer either; that would lose
    real writeups in precisely the case the pipeline exists to survive. The date
    is in the URL, so recover it instead of choosing between stale and lost.
    """
    if getattr(entry, "published_parsed", None):
        t = entry.published_parsed
        return date(t.tm_year, t.tm_mon, t.tm_mday)
    for pattern, text in ((_URL_DATE, entry.get("link", "")),
                          (_TITLE_DATE, entry.get("title", ""))):
        match = pattern.search(str(text))
        if match:
            try:
                return date(*(int(g) for g in match.groups()))
            except ValueError:
                continue  # e.g. /2026/13/45/ — not a real date
    log.warning("mta: %r has no usable date — keeping it rather than dropping a "
                "possibly-real writeup", str(entry.get("title", ""))[:60])
    return None


def parse_mta(rss_text, lookback_days, today=None):
    today = today or date.today()
    feed = feedparser.parse(rss_text)
    items = []
    for entry in feed.entries:
        # The live feed is malformed XML; feedparser recovers but emits phantom
        # empty entries. No link = no identity = drop.
        if not entry.get("link"):
            continue
        published = _entry_date(entry)
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
    http = session or default_session()
    resp = http.get(FEED_URL, timeout=60)
    resp.raise_for_status()
    return parse_mta(resp.text, lookback_days, today)
