"""CISA Known Exploited Vulnerabilities catalog.

parse_kev() is pure (unit-tested); fetch() does the HTTP call.
"""

import hashlib
import json
from datetime import date, timedelta

import requests

FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def parse_kev(data, lookback_days, today=None):
    today = today or date.today()
    items = []
    for vuln in data.get("vulnerabilities", []):
        if lookback_days is not None:
            added = date.fromisoformat(vuln["dateAdded"])
            if added < today - timedelta(days=lookback_days):
                continue
        items.append(
            {
                "source": "kev",
                "external_id": vuln["cveID"],
                "title": vuln.get("vulnerabilityName") or vuln["cveID"],
                "url": CATALOG_URL,
                "raw": vuln,
                "content_hash": hashlib.sha256(
                    json.dumps(vuln, sort_keys=True).encode("utf-8")
                ).hexdigest(),
            }
        )
    return items


def fetch(lookback_days, today=None, session=None):
    http = session or requests
    resp = http.get(FEED_URL, timeout=60)
    resp.raise_for_status()
    return parse_kev(resp.json(), lookback_days, today)
