"""CISA Known Exploited Vulnerabilities catalog.

parse_kev() is pure (unit-tested); fetch() does the HTTP call.
"""

import hashlib
import json
import logging
from datetime import date, timedelta

from ..http import default_session

FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

log = logging.getLogger(__name__)


def parse_kev(data, lookback_days, today=None):
    """Normalize the CISA catalog. Entries that don't parse are skipped, not fatal.

    vuln["dateAdded"] / vuln["cveID"] were unguarded and date.fromisoformat was
    called on whatever was there, so a single entry CISA published with a typo
    raised straight out of the parser and cost every KEV item that day.
    """
    today = today or date.today()
    items = []
    for vuln in data.get("vulnerabilities", []):
        item = _parse_entry(vuln, lookback_days, today)
        if item is not None:
            items.append(item)
    return items


def _parse_entry(vuln, lookback_days, today):
    """One catalog entry -> normalized item, or None if unusable."""
    if not isinstance(vuln, dict):
        log.warning("kev: skipping non-object entry %.60r", vuln)
        return None
    cve_id = vuln.get("cveID")
    if not cve_id:
        log.warning("kev: skipping entry with no cveID: %.80r", vuln)
        return None
    if lookback_days is not None:
        raw_date = vuln.get("dateAdded")
        try:
            added = date.fromisoformat(str(raw_date))
        except (TypeError, ValueError):
            log.warning("kev: %s has unparseable dateAdded %r — skipping", cve_id, raw_date)
            return None
        if added < today - timedelta(days=lookback_days):
            return None
    return {
        "source": "kev",
        "external_id": cve_id,
        "title": vuln.get("vulnerabilityName") or cve_id,
        "url": CATALOG_URL,
        "raw": vuln,
        "content_hash": hashlib.sha256(
            json.dumps(vuln, sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }


def fetch(lookback_days, today=None, session=None):
    http = session or default_session()
    resp = http.get(FEED_URL, timeout=60)
    resp.raise_for_status()
    return parse_kev(resp.json(), lookback_days, today)
