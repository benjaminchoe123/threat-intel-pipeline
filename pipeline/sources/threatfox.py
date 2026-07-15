"""abuse.ch ThreatFox — recent IOCs, aggregated per malware family per day."""

import logging
from datetime import date

from ..http import default_session
from .abusech import check_query_status, family_day_items

log = logging.getLogger(__name__)

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
PORTAL_URL = "https://threatfox.abuse.ch/"


def aggregate_threatfox(data, today=None):
    if not check_query_status(data, "threatfox"):
        return []
    today = today or date.today()
    day = today.isoformat()
    groups = {}
    for entry in data.get("data") or []:
        family = entry.get("malware_printable") or "unclassified"
        groups.setdefault(family, []).append(
            {
                "ioc": entry.get("ioc"),
                "ioc_type": entry.get("ioc_type"),
                "threat_type": entry.get("threat_type"),
                "confidence_level": entry.get("confidence_level"),
                "first_seen": entry.get("first_seen"),
                "reference": entry.get("reference"),
            }
        )
    return family_day_items(groups, "threatfox", day, PORTAL_URL)


def fetch(auth_key, today=None, session=None):
    if not auth_key:
        log.warning("threatfox: no ABUSECH_AUTH_KEY set — skipping (see .env.example)")
        return []
    http = session or default_session()
    resp = http.post(
        API_URL,
        json={"query": "get_iocs", "days": 1},
        headers={"Auth-Key": auth_key},
        timeout=60,
    )
    resp.raise_for_status()
    return aggregate_threatfox(resp.json(), today)
