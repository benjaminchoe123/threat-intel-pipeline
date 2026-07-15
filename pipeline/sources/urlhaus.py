"""abuse.ch URLhaus — recent malware-distribution URLs, aggregated per family
(first tag) per day."""

from datetime import date

import requests

from .abusech import family_day_items

API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
PORTAL_URL = "https://urlhaus.abuse.ch/"


def aggregate_urlhaus(data, today=None):
    today = today or date.today()
    day = today.isoformat()
    groups = {}
    for entry in data.get("urls") or []:
        tags = entry.get("tags") or []
        family = tags[0] if tags else "unclassified"
        groups.setdefault(family, []).append(
            {
                "ioc": entry.get("url"),
                "ioc_type": "url",
                "threat_type": entry.get("threat"),
                "url_status": entry.get("url_status"),
                "first_seen": entry.get("date_added"),
                "tags": tags,
            }
        )
    return family_day_items(groups, "urlhaus", day, PORTAL_URL)


def fetch(auth_key, today=None, session=None):
    if not auth_key:
        print("urlhaus: no ABUSECH_AUTH_KEY set — skipping (see .env.example)")
        return []
    http = session or requests
    resp = http.get(API_URL, headers={"Auth-Key": auth_key}, timeout=60)
    resp.raise_for_status()
    return aggregate_urlhaus(resp.json(), today)
