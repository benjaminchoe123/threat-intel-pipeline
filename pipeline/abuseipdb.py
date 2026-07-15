"""AbuseIPDB community abuse-report scores for IP IOCs.

Free tier: 1,000 checks/day. Only IPs are checkable, so non-IP IOCs in an
item's sample are ignored here (VirusTotal covers those).
"""

import requests

from .vt import extract_iocs

API_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90


def check(ip, api_key, session=None, timeout=30):
    """Fetch the abuse confidence score (0-100) and report count for one IP."""
    http = session or requests
    resp = http.get(
        API_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS},
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"AbuseIPDB returned {resp.status_code} for {ip!r}")
    data = resp.json()["data"]
    return {"score": data.get("abuseConfidenceScore", 0), "reports": data.get("totalReports", 0)}


def block_for_item(item, api_key, session=None):
    """Check an item's IP IOCs. Returns (prompt_block, results), (None, []) if n/a."""
    if not api_key:
        return None, []
    ips = [value for kind, value in extract_iocs(item) if kind == "ip"]
    if not ips:
        return None, []
    results = []
    for ip in ips:
        results.append({"service": "abuseipdb", "ioc": ip, **check(ip, api_key, session)})
    block = "\n".join(
        f"- {r['ioc']}: abuse confidence {r['score']}%, "
        f"{r['reports']} report(s) in the last {MAX_AGE_DAYS} days"
        for r in results
    )
    return block, results
