"""AbuseIPDB community abuse-report scores for IP IOCs.

Free tier: 1,000 checks/day. Only IPs are checkable, so non-IP IOCs in an
item's sample are ignored here (VirusTotal covers those).
"""

import logging

from .http import default_session
from .ratelimit import RateLimiter
from .vt import extract_iocs

log = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90
MAX_IPS_PER_ITEM = 4
SECONDS_BETWEEN_LOOKUPS = 1  # 1,000/day is generous; this is politeness, not quota

# Module-level so pacing spans items, like VirusTotal's.
LIMITER = RateLimiter(SECONDS_BETWEEN_LOOKUPS)


class AbuseIPDBError(RuntimeError):
    """AbuseIPDB returned an unusable response."""


class RateLimitError(AbuseIPDBError):
    """AbuseIPDB rejected the request for quota reasons (HTTP 429)."""

    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after


def extract_ips(item, limit=MAX_IPS_PER_ITEM):
    """IP IOCs from the item's full sample.

    Deliberately not reusing VirusTotal's capped list: that truncated to 4 before
    filtering by kind, so an item whose first 4 IOCs were domains yielded no IPs.
    """
    ips = [value for kind, value in extract_iocs(item, limit=None) if kind == "ip"]
    return ips[:limit] if limit is not None else ips


def check(ip, api_key, session=None, timeout=30):
    """Fetch the abuse confidence score (0-100) and report count for one IP."""
    http = session or default_session()
    resp = http.get(
        API_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS},
        timeout=timeout,
    )
    if resp.status_code == 429:
        raise RateLimitError(
            f"AbuseIPDB returned 429 for {ip!r} — daily quota exhausted",
            retry_after=_retry_after(resp),
        )
    if resp.status_code != 200:
        raise AbuseIPDBError(f"AbuseIPDB returned {resp.status_code} for {ip!r}")
    try:
        data = resp.json()["data"]
    except (ValueError, KeyError, TypeError) as e:
        raise AbuseIPDBError(f"AbuseIPDB sent an unreadable 200 for {ip!r}: {e}") from e
    return {"score": data.get("abuseConfidenceScore", 0), "reports": data.get("totalReports", 0)}


def _retry_after(resp):
    raw = getattr(resp, "headers", {}) or {}
    try:
        return int(raw.get("Retry-After"))
    except (TypeError, ValueError):
        return None


def block_for_item(item, api_key, session=None, cache=None, limiter=None):
    """Check an item's IP IOCs. Returns (prompt_block, results), (None, []) if n/a."""
    if not api_key:
        return None, []
    ips = extract_ips(item)
    if not ips:
        return None, []
    limiter = limiter or LIMITER

    results = []
    for ip in ips:
        cached = cache.get("abuseipdb", ip) if cache else None
        if cached is not None:
            log.debug("abuseipdb cache hit for %s", ip)
            results.append({"service": "abuseipdb", "ioc": ip, "cached": True, **cached})
            continue
        limiter.wait()
        data = check(ip, api_key, session)
        if cache:
            cache.put("abuseipdb", ip, data)
        results.append({"service": "abuseipdb", "ioc": ip, **data})

    block = "\n".join(
        f"- {r['ioc']}: abuse confidence {r['score']}%, "
        f"{r['reports']} report(s) in the last {MAX_AGE_DAYS} days"
        for r in results
    )
    return block, results
