"""GreyNoise Community API: is this IP targeted activity or internet background noise?

GreyNoise answers a question the other sources cannot. VirusTotal and AbuseIPDB
both say "is this IP bad?"; GreyNoise says "is this IP spraying the entire
internet?". An IP with a high abuse score that GreyNoise classifies as a mass
scanner is noise — worth far less analyst attention than a quiet IP hosting
dedicated C2 infrastructure, even though the abuse score alone would rank the
scanner higher.

It also identifies benign scanners (Shodan, Censys, security researchers) by
name, which is the single most common false positive in IP-based triage.

Free tier, requires GREYNOISE_API_KEY in .env; like every other key, absent just
disables the lookup.
"""

import logging

from .http import default_session
from .ratelimit import RateLimiter
from .vt import extract_iocs

log = logging.getLogger(__name__)

API_URL = "https://api.greynoise.io/v3/community/"
MAX_IPS_PER_ITEM = 4
SECONDS_BETWEEN_LOOKUPS = 2  # community tier is modest; be polite

LIMITER = RateLimiter(SECONDS_BETWEEN_LOOKUPS)


class GreyNoiseError(RuntimeError):
    """GreyNoise returned an unusable response."""


class RateLimitError(GreyNoiseError):
    """GreyNoise rejected the request for quota reasons (HTTP 429)."""


def extract_ips(item, limit=MAX_IPS_PER_ITEM):
    ips = [value for kind, value in extract_iocs(item, limit=None) if kind == "ip"]
    return ips[:limit] if limit is not None else ips


def check(ip, api_key, session=None, timeout=30):
    """Classification for one IP. 404 means "not seen", which is meaningful here."""
    http = session or default_session()
    resp = http.get(f"{API_URL}{ip}", headers={"key": api_key, "Accept": "application/json"},
                    timeout=timeout)
    if resp.status_code == 404:
        # Not in GreyNoise: the IP is not mass-scanning. For C2 infrastructure
        # that is the expected — and mildly corroborating — answer.
        return {"seen": False}
    if resp.status_code == 429:
        raise RateLimitError(f"GreyNoise returned 429 for {ip!r} — quota exhausted")
    if resp.status_code != 200:
        raise GreyNoiseError(f"GreyNoise returned {resp.status_code} for {ip!r}")
    try:
        data = resp.json()
    except ValueError as e:
        raise GreyNoiseError(f"GreyNoise sent an unreadable 200 for {ip!r}: {e}") from e
    return {
        "seen": bool(data.get("seen", False)),
        "classification": data.get("classification"),
        "name": data.get("name"),
        "last_seen": data.get("last_seen"),
    }


def _format_line(result):
    ip = result["ioc"]
    if not result.get("seen"):
        return (f"- {ip}: not observed scanning the internet by GreyNoise — consistent "
                "with dedicated infrastructure rather than a mass scanner (not a verdict "
                "on whether it is malicious)")
    classification = result.get("classification") or "unknown"
    name = result.get("name") or "unattributed"
    meaning = {
        "benign": "a known-benign scanner — almost certainly a false positive if flagged elsewhere",
        "malicious": "an opportunistic mass scanner — noisy, not necessarily targeting anyone",
        "unknown": "an internet-wide scanner of unknown intent",
    }.get(classification, "classified by GreyNoise")
    return (f"- {ip}: seen mass-scanning the internet, classified {classification!r} "
            f"({name}) — {meaning}")


def block_for_item(item, api_key, session=None, cache=None, limiter=None):
    """GreyNoise context for an item's IP IOCs. Returns (prompt_block, results)."""
    if not api_key:
        return None, []
    ips = extract_ips(item)
    if not ips:
        return None, []
    limiter = limiter or LIMITER

    results = []
    for ip in ips:
        cached = cache.get("greynoise", ip) if cache else None
        if cached is not None:
            log.debug("greynoise cache hit for %s", ip)
            results.append({"service": "greynoise", "ioc": ip, "cached": True, **cached})
            continue
        limiter.wait()
        data = check(ip, api_key, session)
        if cache:
            cache.put("greynoise", ip, data)
        results.append({"service": "greynoise", "ioc": ip, **data})

    return "\n".join(_format_line(r) for r in results), results
