"""VirusTotal reputation lookups for IOC-bearing feed items.

Free tier limits: 4 lookups/min, 500/day — so lookups are capped per item and
paced between requests. Items without a structured IOC sample (KEV, MTA RSS)
are skipped entirely.
"""

import base64
import logging
import time

import requests

from .ratelimit import RateLimiter

log = logging.getLogger(__name__)

API_BASE = "https://www.virustotal.com/api/v3"
MAX_LOOKUPS_PER_ITEM = 4
SECONDS_BETWEEN_LOOKUPS = 15  # free tier: 4 requests/minute

# Module-level so pacing spans items for the life of the process, not just the
# lookups inside one item.
LIMITER = RateLimiter(SECONDS_BETWEEN_LOOKUPS)

_ENDPOINTS = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "file": "files"}


class VirusTotalError(RuntimeError):
    """VirusTotal returned an unusable response."""


class RateLimitError(VirusTotalError):
    """VirusTotal rejected the request for quota reasons (HTTP 429).

    Distinct from other errors because it is expected, transient, and says
    something specific about how to back off.
    """

    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after

_KIND_BY_IOC_TYPE = {
    "ip": "ip",
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "file",
    "sha1_hash": "file",
    "sha256_hash": "file",
}


def extract_iocs(item, limit=MAX_LOOKUPS_PER_ITEM):
    """Normalize an item's IOC sample to unique (kind, value) pairs.

    limit=None returns every pair. AbuseIPDB needs that: it filters to IPs, and
    sharing VirusTotal's already-truncated list meant an item whose first four
    IOCs were domains got no IP checks at all, despite a far looser quota.
    """
    pairs = []
    for entry in item.get("raw", {}).get("iocs") or []:
        kind = _KIND_BY_IOC_TYPE.get(entry.get("ioc_type"))
        value = entry.get("ioc")
        if not kind or not value:
            continue
        if entry.get("ioc_type") == "ip:port":
            value = _strip_port(value)
        pair = (kind, value)
        if pair not in pairs:
            pairs.append(pair)
        if limit is not None and len(pairs) == limit:
            break
    return pairs


def _strip_port(value):
    """'1.2.3.4:443' -> '1.2.3.4'; '[::1]:443' -> '::1'; bare IPv6 left alone.

    Splitting unconditionally on the last colon mangled unbracketed IPv6 into a
    garbage identifier, which VT answered with a 400 that killed the run.
    """
    if value.startswith("["):
        host, sep, _ = value.partition("]")
        return host[1:] if sep else value
    if value.count(":") > 1:
        return value  # bare IPv6, no port to strip
    return value.rsplit(":", 1)[0]


def lookup(kind, value, api_key, session=None, timeout=30):
    """Fetch VirusTotal engine verdict counts for one IOC."""
    http = session or requests
    ident = value
    if kind == "url":
        # VT identifies URLs by unpadded URL-safe base64 of the URL itself.
        ident = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
    resp = http.get(
        f"{API_BASE}/{_ENDPOINTS[kind]}/{ident}",
        headers={"x-apikey": api_key},
        timeout=timeout,
    )
    if resp.status_code == 404:
        return {"found": False}
    if resp.status_code == 429:
        raise RateLimitError(
            f"VirusTotal returned 429 for {kind} {value!r} — free tier quota exhausted",
            retry_after=_retry_after(resp),
        )
    if resp.status_code != 200:
        raise VirusTotalError(f"VirusTotal returned {resp.status_code} for {kind} {value!r}")
    try:
        stats = resp.json()["data"]["attributes"].get("last_analysis_stats", {})
    except (ValueError, KeyError, TypeError) as e:
        # A 200 carrying an HTML error/captcha page used to raise a bare
        # KeyError/JSONDecodeError straight out of the run.
        raise VirusTotalError(f"VirusTotal sent an unreadable 200 for {kind} {value!r}: {e}")
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def _retry_after(resp):
    """Seconds to wait, per the Retry-After header, if the server sent one."""
    raw = getattr(resp, "headers", {}) or {}
    try:
        return int(raw.get("Retry-After"))
    except (TypeError, ValueError):
        return None


def _format_line(result):
    if not result["found"]:
        return f"- {result['ioc']} ({result['kind']}): not found on VirusTotal"
    return (
        f"- {result['ioc']} ({result['kind']}): {result['malicious']} malicious, "
        f"{result['suspicious']} suspicious, {result['harmless']} harmless, "
        f"{result['undetected']} undetected"
    )


def reputation_for_item(item, api_key, session=None, sleep=None, cache=None, limiter=None):
    """Look up an item's IOC sample. Returns (prompt_block, results), (None, []) if n/a.

    A cache hit costs neither quota nor a pacing delay, so the limiter only ever
    throttles genuinely new IOCs.
    """
    if not api_key:
        return None, []
    pairs = extract_iocs(item)
    if not pairs:
        return None, []
    if limiter is None:
        limiter = RateLimiter(SECONDS_BETWEEN_LOOKUPS, sleep=sleep) if sleep else LIMITER

    results = []
    for kind, value in pairs:
        cached = cache.get("virustotal", value) if cache else None
        if cached is not None:
            log.debug("virustotal cache hit for %s", value)
            results.append({"service": "virustotal", "kind": kind, "ioc": value,
                            "cached": True, **cached})
            continue
        limiter.wait()
        data = lookup(kind, value, api_key, session)
        if cache:
            cache.put("virustotal", value, data)
        results.append({"service": "virustotal", "kind": kind, "ioc": value, **data})
    return "\n".join(_format_line(r) for r in results), results
