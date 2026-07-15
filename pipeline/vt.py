"""VirusTotal reputation lookups for IOC-bearing feed items.

Free tier limits: 4 lookups/min, 500/day — so lookups are capped per item and
paced between requests. Items without a structured IOC sample (KEV, MTA RSS)
are skipped entirely.
"""

import base64
import time

import requests

API_BASE = "https://www.virustotal.com/api/v3"
MAX_LOOKUPS_PER_ITEM = 4
SECONDS_BETWEEN_LOOKUPS = 15  # free tier: 4 requests/minute

_ENDPOINTS = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "file": "files"}

_KIND_BY_IOC_TYPE = {
    "ip": "ip",
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "file",
    "sha1_hash": "file",
    "sha256_hash": "file",
}


def extract_iocs(item):
    """Normalize an item's IOC sample to unique (kind, value) pairs, capped."""
    pairs = []
    for entry in item.get("raw", {}).get("iocs") or []:
        kind = _KIND_BY_IOC_TYPE.get(entry.get("ioc_type"))
        value = entry.get("ioc")
        if not kind or not value:
            continue
        if entry.get("ioc_type") == "ip:port":
            value = value.rsplit(":", 1)[0]
        pair = (kind, value)
        if pair not in pairs:
            pairs.append(pair)
        if len(pairs) == MAX_LOOKUPS_PER_ITEM:
            break
    return pairs


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
    if resp.status_code != 200:
        raise RuntimeError(f"VirusTotal returned {resp.status_code} for {kind} {value!r}")
    stats = resp.json()["data"]["attributes"].get("last_analysis_stats", {})
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def _format_line(result):
    if not result["found"]:
        return f"- {result['ioc']} ({result['kind']}): not found on VirusTotal"
    return (
        f"- {result['ioc']} ({result['kind']}): {result['malicious']} malicious, "
        f"{result['suspicious']} suspicious, {result['harmless']} harmless, "
        f"{result['undetected']} undetected"
    )


def reputation_for_item(item, api_key, session=None, sleep=time.sleep):
    """Look up an item's IOC sample. Returns (prompt_block, results), (None, []) if n/a."""
    if not api_key:
        return None, []
    pairs = extract_iocs(item)
    if not pairs:
        return None, []
    results = []
    for i, (kind, value) in enumerate(pairs):
        if i:
            sleep(SECONDS_BETWEEN_LOOKUPS)
        results.append({"service": "virustotal", "kind": kind, "ioc": value,
                        **lookup(kind, value, api_key, session)})
    return "\n".join(_format_line(r) for r in results), results
