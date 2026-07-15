"""Combined IOC reputation context: VirusTotal + AbuseIPDB per item."""

from . import abuseipdb, vt


def reputation_for_item(item, vt_fn, abuse_fn):
    """Compose per-service blocks into one prompt block and one audit list."""
    sections, results = [], []
    for label, fn in (("VirusTotal", vt_fn), ("AbuseIPDB", abuse_fn)):
        block, service_results = fn(item)
        if block:
            sections.append(f"{label}:\n{block}")
            results.extend(service_results)
    if not sections:
        return None, []
    return "\n\n".join(sections), results


def default_reputation(item):
    from . import config

    return reputation_for_item(
        item,
        vt_fn=lambda i: vt.reputation_for_item(i, api_key=config.VT_API_KEY),
        abuse_fn=lambda i: abuseipdb.block_for_item(i, api_key=config.ABUSEIPDB_API_KEY),
    )
