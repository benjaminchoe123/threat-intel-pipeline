"""Combined IOC reputation context: VirusTotal + AbuseIPDB per item.

Reputation is *prompt context only* — useful evidence, never a precondition. So a
provider outage must degrade the note, not stop the pipeline: previously a single
VirusTotal 429 propagated out of main() and abandoned every remaining item across
every source.

Each provider is isolated from the other for the same reason: VirusTotal failing
is not a reason to skip AbuseIPDB.
"""

import logging

from . import abuseipdb, epss, vt

log = logging.getLogger(__name__)


def reputation_for_item(item, vt_fn, abuse_fn, epss_fn=None):
    """Compose per-service blocks into one prompt block and one audit list.

    Returns (block, results). A provider that fails contributes an explicit
    "lookup unavailable" line rather than silence — the model must not read a
    missing section as "nothing found", which is a different claim.
    """
    providers = [("VirusTotal", vt_fn), ("AbuseIPDB", abuse_fn)]
    if epss_fn is not None:
        providers.append(("EPSS", epss_fn))

    sections, results = [], []
    for label, fn in providers:
        try:
            block, service_results = fn(item)
        except Exception as e:
            log.warning("%s lookup failed for %s:%s — %s", label, item.get("source"),
                        item.get("external_id"), e)
            sections.append(f"{label}: lookup unavailable ({type(e).__name__}) — "
                            "treat as no data, not as a clean verdict.")
            results.append({"service": label.lower(), "error": str(e),
                            "error_type": type(e).__name__})
            continue
        if block:
            sections.append(f"{label}:\n{block}")
            results.extend(service_results)
    if not sections:
        return None, []
    return "\n\n".join(sections), results


def default_reputation(item, cache=None):
    from . import config

    return reputation_for_item(
        item,
        vt_fn=lambda i: vt.reputation_for_item(i, api_key=config.VT_API_KEY, cache=cache),
        abuse_fn=lambda i: abuseipdb.block_for_item(
            i, api_key=config.ABUSEIPDB_API_KEY, cache=cache
        ),
        # No API key, so EPSS always runs — it is the only reputation source that
        # applies to KEV and MTA items, which have no IOC list for the others.
        epss_fn=lambda i: epss.block_for_item(i, cache=cache),
    )
