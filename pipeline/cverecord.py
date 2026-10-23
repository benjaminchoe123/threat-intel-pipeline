"""The CVE record behind a CVE ID: affected versions, CVSS, CISA's SSVC call.

KEV says *that* a CVE is exploited. It does not say which versions are affected,
so every KEV note answered "Affected products / versions" with "Unknown — not
stated in source", and 2026-W42 told its readers to go find the vendor advisory
themselves. The record on CVE.org had the exact ranges for both of that week's
CVEs the whole time.

One free request per CVE, no key. The record carries two independent voices:
the CNA (usually the vendor, who knows the version ranges) and CISA's ADP
"Vulnrichment" container, which adds SSVC decision points — Exploitation,
Automatable, Technical Impact — and fills in CVSS where the CNA gave none.
"""

import logging

from .epss import extract_cves
from .http import default_session

log = logging.getLogger(__name__)

API_URL = "https://cveawg.mitre.org/api/cve/{}"
# One request per CVE. KEV items name one; MTA prose can name a dozen, and the
# first few are the ones the writeup is about.
MAX_CVES_PER_ITEM = 3
MAX_PRODUCTS = 6
MAX_RANGES = 6
MAX_ADVISORIES = 3
# Newest scoring first: the CNA's own choice of version is the one to report.
CVSS_KEYS = (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"))
_OPEN_LOWER = {"", "0", "*", "n/a", "-"}


class CveRecordError(RuntimeError):
    """CVE.org returned an unusable response."""


def fetch(cve, session=None, timeout=30):
    """The raw record, or None when no published record exists (404).

    A 404 is an answer — the ID is reserved, rejected, or not public yet — not
    a failure. Anything else unusable raises, so the caller can say "lookup
    failed" rather than "nothing there".
    """
    http = session or default_session()
    resp = http.get(API_URL.format(cve), timeout=timeout)
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise CveRecordError(f"CVE.org returned {resp.status_code} for {cve}")
    try:
        record = resp.json()
        record["containers"]
    except (ValueError, KeyError, TypeError) as e:
        raise CveRecordError(f"CVE.org sent an unreadable 200 for {cve}: {e}") from e
    return record


def _range(v):
    start = str(v.get("version", "")).strip()
    lower = "" if start.lower() in _OPEN_LOWER else start
    if v.get("lessThanOrEqual"):
        upper = v["lessThanOrEqual"]
        return f"{lower} through {upper}" if lower else f"up to and including {upper}"
    if v.get("lessThan"):
        upper = v["lessThan"]
        return f"{lower} up to (not including) {upper}" if lower else f"before {upper}"
    return lower or None


def _affected(cna):
    out = []
    for entry in (cna.get("affected") or [])[:MAX_PRODUCTS]:
        if not isinstance(entry, dict):
            continue
        ranges = [r for v in entry.get("versions") or []
                  if isinstance(v, dict) and v.get("status") == "affected"
                  for r in [_range(v)] if r]
        if not ranges and entry.get("defaultStatus") == "affected":
            ranges = ["all versions (no range given)"]
        if ranges:
            out.append({"vendor": entry.get("vendor", "?"), "product": entry.get("product", "?"),
                        "ranges": ranges[:MAX_RANGES]})
    return out


def _cvss(metrics, by):
    for m in metrics or []:
        for key, version in CVSS_KEYS:
            c = m.get(key) if isinstance(m, dict) else None
            if isinstance(c, dict) and c.get("baseScore") is not None:
                return {"version": version, "score": c["baseScore"],
                        "severity": c.get("baseSeverity"), "vector": c.get("vectorString"),
                        "by": by}
    return None


def summarize(record):
    """The parts of a record worth a model's attention, in a small fixed shape."""
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = [a for a in containers.get("adp") or [] if isinstance(a, dict)]

    cvss = _cvss(cna.get("metrics"), "CNA")
    ssvc = None
    for adp in adps:
        name = (adp.get("providerMetadata") or {}).get("shortName", "ADP")
        cvss = cvss or _cvss(adp.get("metrics"), name)
        for m in adp.get("metrics") or []:
            other = m.get("other") if isinstance(m, dict) else None
            if isinstance(other, dict) and other.get("type") == "ssvc":
                ssvc = {k: v for opt in (other.get("content") or {}).get("options") or []
                        if isinstance(opt, dict) for k, v in opt.items()}

    advisories = [r["url"] for r in cna.get("references") or []
                  if isinstance(r, dict) and r.get("url")
                  and {"vendor-advisory", "patch"} & set(r.get("tags") or [])]
    return {
        "assigner": (record.get("cveMetadata") or {}).get("assignerShortName"),
        "affected": _affected(cna),
        "cvss": cvss,
        "ssvc": ssvc or None,
        "advisories": advisories[:MAX_ADVISORIES],
    }


def _format(cve, s):
    by = f" (record published by {s['assigner']})" if s.get("assigner") else ""
    lines = [f"- {cve}{by}:"]
    if s["affected"]:
        for a in s["affected"]:
            lines.append(f"  affected: {a['vendor']} {a['product']}: {'; '.join(a['ranges'])}")
    else:
        lines.append("  affected: the record lists no affected version ranges")
    if s["cvss"]:
        c = s["cvss"]
        severity = f" {c['severity']}" if c["severity"] else ""
        lines.append(f"  CVSS {c['version']}: {c['score']}{severity} ({c['vector']}) "
                     f"— scored by {c['by']}")
    if s["ssvc"]:
        lines.append("  CISA SSVC: " + ", ".join(f"{k.lower()}={v}" for k, v in s["ssvc"].items()))
    for url in s["advisories"]:
        lines.append(f"  vendor advisory: {url}")
    return "\n".join(lines)


def block_for_item(item, session=None, cache=None):
    """CVE-record context for an item's CVEs. Returns (prompt_block, results).

    Each CVE is isolated: one failed lookup becomes a "lookup failed" line for
    that CVE and the rest still arrive. A missing record is cached nowhere — a
    reserved ID can be published tomorrow.
    """
    cves = extract_cves(item)[:MAX_CVES_PER_ITEM]
    if not cves:
        return None, []

    lines, results = [], []
    for cve in cves:
        summary = cache.get("cve_record", cve) if cache else None
        cached = summary is not None
        if not cached:
            try:
                record = fetch(cve, session=session)
            except Exception as e:
                log.warning("CVE record lookup failed for %s — %s", cve, e)
                lines.append(f"- {cve}: CVE record lookup failed ({type(e).__name__}) — "
                             "treat versions as unknown, not as unaffected.")
                results.append({"service": "cve_record", "ioc": cve, "error": str(e),
                                "error_type": type(e).__name__})
                continue
            if record is None:
                lines.append(f"- {cve}: no published CVE record yet (reserved or not public) — "
                             "affected versions are unknown, not 'none'.")
                results.append({"service": "cve_record", "ioc": cve, "found": False})
                continue
            summary = summarize(record)
            if cache:
                cache.put("cve_record", cve, summary)
        lines.append(_format(cve, summary))
        results.append({"service": "cve_record", "ioc": cve, "found": True,
                        **({"cached": True} if cached else {}), **summary})
    return "\n".join(lines), results
