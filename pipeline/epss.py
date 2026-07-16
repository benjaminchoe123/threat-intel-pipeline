"""EPSS (Exploit Prediction Scoring System) scores for CVEs.

FIRST's EPSS is a daily-updated model estimating the probability that a CVE will
be exploited in the wild within 30 days. The API is free and needs no key.

This is the first independent evidence KEV notes get: VirusTotal and AbuseIPDB
both key off item["raw"]["iocs"], which only the abuse.ch sources produce, so
KEV and MTA items reached the model with no reputation context and severity
rested on model judgment alone.

EPSS pairs naturally with KEV without duplicating it. KEV says "exploitation has
been observed"; EPSS says "here is how likely exploitation is". A KEV entry with
a low EPSS score is not a contradiction — it is a prioritization signal.
"""

import logging
import math
import re

from .http import default_session

log = logging.getLogger(__name__)

API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100  # the API's documented per-request limit

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class EpssError(RuntimeError):
    """EPSS returned an unusable response."""


def extract_cves(item):
    """CVE IDs mentioned anywhere in the item's raw payload, in first-seen order.

    Deliberately a regex over the whole payload rather than just raw["cveID"]:
    MTA writeups name CVEs in prose, and those notes benefit from a score too.
    """
    raw = item.get("raw") or {}
    found = []
    for value in raw.values():
        for match in CVE_RE.findall(str(value)):
            cve = match.upper()
            if cve not in found:
                found.append(cve)
    return found


def scores(cves, session=None, timeout=30):
    """Fetch EPSS scores. Returns {cve: {"epss", "percentile", "date"}}.

    A CVE with no score is simply absent from the result — it is usually too new
    for a model run. That is not an error, and must not be coerced to zero:
    "no score" and "no exploitation risk" are different claims.
    """
    if not cves:
        return {}
    http = session or default_session()
    out = {}
    for start in range(0, len(cves), BATCH_SIZE):
        batch = cves[start:start + BATCH_SIZE]
        resp = http.get(API_URL, params={"cve": ",".join(batch)}, timeout=timeout)
        if resp.status_code != 200:
            raise EpssError(f"EPSS returned {resp.status_code} for {len(batch)} CVE(s)")
        try:
            rows = resp.json()["data"]
        except (ValueError, KeyError, TypeError) as e:
            raise EpssError(f"EPSS sent an unreadable 200: {e}") from e
        for row in rows:
            try:
                out[row["cve"].upper()] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                    "date": row.get("date"),
                }
            except (KeyError, TypeError, ValueError) as e:
                log.warning("skipping malformed EPSS row %r: %s", row, e)
    return out


def _pct(value):
    """Percentage, floored to one decimal so it never rounds up.

    EPSS 0.99999 formatted with %.1f reads "100.0%" — stating certainty the model
    does not claim. Flooring keeps 99.9% at 99.9%, and only a true 1.0 shows 100.0.
    """
    return f"{math.floor(value * 1000) / 10:.1f}"


def _format_line(cve, score):
    if score is None:
        return (f"- {cve}: no EPSS score published (usually means it is too new to "
                "have been scored — not evidence of low risk)")
    return (
        f"- {cve}: {_pct(score['epss'])}% probability of exploitation in the next "
        f"30 days (EPSS {score['epss']:.5f}, {_pct(score['percentile'])}th percentile"
        f"{', as of ' + score['date'] if score.get('date') else ''})"
    )


def block_for_item(item, session=None, cache=None):
    """EPSS context for an item's CVEs. Returns (prompt_block, results)."""
    cves = extract_cves(item)
    if not cves:
        return None, []

    found, missing = {}, []
    for cve in cves:
        cached = cache.get("epss", cve) if cache else None
        if cached is not None:
            found[cve] = cached
        else:
            missing.append(cve)

    if missing:
        fetched = scores(missing, session=session)
        for cve, score in fetched.items():
            if cache:
                cache.put("epss", cve, score)
        found.update(fetched)

    results, lines = [], []
    for cve in cves:
        score = found.get(cve)
        lines.append(_format_line(cve, score))
        results.append({"service": "epss", "ioc": cve, "found": score is not None,
                        **(score or {})})
    return "\n".join(lines), results
