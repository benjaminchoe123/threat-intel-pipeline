"""Shared HTTP session: identify ourselves, reuse connections, retry transient errors.

Every request was going out as `python-requests/2.x` over a brand-new TCP/TLS
connection with no retry. Three problems, in order of how much they matter:

1. **Anonymity.** abuse.ch and malware-traffic-analysis.net are small operations
   that filter and rate-limit default-UA traffic. Being a good citizen of feeds
   you depend on is not optional when they are free and run by volunteers — and
   an identifiable UA means they can contact you instead of just blocking you.
2. **No retry.** A single transient 503 from CISA lost the whole KEV feed for
   the day. Server errors are retried with backoff; 429 deliberately is not —
   the reputation clients handle quota explicitly, and silently retrying a
   quota rejection is how you get an API key banned rather than throttled.
3. **No connection reuse.** A fresh TLS handshake per lookup, several per item.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

VERSION = "1.0"
REPO_URL = "https://github.com/benjaminchoe123/threat-intel-pipeline"
USER_AGENT = f"threat-intel-pipeline/{VERSION} (+{REPO_URL})"

# Transient server-side failures only. 429 is excluded on purpose: quota is a
# real answer, not a glitch, and the caller decides how to back off.
RETRY_STATUSES = (500, 502, 503, 504)
MAX_RETRIES = 3
BACKOFF_FACTOR = 1.0  # 0s, 2s, 4s between attempts

_default = None


def build_session(retries=MAX_RETRIES, backoff=BACKOFF_FACTOR):
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=backoff,
        status_forcelist=RETRY_STATUSES,
        allowed_methods=frozenset(["GET", "POST"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def default_session():
    """Process-wide session, built lazily so importing the package opens nothing."""
    global _default
    if _default is None:
        _default = build_session()
    return _default


def reset_default():
    """Drop the cached session (tests)."""
    global _default
    if _default is not None:
        _default.close()
    _default = None
