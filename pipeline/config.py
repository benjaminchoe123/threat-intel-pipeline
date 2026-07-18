"""Central paths and tunables."""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

VAULT_DIR = ROOT / "vault"
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
QUARANTINE_DIR = DATA_DIR / "quarantine"
STATE_DB = DATA_DIR / "state.db"
LOGS_DIR = ROOT / "logs"
AUDIT_DIR = LOGS_DIR / "audit"
SKILL_FILE = ROOT / "skills" / "threat-analyst.md"

def _positive_int(name, default):
    """Read a positive int from the environment, falling back on nonsense.

    int(os.getenv(...)) raised ValueError at *import*, so one typo in .env broke
    every entry point including the test suite, with a traceback that pointed at
    config.py rather than at the typo.
    """
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        log.warning("%s=%r is not an integer — using %d", name, raw, default)
        return default
    if value < 1:
        log.warning("%s=%d must be >= 1 — using %d", name, value, default)
        return default
    return value


LOOKBACK_DAYS = _positive_int("LOOKBACK_DAYS", 7)
MAX_ENRICH_PER_RUN = _positive_int("MAX_ENRICH_PER_RUN", 15)
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
MISP_URL = os.getenv("MISP_URL", "")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
# Optional: path to a todo/task list to append a "review & publish" reminder to
# after each weekly draft. Empty means unset — the reminder is skipped entirely.
BRAIN_TODO = os.getenv("BRAIN_TODO", "")
# Local/self-signed MISP deployments (e.g. the default misp-docker cert) need
# this off; default stays True so a real cert isn't silently unverified.
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "true").strip().lower() not in ("false", "0", "")
