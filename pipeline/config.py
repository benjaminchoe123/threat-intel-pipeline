"""Central paths and tunables."""

import os
from pathlib import Path

from dotenv import load_dotenv

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

LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "7"))
MAX_ENRICH_PER_RUN = int(os.getenv("MAX_ENRICH_PER_RUN", "15"))
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")
