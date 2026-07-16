"""A typo in .env must not break every entry point at import time."""

import pytest

from pipeline.config import _positive_int


def test_reads_a_valid_value(monkeypatch):
    monkeypatch.setenv("X_TEST", "3")
    assert _positive_int("X_TEST", 7) == 3


def test_unset_uses_the_default(monkeypatch):
    monkeypatch.delenv("X_TEST", raising=False)
    assert _positive_int("X_TEST", 7) == 7


@pytest.mark.parametrize("raw", ["", "   ", "seven", "3.5", "None"])
def test_nonsense_falls_back_instead_of_raising_at_import(monkeypatch, raw):
    """int(os.getenv(...)) raised ValueError inside config.py, so one typo broke
    the whole package - including the tests - and blamed config.py for it."""
    monkeypatch.setenv("X_TEST", raw)
    assert _positive_int("X_TEST", 7) == 7


@pytest.mark.parametrize("raw", ["0", "-1"])
def test_non_positive_falls_back(monkeypatch, raw):
    """MAX_ENRICH_PER_RUN=0 silently enriched nothing while still fetching feeds."""
    monkeypatch.setenv("X_TEST", raw)
    assert _positive_int("X_TEST", 15) == 15
