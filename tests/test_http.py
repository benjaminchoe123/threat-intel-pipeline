"""Every request used to go out as python-requests/2.x, unretried, on a fresh
connection. abuse.ch and MTA are volunteer-run and filter default-UA traffic."""

import pytest

from pipeline import http


@pytest.fixture(autouse=True)
def _reset():
    http.reset_default()
    yield
    http.reset_default()


def test_session_identifies_itself_and_links_back():
    ua = http.build_session().headers["User-Agent"]
    assert "threat-intel-pipeline" in ua
    assert "github.com" in ua, "an identifiable UA lets a feed owner contact us, not just block us"
    assert "python-requests" not in ua


def test_default_session_is_reused():
    assert http.default_session() is http.default_session()


def test_reset_default_builds_a_fresh_session():
    first = http.default_session()
    http.reset_default()
    assert http.default_session() is not first


def test_retries_transient_server_errors():
    retry = http.build_session().get_adapter("https://x/").max_retries
    for status in (500, 502, 503, 504):
        assert status in retry.status_forcelist


def test_does_not_retry_429():
    """Quota is a real answer, not a glitch. Silently retrying a 429 gets a key
    banned rather than throttled; the reputation clients handle it explicitly."""
    retry = http.build_session().get_adapter("https://x/").max_retries
    assert 429 not in retry.status_forcelist


def test_retry_honors_retry_after():
    retry = http.build_session().get_adapter("https://x/").max_retries
    assert retry.respect_retry_after_header is True


def test_backoff_is_configured():
    retry = http.build_session().get_adapter("https://x/").max_retries
    assert retry.backoff_factor > 0
    assert retry.total == http.MAX_RETRIES


def test_both_schemes_are_mounted():
    session = http.build_session()
    assert session.get_adapter("https://x/") is session.get_adapter("http://x/")
