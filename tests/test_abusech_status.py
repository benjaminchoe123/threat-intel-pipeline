"""abuse.ch reports failure in the response envelope, not the HTTP status.

A revoked or typo'd ABUSECH_AUTH_KEY returns HTTP 200 with
{"query_status": "illegal_auth_key"} and no "data" key. The old code read
data.get("data") or [] and got zero items, so raise_for_status() never fired and
the run reported a successful, quiet day. Silent feed death is the worst failure
mode a threat pipeline can have.
"""

import pytest

from pipeline.sources.abusech import FeedAuthError, FeedError, check_query_status
from pipeline.sources.threatfox import aggregate_threatfox
from pipeline.sources.urlhaus import aggregate_urlhaus


@pytest.mark.parametrize("status", ["illegal_auth_key", "unauthorized", "auth_key_required"])
def test_auth_failures_raise_feedautherror(status):
    with pytest.raises(FeedAuthError, match="ABUSECH_AUTH_KEY"):
        check_query_status({"query_status": status}, "threatfox")


@pytest.mark.parametrize("status", ["no_result", "no_results"])
def test_no_result_is_a_legitimate_empty_day(status):
    assert check_query_status({"query_status": status}, "threatfox") is False


def test_ok_passes():
    assert check_query_status({"query_status": "ok", "data": []}, "threatfox") is True


def test_unknown_status_raises():
    with pytest.raises(FeedError, match="illegal_query"):
        check_query_status({"query_status": "illegal_query"}, "threatfox")


def test_missing_status_raises_rather_than_reading_as_empty():
    with pytest.raises(FeedError, match="no query_status"):
        check_query_status({"data": []}, "urlhaus")


def test_threatfox_aggregate_refuses_an_auth_failure():
    with pytest.raises(FeedAuthError):
        aggregate_threatfox({"query_status": "illegal_auth_key"})


def test_urlhaus_aggregate_refuses_an_auth_failure():
    with pytest.raises(FeedAuthError):
        aggregate_urlhaus({"query_status": "illegal_auth_key"})


def test_threatfox_empty_day_returns_no_items():
    assert aggregate_threatfox({"query_status": "no_result"}) == []


def test_urlhaus_empty_day_returns_no_items():
    assert aggregate_urlhaus({"query_status": "no_result"}) == []
