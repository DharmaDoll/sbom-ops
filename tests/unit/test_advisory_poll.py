from datetime import UTC, datetime, timedelta

import pytest

from sbom_ops.domain.advisory_poll import poll_view, record_poll

NOW = datetime(2026, 10, 27, tzinfo=UTC)
HOUR = timedelta(hours=1)


def test_failure_preserves_success_and_recovery_clears_error():
    first = record_poll(None, now=NOW, interval=HOUR)
    failed = record_poll(
        first,
        now=NOW + HOUR,
        interval=HOUR,
        error="http_error",
        http_status=503,
        retry_after="7200",
    )
    assert failed.last_success == NOW
    assert failed.error == "http_error"
    assert failed.next_attempt == NOW + HOUR * 3
    assert failed.freshness(NOW + HOUR, HOUR) == "unknown"
    recovered = record_poll(failed, now=NOW + HOUR * 3, interval=HOUR)
    assert recovered.last_success == NOW + HOUR * 3
    assert recovered.error is None and recovered.http_status is None


def test_freshness_and_due_boundaries_and_clock_rollback():
    state = record_poll(None, now=NOW, interval=HOUR)
    assert state.freshness(NOW, HOUR) == "fresh"
    assert state.freshness(NOW + HOUR, HOUR) == "stale"
    assert not state.due(NOW)
    assert state.due(NOW + HOUR)
    assert state.freshness(NOW - HOUR, HOUR) == "unknown"
    assert not state.due(NOW - HOUR)


@pytest.mark.parametrize("retry", ["-1", "bad", "60\r\nInjected", "0", "60"])
def test_invalid_or_short_retry_does_not_shorten_interval(retry):
    state = record_poll(
        None,
        now=NOW,
        interval=HOUR,
        error="http_error",
        http_status=429,
        retry_after=retry,
    )
    assert state.last_success is None
    assert state.next_attempt == NOW + HOUR
    assert state.freshness(NOW, HOUR) == "unknown"


def test_http_date_and_non_retry_status():
    date = "Tue, 27 Oct 2026 03:00:00 GMT"
    state = record_poll(
        None,
        now=NOW,
        interval=HOUR,
        error="http_error",
        http_status=503,
        retry_after=date,
    )
    assert state.next_attempt == NOW + HOUR * 3
    other = record_poll(
        None,
        now=NOW,
        interval=HOUR,
        error="http_error",
        http_status=404,
        retry_after=date,
    )
    assert other.next_attempt == NOW + HOUR


def test_invalid_transition_rejected():
    state = record_poll(None, now=NOW, interval=HOUR)
    with pytest.raises(ValueError):
        record_poll(state, now=NOW - HOUR, interval=HOUR)
    with pytest.raises(ValueError):
        record_poll(None, now=NOW.replace(tzinfo=None), interval=HOUR)
    with pytest.raises(ValueError):
        record_poll(None, now=NOW, interval=timedelta(0))
    with pytest.raises(ValueError):
        record_poll(None, now=NOW, interval=HOUR, error="private remote text")


@pytest.mark.parametrize("status", [None, True, 99, 600, "503"])
def test_invalid_http_error_state_rejected(status):
    with pytest.raises(ValueError):
        record_poll(
            None, now=NOW, interval=HOUR, error="http_error", http_status=status
        )


def test_non_http_error_has_no_status_and_preserves_original_success():
    state = record_poll(None, now=NOW, interval=HOUR)
    for offset, error in enumerate(("transport_error", "invalid_feed"), start=1):
        state = record_poll(state, now=NOW + HOUR * offset, interval=HOUR, error=error)
        assert state.last_success == NOW
        assert state.http_status is None
    with pytest.raises(ValueError):
        record_poll(
            state,
            now=NOW + HOUR * 3,
            interval=HOUR,
            error="invalid_feed",
            http_status=200,
        )


def test_overflow_is_controlled_error():
    with pytest.raises(ValueError):
        record_poll(None, now=datetime.max.replace(tzinfo=UTC), interval=HOUR)


def test_view_threshold_does_not_change_retry_schedule():
    state = record_poll(None, now=NOW, interval=HOUR)
    assert poll_view(state, now=NOW + HOUR, max_age=HOUR)["freshness"] == "stale"
    view = poll_view(state, now=NOW + HOUR, max_age=HOUR * 2)
    assert view["freshness"] == "fresh"
    assert view["state"]["next_attempt"] == (NOW + HOUR).isoformat()
    assert view["coverage"] == "not_guaranteed"
    assert poll_view(None, now=NOW, max_age=HOUR)["state"] is None
    with pytest.raises(ValueError):
        poll_view(None, now=NOW, max_age=timedelta(0))
