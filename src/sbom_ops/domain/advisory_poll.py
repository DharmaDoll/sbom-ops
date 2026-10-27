"""Source polling state; freshness does not imply feed coverage."""

import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

_ERRORS = frozenset(
    (
        "http_error",
        "transport_error",
        "response_too_large",
        "unsupported_encoding",
        "invalid_feed",
    )
)


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("poll datetime requires timezone")


def _interval(value: timedelta) -> None:
    if not isinstance(value, timedelta) or value <= timedelta(0):
        raise ValueError("poll interval must be positive")


@dataclass(frozen=True)
class AdvisoryPollState:
    last_attempt: datetime
    last_success: datetime | None
    error: str | None
    http_status: int | None
    next_attempt: datetime

    def __post_init__(self) -> None:
        _aware(self.last_attempt)
        _aware(self.next_attempt)
        if self.next_attempt <= self.last_attempt:
            raise ValueError("invalid next poll time")
        if self.last_success is not None:
            _aware(self.last_success)
            if self.last_success > self.last_attempt:
                raise ValueError("success is after latest attempt")
        if self.error is not None and self.error not in _ERRORS:
            raise ValueError("invalid poll error")
        if self.error is None and self.last_success != self.last_attempt:
            raise ValueError("successful attempt needs success time")
        if self.error == "http_error":
            if type(self.http_status) is not int or not 100 <= self.http_status <= 599:
                raise ValueError("invalid poll HTTP status")
        elif self.http_status is not None:
            raise ValueError("HTTP status requires HTTP error")

    def freshness(self, now: datetime, interval: timedelta) -> str:
        _aware(now)
        _interval(interval)
        if now < self.last_attempt or self.error or self.last_success is None:
            return "unknown"
        return "fresh" if now - self.last_success < interval else "stale"

    def due(self, now: datetime) -> bool:
        _aware(now)
        return now >= self.next_attempt


def record_poll(
    previous: AdvisoryPollState | None,
    *,
    now: datetime,
    interval: timedelta,
    error: str | None = None,
    http_status: int | None = None,
    retry_after: str | None = None,
) -> AdvisoryPollState:
    _aware(now)
    _interval(interval)
    now = now.astimezone(UTC)
    if previous is not None and now < previous.last_attempt:
        raise ValueError("poll attempt predates existing state")
    try:
        next_attempt = now + interval
    except OverflowError as exc:
        raise ValueError("poll interval exceeds datetime range") from exc
    if http_status in (429, 503) and isinstance(retry_after, str):
        if (
            len(retry_after) <= 128
            and retry_after.isascii()
            and retry_after.isprintable()
        ):
            try:
                if re.fullmatch(r"[0-9]{1,9}", retry_after):
                    retry_at = now + timedelta(seconds=int(retry_after))
                else:
                    retry_at = parsedate_to_datetime(retry_after)
                    _aware(retry_at)
                next_attempt = max(next_attempt, retry_at)
            except (ValueError, TypeError, OverflowError):
                pass
    return AdvisoryPollState(
        last_attempt=now,
        last_success=(
            now
            if error is None
            else previous.last_success if previous is not None else None
        ),
        error=error,
        http_status=http_status,
        next_attempt=next_attempt.astimezone(UTC),
    )


def poll_view(
    state: AdvisoryPollState | None, *, now: datetime, max_age: timedelta
) -> dict[str, object]:
    """Read-time freshness threshold, not a change to the polling schedule."""
    _aware(now)
    _interval(max_age)
    return {
        "checked_at": now.isoformat(),
        "max_age_seconds": max_age.total_seconds(),
        "freshness": "unknown" if state is None else state.freshness(now, max_age),
        "state": (
            None
            if state is None
            else {
                key: value.isoformat() if isinstance(value, datetime) else value
                for key, value in asdict(state).items()
            }
        ),
        "coverage": "not_guaranteed",
    }
