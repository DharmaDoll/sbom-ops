"""Provider-wide retry policy. Waiting never changes PoC evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime


@dataclass(frozen=True)
class PocSourceState:
    source: str
    failures: int = 0
    retry_at: str | None = None
    last_error: str | None = None
    http_status: int | None = None

    def blocked(self, now: datetime) -> bool:
        return self.retry_at is not None and now < datetime.fromisoformat(self.retry_at)

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def retry_after_deadline(value: str | None, now: datetime) -> datetime:
    """RFC 9110 section 10.2.3: delay-seconds or HTTP-date; never truncate waits."""
    if value is None:
        return now
    value = value.strip()
    if value.isascii() and value.isdigit():
        # Huge, valid delays stay blocked rather than overflowing or becoming short.
        if len(value.lstrip("0")) > 12:
            return datetime.max.replace(tzinfo=UTC)
        try:
            return now + timedelta(seconds=int(value.lstrip("0") or "0"))
        except (OverflowError, ValueError):
            return datetime.max.replace(tzinfo=UTC)
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is not None:
            return max(now, parsed.astimezone(UTC))
    except (ValueError, TypeError, OverflowError):
        pass
    return now


@dataclass(frozen=True)
class PocRetryPolicy:
    base_seconds: int = 60
    max_seconds: int = 3600

    def __post_init__(self) -> None:
        if not 1 <= self.base_seconds <= self.max_seconds <= 604800:
            raise ValueError("retry delays require 1 <= base <= max <= 604800")

    def failure(
        self,
        previous: PocSourceState,
        *,
        now: datetime,
        error: str,
        status: int | None = None,
        retry_after: str | None = None,
    ) -> PocSourceState:
        failures = min(previous.failures + 1, 64)
        seconds = min(self.max_seconds, self.base_seconds * 2 ** (failures - 1))
        retry_at = max(
            now + timedelta(seconds=seconds), retry_after_deadline(retry_after, now)
        )
        return PocSourceState(
            previous.source, failures, retry_at.isoformat(), error, status
        )
