"""Explicit single-source fetch, parse and atomic persistence."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from sbom_ops.clients.advisory_feed import AdvisoryFetchError
from sbom_ops.domain.advisory_feed import AdvisoryFeedItem
from sbom_ops.domain.advisory_poll import AdvisoryPollState, record_poll
from sbom_ops.services.advisory_feed_parser import parse_advisory_feed
from sbom_ops.storage.advisory_feed import AdvisoryFeedStore


class FeedFetcher(Protocol):
    def fetch(self, source_id: str) -> bytes: ...


@dataclass(frozen=True)
class AdvisoryRefreshResult:
    status: str
    state: AdvisoryPollState
    items: tuple[AdvisoryFeedItem, ...] = ()
    record_ids: tuple[int, ...] = ()


def refresh_advisories(
    store: AdvisoryFeedStore,
    client: FeedFetcher,
    *,
    source_id: str,
    now: datetime,
    interval: timedelta = timedelta(hours=1),
) -> AdvisoryRefreshResult:
    if source_id not in ("jpcert", "ubuntu"):
        raise ValueError("unsupported advisory source")
    # Validate configuration before performing any request, even for a skipped run.
    record_poll(None, now=now, interval=interval)
    previous = store.poll_state(source_id)
    if previous is not None and not previous.due(now):
        return AdvisoryRefreshResult("not_due", previous)
    items: tuple[AdvisoryFeedItem, ...] = ()
    try:
        raw = client.fetch(source_id)
    except AdvisoryFetchError as exc:
        state = record_poll(
            previous,
            now=now,
            interval=interval,
            error=exc.code,
            http_status=exc.status,
            retry_after=exc.retry_after,
        )
    else:
        try:
            items = parse_advisory_feed(raw, source_id=source_id)
        except ValueError:
            state = record_poll(
                previous, now=now, interval=interval, error="invalid_feed"
            )
        else:
            state = record_poll(previous, now=now, interval=interval)
    # Database/optimistic-concurrency failures propagate: they are not fetch failures.
    ids = store.save_poll(source_id, items, state, expected=previous)
    return AdvisoryRefreshResult(
        "failed" if state.error else "succeeded", state, items, ids
    )
