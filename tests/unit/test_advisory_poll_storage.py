import sqlite3
from dataclasses import replace
from datetime import timedelta

import pytest
from test_advisory_feed_storage import NOW, item

from sbom_ops.domain.advisory_poll import record_poll
from sbom_ops.storage.advisory_feed import (
    ADVISORY_FEED_SCHEMA,
    ADVISORY_POLL_SCHEMA,
    AdvisoryFeedStore,
)


@pytest.fixture
def path(tmp_path):
    path = tmp_path / "assets.db"
    with sqlite3.connect(path) as db:
        db.execute(ADVISORY_FEED_SCHEMA)
        db.execute(ADVISORY_POLL_SCHEMA)
        db.execute("PRAGMA user_version=12")
    return path


def test_success_failure_and_reopen_preserve_articles(path):
    first = record_poll(None, now=NOW, interval=timedelta(hours=1))
    with AdvisoryFeedStore(path) as store:
        store.save_poll("fixture", (item(),), first, expected=None)
    failed = record_poll(
        first,
        now=NOW + timedelta(hours=1),
        interval=timedelta(hours=1),
        error="transport_error",
    )
    with AdvisoryFeedStore(path) as store:
        assert store.poll_state("fixture") == first
        store.save_poll("fixture", (), failed, expected=first)
    with AdvisoryFeedStore(path, read_only=True) as store:
        assert store.poll_state("fixture") == failed
        assert len(store.history(*item().identity)) == 1
        assert store.poll_state("other") is None


def test_conflicting_writer_does_not_save_article(path):
    first = record_poll(None, now=NOW, interval=timedelta(hours=1))
    with AdvisoryFeedStore(path) as store:
        store.save_poll("fixture", (), first, expected=None)
        with pytest.raises(ValueError):
            store.save_poll("fixture", (item(),), first, expected=None)
        assert store.history(*item().identity) == ()
        assert store.poll_state("fixture") == first


def test_failed_state_write_rolls_back_article(path):
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TRIGGER fail_poll BEFORE INSERT ON advisory_poll_state "
            "BEGIN SELECT RAISE(ABORT, 'fixture'); END"
        )
    state = record_poll(None, now=NOW, interval=timedelta(hours=1))
    with AdvisoryFeedStore(path) as store:
        with pytest.raises(sqlite3.IntegrityError):
            store.save_poll("fixture", (item(),), state, expected=None)
        assert store.history(*item().identity) == ()
        assert store.poll_state("fixture") is None


def test_failure_cannot_insert_articles_or_change_success(path):
    first = record_poll(None, now=NOW, interval=timedelta(hours=1))
    failed = record_poll(
        first,
        now=NOW + timedelta(hours=1),
        interval=timedelta(hours=1),
        error="invalid_feed",
    )
    with AdvisoryFeedStore(path) as store:
        store.save_poll("fixture", (), first, expected=None)
        with pytest.raises(ValueError):
            store.save_poll("fixture", (item(),), failed, expected=first)
        with pytest.raises(ValueError):
            store.save_poll(
                "fixture", (), replace(failed, last_success=None), expected=first
            )
        assert store.poll_state("fixture") == first


def test_readonly_and_corrupt_state_are_rejected(path):
    first = record_poll(None, now=NOW, interval=timedelta(hours=1))
    with AdvisoryFeedStore(path) as store:
        store.save_poll("fixture", (), first, expected=None)
    with AdvisoryFeedStore(path, read_only=True) as store:
        with pytest.raises(ValueError):
            store.save_poll("fixture", (item(),), first, expected=first)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE advisory_poll_state SET next_attempt=last_attempt")
    with AdvisoryFeedStore(path) as store:
        with pytest.raises(ValueError):
            store.poll_state("fixture")
        with pytest.raises(ValueError):
            store.save_poll("fixture", (item(),), first, expected=first)
        assert store.history(*item().identity) == ()
