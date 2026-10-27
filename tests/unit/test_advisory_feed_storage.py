"""Isolated v12 table contract; registry migration is verified separately."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sbom_ops.domain.advisory_feed import AdvisoryFeedItem
from sbom_ops.storage.advisory_feed import ADVISORY_FEED_SCHEMA, AdvisoryFeedStore

NOW = datetime(2026, 10, 27, tzinfo=UTC)


@pytest.fixture
def path(tmp_path: Path) -> Path:
    result = tmp_path / "isolated.db"
    with sqlite3.connect(result) as db:
        db.execute(ADVISORY_FEED_SCHEMA)
        db.execute("PRAGMA user_version=12")
    return result


def item() -> AdvisoryFeedItem:
    return AdvisoryFeedItem(
        "fixture",
        "item#1",
        "https://example.test/article#1",
        "Example",
        (("description", "private-body-marker CVE-2026-1000"),),
    )


def test_repeat_correction_and_reappearance_preserve_history(path: Path) -> None:
    original = item()
    corrected = replace(original, title="Corrected")
    with AdvisoryFeedStore(path) as store:
        first = store.save((original,), fetched_at=NOW)
        assert len(first) == 1
        assert store.save((original,), fetched_at=NOW + timedelta(hours=1)) == first
        second = store.save((corrected,), fetched_at=NOW + timedelta(hours=2))
        third = store.save((original,), fetched_at=NOW + timedelta(hours=3))
        assert len({first[0], second[0], third[0]}) == 3
        history = store.history("fixture", "item#1")
        assert len(history) == 3
        assert history[0]["last_seen_at"] == (NOW + timedelta(hours=1)).isoformat()
        assert history[0]["metadata"]["cve_mentions"] == [
            ["CVE-2026-1000", "description"]
        ]
    with sqlite3.connect(path) as db:
        assert "private-body-marker" not in "\n".join(db.iterdump())


def test_backdated_batch_is_atomic(path: Path) -> None:
    original = item()
    other = replace(original, item_key="item#2")
    with AdvisoryFeedStore(path) as store:
        store.save((original,), fetched_at=NOW)
        with pytest.raises(ValueError):
            store.save((other, original), fetched_at=NOW - timedelta(seconds=1))
        assert store.history("fixture", "item#2") == ()
        assert len(store.history("fixture", "item#1")) == 1


def test_readonly_refuses_save_and_does_not_change_db(path: Path) -> None:
    raw = path.read_bytes()
    with AdvisoryFeedStore(path, read_only=True) as store:
        assert store.history("fixture", "item#1") == ()
        with pytest.raises(ValueError):
            store.save((item(),), fetched_at=NOW)
    assert path.read_bytes() == raw


def test_duplicate_batch_and_naive_timestamp_rejected(path: Path) -> None:
    with AdvisoryFeedStore(path) as store:
        with pytest.raises(ValueError):
            store.save((item(), item()), fetched_at=NOW)
        with pytest.raises(ValueError):
            store.save((item(),), fetched_at=NOW.replace(tzinfo=None))
        assert store.history("fixture", "item#1") == ()


def test_two_writers_do_not_duplicate_same_revision(path: Path) -> None:
    def write() -> tuple[int, ...]:
        with AdvisoryFeedStore(path) as store:
            return store.save((item(),), fetched_at=NOW)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(write) for _ in range(2)]
        assert futures[0].result() == futures[1].result()
    with AdvisoryFeedStore(path, read_only=True) as store:
        assert len(store.history("fixture", "item#1")) == 1


@pytest.mark.parametrize("case", ["identity", "body", "cve", "time"])
def test_corrupt_record_is_rejected(path: Path, case: str) -> None:
    with AdvisoryFeedStore(path) as store:
        store.save((item(),), fetched_at=NOW)
    with sqlite3.connect(path) as db:
        raw = db.execute(
            "SELECT metadata_json FROM advisory_feed_revisions"
        ).fetchone()[0]
        metadata = json.loads(raw)
        if case == "identity":
            metadata["item_key"] = "wrong"
        elif case == "body":
            metadata["source_fields"] = [["description", "should not be stored"]]
        elif case == "cve":
            metadata["cve_mentions"] = [["not-a-cve", "title"]]
        else:
            db.execute("UPDATE advisory_feed_revisions SET last_seen_at='2020-01-01'")
        db.execute(
            "UPDATE advisory_feed_revisions SET metadata_json=?",
            (json.dumps(metadata),),
        )
    with AdvisoryFeedStore(path, read_only=True) as store:
        with pytest.raises(ValueError):
            store.history("fixture", "item#1")


def test_existing_schema_is_not_implicitly_migrated(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=11")
    original = path.read_bytes()
    with pytest.raises(ValueError, match="schema v12"):
        AdvisoryFeedStore(path)
    assert path.read_bytes() == original
    missing = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        AdvisoryFeedStore(missing)
    assert not missing.exists()
