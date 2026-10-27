"""Feed revision storage, intended for the shared asset DB schema v12."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

from sbom_ops.domain.advisory_feed import AdvisoryFeedItem
from sbom_ops.domain.advisory_poll import AdvisoryPollState

ADVISORY_POLL_SCHEMA = """
CREATE TABLE advisory_poll_state (
    source_id TEXT PRIMARY KEY,
    last_attempt TEXT NOT NULL,
    last_success TEXT,
    error TEXT,
    http_status INTEGER,
    next_attempt TEXT NOT NULL
)
"""

ADVISORY_FEED_SCHEMA = """
CREATE TABLE advisory_feed_revisions (
    record_id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL,
    item_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL
        CHECK(length(CAST(metadata_json AS BLOB)) <= 262144)
)
"""


class AdvisoryFeedStore:
    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self._read_only = read_only
        self._db = sqlite3.connect(
            f"{Path(path).resolve().as_uri()}?mode={'ro' if read_only else 'rw'}",
            uri=True,
            timeout=5.0,
        )
        self._db.row_factory = sqlite3.Row
        try:
            if self._db.execute("PRAGMA user_version").fetchone()[0] != 12:
                raise ValueError("advisory storage requires schema v12; migrate first")
        except (sqlite3.Error, ValueError):
            self._db.close()
            raise

    def __enter__(self) -> AdvisoryFeedStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._db.close()

    def save(
        self, items: tuple[AdvisoryFeedItem, ...], *, fetched_at: datetime
    ) -> tuple[int, ...]:
        return self._save(items, fetched_at=fetched_at)

    def poll_state(self, source_id: str) -> AdvisoryPollState | None:
        row = self._db.execute(
            "SELECT * FROM advisory_poll_state WHERE source_id=?", (source_id,)
        ).fetchone()
        if row is None:
            return None
        return AdvisoryPollState(
            datetime.fromisoformat(row["last_attempt"]),
            (
                datetime.fromisoformat(row["last_success"])
                if row["last_success"]
                else None
            ),
            row["error"],
            row["http_status"],
            datetime.fromisoformat(row["next_attempt"]),
        )

    def save_poll(
        self,
        source_id: str,
        items: tuple[AdvisoryFeedItem, ...],
        state: AdvisoryPollState,
        *,
        expected: AdvisoryPollState | None,
    ) -> tuple[int, ...]:
        if not isinstance(source_id, str) or not re.fullmatch(
            r"[a-z][a-z0-9_-]{0,63}", source_id
        ):
            raise ValueError("invalid poll source")
        if any(item.source_id != source_id for item in items):
            raise ValueError("poll source mismatch")
        if state.error is not None:
            if items or state.last_success != (
                expected.last_success if expected is not None else None
            ):
                raise ValueError("failed poll cannot change successful data")
        if expected is not None and state.last_attempt < expected.last_attempt:
            raise ValueError("poll state predates existing state")
        return self._save(
            items, fetched_at=state.last_attempt, poll=(source_id, state, expected)
        )

    def _save(
        self,
        items: tuple[AdvisoryFeedItem, ...],
        *,
        fetched_at: datetime,
        poll: tuple[str, AdvisoryPollState, AdvisoryPollState | None] | None = None,
    ) -> tuple[int, ...]:
        if self._read_only:
            raise ValueError("advisory storage is read-only")
        if not isinstance(fetched_at, datetime) or fetched_at.utcoffset() is None:
            raise ValueError("advisory observation needs timezone")
        if (
            not isinstance(items, tuple)
            or len(items) > 500
            or any(not isinstance(item, AdvisoryFeedItem) for item in items)
        ):
            raise ValueError("invalid advisory batch")
        if len({item.identity for item in items}) != len(items):
            raise ValueError("duplicate advisory batch identity")
        stamp = fetched_at.astimezone(UTC).isoformat()
        prepared = []
        for item in items:
            metadata = json.dumps(
                item.metadata, ensure_ascii=False, separators=(",", ":")
            )
            if len(metadata.encode("utf-8")) > 262144:
                raise ValueError("advisory metadata too large")
            prepared.append((item, metadata))
        ids = []
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            if poll is not None and self.poll_state(poll[0]) != poll[2]:
                raise ValueError("poll state changed concurrently")
            for item, metadata in prepared:
                row = self._db.execute(
                    "SELECT * FROM advisory_feed_revisions "
                    "WHERE source_id=? AND item_key=? "
                    "ORDER BY record_id DESC LIMIT 1",
                    item.identity,
                ).fetchone()
                if row is not None:
                    self._decode(row)
                    if fetched_at < datetime.fromisoformat(row["last_seen_at"]):
                        raise ValueError("advisory observation predates latest record")
                if row is not None and row["fingerprint"] == item.fingerprint:
                    self._db.execute(
                        "UPDATE advisory_feed_revisions SET last_seen_at=? "
                        "WHERE record_id=?",
                        (stamp, row["record_id"]),
                    )
                    ids.append(row["record_id"])
                else:
                    cursor = self._db.execute(
                        "INSERT INTO advisory_feed_revisions "
                        "(source_id,item_key,fingerprint,first_seen_at,"
                        "last_seen_at,metadata_json) "
                        "VALUES (?,?,?,?,?,?)",
                        (*item.identity, item.fingerprint, stamp, stamp, metadata),
                    )
                    ids.append(int(cursor.lastrowid))
            if poll is not None:
                source_id, state, _ = poll
                self._db.execute(
                    "INSERT INTO advisory_poll_state VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(source_id) DO UPDATE SET "
                    "last_attempt=excluded.last_attempt, "
                    "last_success=excluded.last_success, error=excluded.error, "
                    "http_status=excluded.http_status, "
                    "next_attempt=excluded.next_attempt",
                    (
                        source_id,
                        state.last_attempt.astimezone(UTC).isoformat(),
                        (
                            state.last_success.astimezone(UTC).isoformat()
                            if state.last_success
                            else None
                        ),
                        state.error,
                        state.http_status,
                        state.next_attempt.astimezone(UTC).isoformat(),
                    ),
                )
        return tuple(ids)

    def history(self, source_id: str, item_key: str) -> tuple[dict[str, object], ...]:
        rows = self._db.execute(
            "SELECT * FROM advisory_feed_revisions WHERE source_id=? AND item_key=? "
            "ORDER BY record_id LIMIT 10001",
            (source_id, item_key),
        ).fetchall()
        if len(rows) > 10000:
            raise ValueError("advisory history limit exceeded")
        return tuple(self._decode(row) for row in rows)

    def latest(
        self, source_id: str, *, after_id: int = 0, limit: int = 100
    ) -> tuple[dict[str, object], ...]:
        """Latest known revision per item, ordered by revision ID for pagination."""
        if (
            type(after_id) is not int
            or not 0 <= after_id <= 9223372036854775807
            or type(limit) is not int
            or not 1 <= limit <= 500
        ):
            raise ValueError("invalid advisory pagination")
        rows = self._db.execute(
            "SELECT * FROM advisory_feed_revisions WHERE record_id IN "
            "(SELECT MAX(record_id) FROM advisory_feed_revisions "
            "WHERE source_id=? GROUP BY item_key) "
            "AND record_id>? ORDER BY record_id LIMIT ?",
            (source_id, after_id, limit),
        ).fetchall()
        return tuple(self._decode(row) for row in rows)

    def latest_with_state(
        self, source_id: str, *, after_id: int = 0, limit: int = 100
    ) -> tuple[tuple[dict[str, object], ...], AdvisoryPollState | None]:
        """Read one page and its source state in the same SQLite snapshot."""
        with self._db:
            self._db.execute("BEGIN")
            rows = self.latest(source_id, after_id=after_id, limit=limit)
            state = self.poll_state(source_id)
        return rows, state

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, object]:
        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate advisory metadata key")
                result[key] = value
            return result

        try:
            raw = row["metadata_json"]
            if not isinstance(raw, str) or len(raw.encode("utf-8")) > 262144:
                raise ValueError("invalid advisory metadata size")
            metadata = json.loads(raw, object_pairs_hook=unique)
            if not isinstance(metadata, dict) or set(metadata) != {
                "source_id",
                "item_key",
                "url",
                "title",
                "fingerprint",
                "source_fields",
                "cve_mentions",
            }:
                raise ValueError("invalid advisory metadata shape")
            fields = metadata["source_fields"]
            if not isinstance(fields, list) or any(
                not isinstance(pair, list)
                or len(pair) != 2
                or pair[0] in ("description", "content:encoded")
                for pair in fields
            ):
                raise ValueError("invalid stored advisory fields")
            item = AdvisoryFeedItem(
                metadata["source_id"],
                metadata["item_key"],
                metadata["url"],
                metadata["title"],
                tuple(tuple(pair) for pair in fields),
            )
            if item.identity != (row["source_id"], row["item_key"]) or (
                metadata["fingerprint"] != row["fingerprint"]
                or not re.fullmatch(r"[0-9a-f]{64}", row["fingerprint"])
            ):
                raise ValueError("advisory index mismatch")
            mentions = metadata["cve_mentions"]
            if not isinstance(mentions, list) or any(
                not isinstance(pair, list)
                or len(pair) != 2
                or not isinstance(pair[0], str)
                or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", pair[0])
                or pair[1] not in ("title", "description", "content:encoded")
                for pair in mentions
            ):
                raise ValueError("invalid advisory CVE mentions")
            if len(set(tuple(pair) for pair in mentions)) != len(mentions):
                raise ValueError("duplicate advisory CVE mention")
            first = datetime.fromisoformat(row["first_seen_at"])
            last = datetime.fromisoformat(row["last_seen_at"])
            if first.utcoffset() is None or last.utcoffset() is None or last < first:
                raise ValueError("invalid advisory observation times")
            return {
                "record_id": row["record_id"],
                "first_seen_at": first.isoformat(),
                "last_seen_at": last.isoformat(),
                "metadata": metadata,
            }
        except (KeyError, TypeError, RecursionError, UnicodeError) as exc:
            raise ValueError("invalid stored advisory metadata") from exc
