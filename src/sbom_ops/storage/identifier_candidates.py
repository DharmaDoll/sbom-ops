"""Append-only candidate observations in the shared SQLite DB."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType

from sbom_ops.domain.identifier_candidates import IdentifierObservation
from sbom_ops.domain.identifier_review import IdentifierDecision

IDENTIFIER_SCHEMA = """
CREATE TABLE identifier_observations (
    observation_id INTEGER PRIMARY KEY,
    original_id TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    observation_json TEXT NOT NULL
)
"""

IDENTIFIER_REVIEW_SCHEMA = """
CREATE TABLE identifier_reviews (
    review_id INTEGER PRIMARY KEY,
    observation_id INTEGER NOT NULL REFERENCES identifier_observations(observation_id),
    original_id TEXT NOT NULL,
    dt_source TEXT NOT NULL,
    cve TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('approve', 'revoke')),
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    expires_at TEXT,
    CHECK ((action = 'approve' AND expires_at IS NOT NULL)
        OR (action = 'revoke' AND expires_at IS NULL))
)
"""


class IdentifierStore:
    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self._db = sqlite3.connect(
            f"{Path(path).resolve().as_uri()}?mode={'ro' if read_only else 'rw'}",
            uri=True,
            timeout=5.0,
        )
        self._db.execute("PRAGMA foreign_keys=ON")
        self.version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if self.version not in (8, 9):
            self._db.close()
            raise ValueError(
                "identifier candidates require schema v8; back up and migrate"
            )

    def __enter__(self) -> IdentifierStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._db.close()

    def save(self, observation: IdentifierObservation) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO identifier_observations "
                "(original_id, source, observed_at, observation_json) "
                "VALUES (?, ?, ?, ?)",
                (
                    observation.original_id,
                    observation.source,
                    observation.observed_at,
                    json.dumps(observation.as_dict(), ensure_ascii=False),
                ),
            )

    def recent(self, *, limit: int = 100) -> list[dict[str, object]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        return [
            {"observation_id": row[0], **json.loads(row[1])}
            for row in self._db.execute(
                "SELECT observation_id, observation_json FROM identifier_observations "
                "ORDER BY observation_id DESC LIMIT ?",
                (limit,),
            )
        ]

    def observation(self, observation_id: int) -> dict[str, object]:
        row = self._db.execute(
            "SELECT observation_json FROM identifier_observations "
            "WHERE observation_id=?",
            (observation_id,),
        ).fetchone()
        if row is None:
            raise ValueError("candidate observation not found")
        return {**json.loads(row[0]), "observation_id": observation_id}

    def latest_observation_id(self, original_id: str, source: str) -> int:
        return self._db.execute(
            "SELECT MAX(observation_id) FROM identifier_observations "
            "WHERE original_id=? AND source=?",
            (original_id, source),
        ).fetchone()[0]

    def require_reviews(self) -> None:
        if self.version < 9:
            raise ValueError(
                "identifier reviews require schema v9; back up and migrate"
            )

    def latest_review(
        self, original_id: str, dt_source: str
    ) -> dict[str, object] | None:
        self.require_reviews()
        cursor = self._db.execute(
            "SELECT * FROM identifier_reviews WHERE original_id=? AND dt_source=? "
            "ORDER BY review_id DESC LIMIT 1",
            (original_id, dt_source),
        )
        row = cursor.fetchone()
        return (
            dict(zip((column[0] for column in cursor.description), row, strict=True))
            if row
            else None
        )

    def reviews(self, *, limit: int = 100) -> list[dict[str, object]]:
        self.require_reviews()
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        cursor = self._db.execute(
            "SELECT * FROM identifier_reviews ORDER BY review_id DESC LIMIT ?", (limit,)
        )
        fields = [column[0] for column in cursor.description]
        return [dict(zip(fields, row, strict=True)) for row in cursor]

    @contextmanager
    def decision_transaction(self) -> Iterator[None]:
        self.require_reviews()
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            yield

    def append_decision(self, decision: IdentifierDecision) -> int:
        self.require_reviews()
        if not self._db.in_transaction:
            raise ValueError("decision requires an explicit transaction")
        cursor = self._db.execute(
            "INSERT INTO identifier_reviews (observation_id, original_id, dt_source, "
            "cve, action, actor, reason, decided_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                decision.observation_id,
                decision.original_id,
                decision.dt_source,
                decision.cve,
                decision.action,
                decision.actor,
                decision.reason,
                decision.decided_at,
                decision.expires_at,
            ),
        )
        return cursor.lastrowid
