"""Append-only CISA snapshots in the shared asset database."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import TracebackType

from sbom_ops.domain.vulnrichment import validate_request
from sbom_ops.domain.vulnrichment_snapshot import VulnrichmentSnapshot

VULNRICHMENT_SCHEMA = """
CREATE TABLE vulnrichment_snapshots (
    snapshot_id INTEGER PRIMARY KEY,
    cve TEXT NOT NULL,
    revision TEXT NOT NULL,
    snapshot_json TEXT NOT NULL
        CHECK(length(CAST(snapshot_json AS BLOB)) <= 2097152)
)
"""


class VulnrichmentStore:
    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self._db = sqlite3.connect(
            f"{Path(path).resolve().as_uri()}?mode={'ro' if read_only else 'rw'}",
            uri=True,
            timeout=5.0,
        )
        try:
            if self._db.execute("PRAGMA user_version").fetchone()[0] != 10:
                raise ValueError(
                    "CISA storage requires schema v10; back up and migrate"
                )
        except (sqlite3.Error, ValueError):
            self._db.close()
            raise

    def __enter__(self) -> VulnrichmentStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._db.close()

    def save(self, snapshot: VulnrichmentSnapshot) -> int:
        serialized = snapshot.to_json()
        validated = VulnrichmentSnapshot.from_json(serialized)
        with self._db:
            cursor = self._db.execute(
                "INSERT INTO vulnrichment_snapshots (cve, revision, snapshot_json) "
                "VALUES (?, ?, ?)",
                (validated.cve, validated.revision, serialized),
            )
            return int(cursor.lastrowid)

    def get(
        self,
        snapshot_id: int,
        *,
        cve: str,
        revision: str,
    ) -> VulnrichmentSnapshot | None:
        validate_request(cve, revision)
        if type(snapshot_id) is not int or snapshot_id <= 0:
            raise ValueError("snapshot ID must be a positive integer")
        row = self._db.execute(
            "SELECT cve, revision, snapshot_json FROM vulnrichment_snapshots "
            "WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            return None
        if row[0] != cve or row[1] != revision:
            raise ValueError("CISA snapshot target mismatch")
        snapshot = VulnrichmentSnapshot.from_json(row[2])
        if snapshot.cve != cve or snapshot.revision != revision:
            raise ValueError("CISA snapshot index and payload mismatch")
        return snapshot
