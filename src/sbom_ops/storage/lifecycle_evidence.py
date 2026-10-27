"""Append-only lifecycle evidence in the shared asset database."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

from sbom_ops.domain.asset_registry import validate_identifier
from sbom_ops.domain.lifecycle_evidence import (
    LifecycleEvidence,
    RecordedEvidence,
    parse_evidence,
    serialize_evidence,
    validate_correction,
)

LIFECYCLE_EVIDENCE_SCHEMA = """
CREATE TABLE lifecycle_evidence (
    record_id INTEGER PRIMARY KEY,
    service_id TEXT NOT NULL,
    deployable_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('source', 'build', 'unknown')),
    recorded_at TEXT NOT NULL,
    supersedes_id INTEGER UNIQUE REFERENCES lifecycle_evidence(record_id),
    evidence_json TEXT NOT NULL
        CHECK(length(CAST(evidence_json AS BLOB)) <= 65536),
    FOREIGN KEY (service_id, deployable_id)
        REFERENCES deployables(service_id, deployable_id),
    CHECK(supersedes_id IS NULL OR supersedes_id < record_id)
)
"""


class LifecycleEvidenceStore:
    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self._read_only = read_only
        self._db = sqlite3.connect(
            f"{Path(path).resolve().as_uri()}?mode={'ro' if read_only else 'rw'}",
            uri=True,
            timeout=5.0,
        )
        self._db.row_factory = sqlite3.Row
        try:
            self._db.execute("PRAGMA foreign_keys=ON")
            if self._db.execute("PRAGMA user_version").fetchone()[0] not in (11, 12):
                raise ValueError(
                    "lifecycle evidence requires schema v11; migrate first"
                )
        except (sqlite3.Error, ValueError):
            self._db.close()
            raise

    def __enter__(self) -> LifecycleEvidenceStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._db.close()

    @staticmethod
    def _decode(row: sqlite3.Row) -> RecordedEvidence:
        item = parse_evidence(row["evidence_json"])
        if (
            row["service_id"],
            row["deployable_id"],
            row["kind"],
            row["supersedes_id"],
        ) != (item.service_id, item.deployable_id, item.kind, item.supersedes_id):
            raise ValueError("inconsistent lifecycle evidence")
        recorded = datetime.fromisoformat(row["recorded_at"])
        if recorded.utcoffset() is None or row["record_id"] < 1:
            raise ValueError("invalid stored evidence metadata")
        return RecordedEvidence(row["record_id"], recorded.astimezone(UTC), item)

    def list_records(
        self, service_id: str, deployable_id: str
    ) -> tuple[RecordedEvidence, ...]:
        return self.read_records_from(self._db, service_id, deployable_id)

    @staticmethod
    def read_records_from(
        connection: sqlite3.Connection, service_id: str, deployable_id: str
    ) -> tuple[RecordedEvidence, ...]:
        """Read through a caller-owned transaction without committing it."""
        validate_identifier(service_id, label="service ID")
        validate_identifier(deployable_id, label="deployable ID")
        cursor = connection.cursor()
        cursor.row_factory = sqlite3.Row
        rows = cursor.execute(
            "SELECT * FROM lifecycle_evidence WHERE service_id=? AND deployable_id=? "
            "ORDER BY record_id",
            (service_id, deployable_id),
        ).fetchall()
        records = tuple(LifecycleEvidenceStore._decode(row) for row in rows)
        seen: dict[int, RecordedEvidence] = {}
        superseded: set[int] = set()
        for record in records:
            previous_id = record.evidence.supersedes_id
            if previous_id is not None:
                if previous_id not in seen or previous_id in superseded:
                    raise ValueError("inconsistent evidence correction history")
                validate_correction(
                    seen[previous_id].evidence,
                    record.evidence,
                    previous_id=previous_id,
                )
                superseded.add(previous_id)
            seen[record.record_id] = record
        return records

    def append(self, evidence: LifecycleEvidence) -> RecordedEvidence:
        if self._read_only:
            raise ValueError("lifecycle evidence store is read-only")
        raw = serialize_evidence(evidence)
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            scope = (evidence.service_id, evidence.deployable_id)
            if (
                self._db.execute(
                    "SELECT 1 FROM deployables WHERE service_id=? AND deployable_id=?",
                    scope,
                ).fetchone()
                is None
            ):
                raise ValueError("evidence requires a registered asset")
            if (
                self._db.execute(
                    "SELECT 1 FROM asset_lifecycle_events WHERE service_id=? AND "
                    "(action='retire_service' OR (action='retire_deployable' "
                    "AND deployable_id=?)) LIMIT 1",
                    scope,
                ).fetchone()
                is not None
            ):
                raise ValueError("cannot register evidence for a retired asset")
            if evidence.supersedes_id is not None:
                previous = self._db.execute(
                    "SELECT * FROM lifecycle_evidence WHERE record_id=?",
                    (evidence.supersedes_id,),
                ).fetchone()
                if previous is None:
                    raise ValueError("correction target does not exist")
                validate_correction(
                    self._decode(previous).evidence,
                    evidence,
                    previous_id=evidence.supersedes_id,
                )
                if (
                    self._db.execute(
                        "SELECT 1 FROM lifecycle_evidence WHERE supersedes_id=?",
                        (evidence.supersedes_id,),
                    ).fetchone()
                    is not None
                ):
                    raise ValueError("correction target is already superseded")
            recorded = datetime.now(UTC)
            cursor = self._db.execute(
                "INSERT INTO lifecycle_evidence "
                "(service_id,deployable_id,kind,recorded_at,"
                "supersedes_id,evidence_json) "
                "VALUES (?,?,?,?,?,?)",
                (
                    *scope,
                    evidence.kind,
                    recorded.isoformat(),
                    evidence.supersedes_id,
                    raw,
                ),
            )
            assert cursor.lastrowid is not None
            result = RecordedEvidence(cursor.lastrowid, recorded, evidence)
        return result
