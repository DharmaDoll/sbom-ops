"""PoC tables in the shared local SQLite DB; no asset or priority business rules."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

from sbom_ops.domain.advisory import (
    AdvisorySnapshot,
    EvidenceFreshness,
    EvidenceOutcome,
    VulnerabilityEvidenceObservation,
)
from sbom_ops.domain.poc import PocRecord

POC_SCHEMA = """
CREATE TABLE poc_observations (
    cve TEXT NOT NULL,
    source TEXT NOT NULL,
    last_attempt_at TEXT NOT NULL,
    last_error TEXT,
    last_http_status INTEGER,
    outcome TEXT CHECK(outcome IN ('available', 'not_observed')),
    observed_at TEXT,
    expires_at TEXT,
    record_count INTEGER CHECK(record_count >= 0),
    complete INTEGER CHECK(complete IN (0, 1)),
    PRIMARY KEY(cve, source),
    CHECK (outcome != 'available' OR record_count > 0),
    CHECK (outcome != 'not_observed' OR (record_count = 0 AND complete = 1)),
    CHECK (
        (outcome IS NULL AND observed_at IS NULL AND expires_at IS NULL
         AND record_count IS NULL AND complete IS NULL)
        OR (outcome IS NOT NULL AND observed_at IS NOT NULL AND expires_at IS NOT NULL
            AND record_count IS NOT NULL AND complete IS NOT NULL)
    )
)
"""


class PocStore:
    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self._db = sqlite3.connect(
            f"{Path(path).resolve().as_uri()}?mode={'ro' if read_only else 'rw'}",
            uri=True,
            timeout=5.0,
        )
        try:
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version != 6:
                raise ValueError(
                    "PoC storage requires schema v6; back up and migrate the DB"
                )
            self._db.row_factory = sqlite3.Row
        except (sqlite3.Error, ValueError):
            self._db.close()
            raise

    def __enter__(self) -> PocStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._db.close()

    @staticmethod
    def _record(row: sqlite3.Row) -> PocRecord:
        success = None
        # Validate persisted times too: damaged cache must not become fresh evidence.
        attempted = datetime.fromisoformat(row["last_attempt_at"])
        if attempted.tzinfo is None:
            raise ValueError("PoC attempt timestamp must include a timezone")
        if row["outcome"] is not None:
            observed = datetime.fromisoformat(row["observed_at"])
            expires = datetime.fromisoformat(row["expires_at"])
            if observed.tzinfo is None or expires.tzinfo is None or expires <= observed:
                raise ValueError("invalid PoC observation timestamps")
            success = VulnerabilityEvidenceObservation(
                vulnerability_id=row["cve"],
                source=row["source"],
                signal="published_poc",
                outcome=EvidenceOutcome(row["outcome"]),
                observed_at=row["observed_at"],
                source_revision=None,
                freshness=EvidenceFreshness.FRESH,
                record_count=row["record_count"],
                complete=bool(row["complete"]),
                expires_at=row["expires_at"],
            )
        return PocRecord(
            row["cve"],
            row["source"],
            row["last_attempt_at"],
            success,
            row["last_error"],
            row["last_http_status"],
        )

    def get(self, cve: str, source: str) -> PocRecord | None:
        row = self._db.execute(
            "SELECT * FROM poc_observations WHERE cve = ? AND source = ?",
            (cve, source),
        ).fetchone()
        return self._record(row) if row else None

    def save(self, record: PocRecord) -> None:
        success = record.success
        with self._db:
            self._db.execute(
                "INSERT INTO poc_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(cve, source) DO UPDATE SET "
                "last_attempt_at=excluded.last_attempt_at, "
                "last_error=excluded.last_error, "
                "last_http_status=excluded.last_http_status, "
                + ", ".join(
                    f"{column}=CASE WHEN excluded.last_error IS NULL "
                    f"THEN excluded.{column} ELSE poc_observations.{column} END"
                    for column in (
                        "outcome",
                        "observed_at",
                        "expires_at",
                        "record_count",
                        "complete",
                    )
                ),
                (
                    record.cve,
                    record.source,
                    record.last_attempt_at,
                    record.error,
                    record.http_status,
                    success.outcome.value if success else None,
                    success.observed_at if success else None,
                    success.expires_at if success else None,
                    success.record_count if success else None,
                    int(success.complete) if success else None,
                ),
            )

    def snapshot(self) -> AdvisorySnapshot:
        rows = self._db.execute(
            "SELECT * FROM poc_observations ORDER BY cve, source LIMIT 10001"
        ).fetchall()
        if len(rows) > 10000:
            raise ValueError("PoC database exceeds the 10,000 observation reader limit")
        return AdvisorySnapshot(
            snapshot_id="sqlite-poc",
            generated_at=datetime.now(UTC).isoformat(),
            vulnerability_observations=tuple(
                self._record(row).observation() for row in rows
            ),
            project_exposure=(),
        )
