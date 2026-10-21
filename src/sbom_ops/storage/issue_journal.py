"""Local durable create intents. No HTTP calls and no automatic deletion/reset."""

from __future__ import annotations

import errno
import json
import os
import sqlite3
import stat
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from uuid import uuid4

from sbom_ops.domain.issue_intent import (
    IssueCreateIntent,
    IssueIntentError,
    IssueJournalBusy,
)
from sbom_ops.domain.workflow_audit import WorkflowEvent

_APPLICATION_ID = 0x53424F57
_AUDIT_SCHEMA = """
CREATE TABLE workflow_events (
    sequence INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    event_json TEXT NOT NULL
)
"""
_SCHEMA = """
CREATE TABLE issue_create_intents (
    intent_id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    run_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending', 'confirmed')),
    created_at TEXT NOT NULL,
    issue_number INTEGER,
    confirmed_at TEXT,
    confirmed_run_id TEXT,
    UNIQUE(repository, finding_key),
    CHECK ((state = 'pending' AND issue_number IS NULL AND confirmed_at IS NULL
            AND confirmed_run_id IS NULL)
        OR (state = 'confirmed' AND issue_number IS NOT NULL AND issue_number > 0
            AND confirmed_at IS NOT NULL
            AND confirmed_run_id IS NOT NULL))
)
"""


class IssueJournal:
    @staticmethod
    def initialize(path: str | Path) -> None:
        # Explicit init only. O_EXCL refuses an existing DB, including symlinks.
        descriptor = os.open(
            path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        os.close(descriptor)
        db = sqlite3.connect(path)
        try:
            with db:
                db.execute(_SCHEMA)
                db.execute(_AUDIT_SCHEMA)
                db.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                db.execute("PRAGMA user_version = 2")
        finally:
            db.close()

    def __init__(
        self, path: str | Path, *, read_only: bool = False, _allow_legacy: bool = False
    ) -> None:
        import fcntl

        self.read_only = read_only
        self._descriptor = os.open(
            path,
            (os.O_RDONLY if read_only else os.O_RDWR) | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        self._db: sqlite3.Connection | None = None
        try:
            info = os.fstat(self._descriptor)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                raise IssueIntentError(
                    "workflow journal must be a private regular file (0600)"
                )
            try:
                fcntl.flock(
                    self._descriptor,
                    (fcntl.LOCK_SH if read_only else fcntl.LOCK_EX) | fcntl.LOCK_NB,
                )
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    raise IssueJournalBusy(
                        "workflow journal is already in use"
                    ) from None
                raise
            self._db = sqlite3.connect(
                f"{Path(path).absolute().as_uri()}?mode={'ro' if read_only else 'rw'}",
                uri=True,
                timeout=5.0,
            )
            current = os.stat(path, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise IssueIntentError("workflow journal changed while opening")
            self._db.row_factory = sqlite3.Row
            if (
                self._db.execute("PRAGMA application_id").fetchone()[0]
                != _APPLICATION_ID
                or self.schema_version not in (1, 2)
                or self._db.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
                or self._db.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
            ):
                raise IssueIntentError(
                    "invalid workflow journal; do not reset or replace it"
                )
            self._db.execute("PRAGMA synchronous = FULL")
            self.records()  # Validate persisted state before permitting a write.
            if self.schema_version == 1 and not (read_only or _allow_legacy):
                raise IssueIntentError(
                    "workflow journal needs workflow migrate --backup PATH; "
                    "do not reinitialize"
                )
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> IssueJournal:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
        if self._descriptor is not None:
            # Releases flock; never replace/unlink the inode.
            os.close(self._descriptor)
            self._descriptor = None

    def records(self) -> tuple[IssueCreateIntent, ...]:
        assert self._db is not None
        return tuple(
            IssueCreateIntent(**dict(row))
            for row in self._db.execute(
                "SELECT * FROM issue_create_intents ORDER BY created_at, intent_id"
            )
        )

    @property
    def schema_version(self) -> int:
        assert self._db is not None
        return self._db.execute("PRAGMA user_version").fetchone()[0]

    @classmethod
    def migrate(cls, path: str | Path, backup_path: str | Path) -> None:
        with cls(path, _allow_legacy=True) as journal:
            if journal.schema_version != 1:
                raise IssueIntentError("workflow journal is already current")
            descriptor = os.open(
                backup_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
            )
            os.close(descriptor)
            assert journal._db is not None
            backup = sqlite3.connect(backup_path)
            try:
                journal._db.backup(backup)
                if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise IssueIntentError("workflow backup integrity check failed")
            finally:
                backup.close()
            # Explicit transaction includes both DDL and version change.
            with journal._db:
                journal._db.execute("BEGIN IMMEDIATE")
                journal._db.execute(_AUDIT_SCHEMA)
                journal._db.execute("PRAGMA user_version = 2")

    def append_event(self, event: WorkflowEvent) -> None:
        assert self._db is not None
        with self._db:
            self._db.execute(
                "INSERT INTO workflow_events(event_id, run_id, event_json) "
                "VALUES (?, ?, ?)",
                (
                    event.event_id,
                    event.run_id,
                    json.dumps(event.as_dict(), ensure_ascii=False),
                ),
            )

    def events(self, run_id: str | None = None) -> tuple[WorkflowEvent, ...]:
        assert self._db is not None
        if self.schema_version == 1:
            return ()
        query = "SELECT event_id, run_id, event_json FROM workflow_events"
        params = () if run_id is None else (run_id,)
        if run_id is not None:
            query += " WHERE run_id = ?"
        rows = self._db.execute(query + " ORDER BY sequence", params)
        result = []
        for row in rows:
            try:
                value = json.loads(row[2])
                value["labels"] = tuple(value["labels"])
                event = WorkflowEvent(**value)
                if (event.event_id, event.run_id) != (row[0], row[1]):
                    raise ValueError("event identity mismatch")
                result.append(event)
            except (ValueError, TypeError, KeyError) as exc:
                raise IssueIntentError("invalid workflow audit record") from exc
        return tuple(result)

    def reserve(
        self, repository: str, finding_key: str, run_id: str
    ) -> IssueCreateIntent:
        assert self._db is not None
        intent = IssueCreateIntent(
            str(uuid4()),
            repository.lower(),
            finding_key,
            run_id,
            "pending",
            datetime.now(UTC).isoformat(),
        )
        try:
            with self._db:
                self._db.execute(
                    "INSERT INTO issue_create_intents VALUES "
                    "(:intent_id, :repository, :finding_key, :run_id, :state, "
                    ":created_at, :issue_number, :confirmed_at, :confirmed_run_id)",
                    asdict(intent),
                )
        except sqlite3.IntegrityError as exc:
            raise IssueIntentError(
                "create intent already exists; reconcile before writing"
            ) from exc
        # Transaction has committed before the caller is allowed to POST.
        return intent

    def confirm(
        self, intent: IssueCreateIntent, issue_number: int, run_id: str
    ) -> None:
        assert self._db is not None
        if (
            type(issue_number) is not int
            or issue_number <= 0
            or not isinstance(run_id, str)
            or not run_id.strip()
        ):
            raise IssueIntentError("invalid confirmed issue number")
        with self._db:
            changed = self._db.execute(
                "UPDATE issue_create_intents SET state='confirmed', issue_number=?, "
                "confirmed_at=?, confirmed_run_id=? "
                "WHERE intent_id=? AND state='pending'",
                (issue_number, datetime.now(UTC).isoformat(), run_id, intent.intent_id),
            ).rowcount
            if changed != 1:
                raise IssueIntentError("create intent is not pending")
