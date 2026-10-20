"""Local durable create intents. No HTTP calls and no automatic deletion/reset."""

from __future__ import annotations

import errno
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

_APPLICATION_ID = 0x53424F57
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
                db.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                db.execute("PRAGMA user_version = 1")
        finally:
            db.close()

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
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
                or self._db.execute("PRAGMA user_version").fetchone()[0] != 1
                or self._db.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
                or self._db.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
            ):
                raise IssueIntentError(
                    "invalid workflow journal; do not reset or replace it"
                )
            self._db.execute("PRAGMA synchronous = FULL")
            self.records()  # Validate persisted state before permitting a write.
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
