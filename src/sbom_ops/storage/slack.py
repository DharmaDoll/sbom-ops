"""Private, independently locked Slack delivery journal. No message bodies."""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from dataclasses import asdict
from pathlib import Path
from types import TracebackType

from sbom_ops.domain.slack import Delivery

_APPLICATION_ID = 0x53424F53
_SCHEMA = """
CREATE TABLE deliveries (
 intent_id TEXT PRIMARY KEY, channel TEXT NOT NULL, notification_key TEXT NOT NULL,
 fingerprint TEXT NOT NULL, event TEXT NOT NULL, run_id TEXT NOT NULL,
 state TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
 attempts INTEGER NOT NULL, retry_at REAL NOT NULL, ts TEXT, thread_ts TEXT,
 body_hash TEXT NOT NULL, error TEXT
);
CREATE TABLE audit (
 sequence INTEGER PRIMARY KEY, intent_id TEXT NOT NULL, state TEXT NOT NULL,
 at REAL NOT NULL, actor TEXT
);
"""


class SlackJournal:
    @staticmethod
    def initialize(path: str | Path) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        db = sqlite3.connect(path)
        try:
            db.executescript(_SCHEMA)
            db.execute(f"PRAGMA application_id={_APPLICATION_ID}")
            db.execute("PRAGMA user_version=1")
            db.commit()
        finally:
            db.close()

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        import fcntl

        self._db = None
        self._fd = os.open(
            path,
            (os.O_RDONLY if read_only else os.O_RDWR) | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        try:
            info = os.fstat(self._fd)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("Slack journal must be private regular file (0600)")
            fcntl.flock(
                self._fd,
                (fcntl.LOCK_SH if read_only else fcntl.LOCK_EX) | fcntl.LOCK_NB,
            )
            self._db = sqlite3.connect(
                f"{Path(path).absolute().as_uri()}?mode={'ro' if read_only else 'rw'}",
                uri=True,
            )
            current = os.stat(path, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("Slack journal changed while opening")
            self._db.row_factory = sqlite3.Row
            if (
                self._db.execute("PRAGMA application_id").fetchone()[0]
                != _APPLICATION_ID
                or self._db.execute("PRAGMA user_version").fetchone()[0] != 1
                or self._db.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
                or self._db.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
            ):
                raise ValueError("invalid Slack journal; never reset to retry")
            self._db.execute("PRAGMA synchronous=FULL")
            self.records()
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> SlackJournal:
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
        os.close(self._fd)

    def records(self) -> tuple[Delivery, ...]:
        rows = tuple(
            Delivery(**dict(r))
            for r in self._db.execute("SELECT * FROM deliveries ORDER BY rowid")
        )
        for row in rows:
            if (
                row.state
                not in ("pending", "confirmed", "unknown", "rejected", "rate_limited")
                or row.attempts < 1
                or (row.state == "confirmed" and not valid_ts(row.ts))
            ):
                raise ValueError("invalid Slack delivery state")
        return rows

    def reserve(self, row: Delivery) -> None:
        if row.state != "pending":
            raise ValueError("intent must start pending")
        with self._db:
            self._db.execute(
                "INSERT INTO deliveries VALUES ("
                + ",".join("?" for _ in asdict(row))
                + ")",
                tuple(asdict(row).values()),
            )
            self._db.execute(
                "INSERT INTO audit(intent_id,state,at) VALUES (?,?,?)",
                (row.intent_id, "pending", row.created_at),
            )

    def finish(
        self,
        intent_id: str,
        *,
        state: str,
        now: float,
        ts: str | None = None,
        error: str | None = None,
        retry_at: float = 0,
        actor: str | None = None,
    ) -> None:
        if state not in ("confirmed", "unknown", "rejected", "rate_limited"):
            raise ValueError("invalid delivery outcome")
        if state == "confirmed" and not valid_ts(ts):
            raise ValueError("invalid Slack timestamp")
        if actor is not None and (not re.fullmatch(r"[A-Za-z0-9_.@-]{1,120}", actor)):
            raise ValueError("invalid confirmation actor")
        with self._db:
            allowed = ("pending", "unknown") if actor else ("pending",)
            changed = self._db.execute(
                "UPDATE deliveries SET state=?, updated_at=?, ts=?, "
                "error=?, retry_at=? "
                "WHERE intent_id=? AND state IN ("
                + ",".join("?" for _ in allowed)
                + ")",
                (state, now, ts, error, retry_at, intent_id, *allowed),
            ).rowcount
            if changed != 1:
                raise ValueError("delivery is not awaiting confirmation")
            self._db.execute(
                "INSERT INTO audit(intent_id,state,at,actor) VALUES (?,?,?,?)",
                (intent_id, state, now, actor),
            )

    def audit(self) -> list[dict[str, object]]:
        return [
            dict(row)
            for row in self._db.execute("SELECT * FROM audit ORDER BY sequence")
        ]


def valid_ts(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9]{1,16}\.[0-9]{1,10}", value) is not None
    )
