"""Non-blocking local process locks; never hold a SQLite transaction on the network."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sbom_ops.domain.poc import PocRunBusy


def poc_lock_path(db_path: str | Path, *, job: bool = False) -> Path:
    suffix = ".poc-job.lock" if job else ".poc.lock"
    return Path(str(Path(db_path).resolve()) + suffix)


@contextmanager
def exclusive_run(path: Path) -> Iterator[None]:
    try:
        import fcntl
    except ImportError as exc:
        raise ValueError("PoC updates require Unix local file locking") from exc
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("PoC lock must be a regular file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise PocRunBusy("PoC operation is already running") from None
            raise
        yield
    finally:
        # Closing releases the OS lock, even after exceptions. Never unlink the
        # file: replacing its inode would let a new process bypass a live lock.
        os.close(descriptor)
