"""Publish a complete snapshot without overwriting previous evidence."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def save_poc_snapshot(path: Path, snapshot: dict[str, object]) -> None:
    content = json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n"
    if len(content.encode("utf-8")) > 5 * 1024 * 1024:
        raise ValueError("PoC snapshot exceeds the 5 MiB reader limit")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = stream.name
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # link fails if the destination already exists, including a symlink.
        os.link(temporary, path)
    finally:
        if temporary is not None:
            Path(temporary).unlink()
