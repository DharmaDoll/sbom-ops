from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


def append_sync_event(path: str, payload: Mapping[str, Any]) -> bool:
    """Append one JSONL sync event.

    Returns ``False`` when the optional sink cannot be written. A logging sink
    must never replace the primary sync result, so callers can deliberately
    continue while reporting the failure through their normal channel.
    """
    try:
        with open(path, "a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except OSError:
        return False
    return True
