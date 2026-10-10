from __future__ import annotations

import json
from pathlib import Path

from sbom_ops.domain.asset_import import (
    AssetRegistrationBatch,
    parse_asset_registration,
)

_MAX_BYTES = 1_048_576


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_asset_registration(path: str | Path) -> AssetRegistrationBatch:
    with Path(path).open("rb") as source:
        content = source.read(_MAX_BYTES + 1)
    if len(content) > _MAX_BYTES:
        raise ValueError("asset registration file exceeds 1 MiB")
    try:
        document = json.loads(content, object_pairs_hook=_unique_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("asset registration must be UTF-8 JSON") from exc
    return parse_asset_registration(document)
