from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class HttpApiError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def request_json(
    request: Request,
    *,
    timeout: float,
    max_retries: int,
    backoff_seconds: float,
    error_message: str,
    opener: Any = urlopen,
) -> Any:
    """Fetch JSON with bounded retries for transient failures only."""
    retryable_statuses = {408, 429, 500, 502, 503, 504}
    attempts = max(0, max_retries) + 1
    for attempt in range(attempts):
        try:
            with opener(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code not in retryable_statuses or attempt == attempts - 1:
                raise HttpApiError(error_message, status=exc.code) from exc
            retry_after = exc.headers.get("Retry-After")
            try:
                delay = (
                    float(retry_after)
                    if retry_after
                    else backoff_seconds * (2**attempt)
                )
            except ValueError:
                delay = backoff_seconds * (2**attempt)
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt == attempts - 1:
                raise HttpApiError(error_message) from exc
            delay = backoff_seconds * (2**attempt)
        time.sleep(min(max(0.0, delay), 30.0))
    raise HttpApiError(error_message)


def collection_items(payload: Any, keys: tuple[str, ...]) -> list[Mapping[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    if isinstance(payload, Mapping):
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, Mapping)]
    return []
