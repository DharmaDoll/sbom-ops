from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class HttpApiError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class HttpJsonResponse:
    payload: Any
    status: int
    headers: dict[str, str]
    duration_seconds: float


def request_json(
    request: Request,
    *,
    timeout: float,
    max_retries: int,
    backoff_seconds: float,
    error_message: str,
    opener: Any = urlopen,
    allow_not_modified: bool = False,
    return_headers: bool = False,
    return_response: bool = False,
    allow_empty: bool = False,
) -> Any:
    """Fetch JSON with bounded retries for transient failures only."""
    if return_headers and return_response:
        raise ValueError("return_headers and return_response are mutually exclusive")
    retryable_statuses = {408, 429, 500, 502, 503, 504}
    attempts = max(0, max_retries) + 1
    started = time.monotonic()
    for attempt in range(attempts):
        try:
            with opener(request, timeout=timeout) as response:
                response_body = response.read()
                payload = (
                    None
                    if allow_empty and not response_body
                    else json.loads(response_body.decode("utf-8"))
                )
                response_headers = dict(getattr(response, "headers", {}).items())
                if return_response:
                    status = getattr(response, "status", None)
                    if status is None:
                        getcode = getattr(response, "getcode", None)
                        status = getcode() if callable(getcode) else 200
                    return HttpJsonResponse(
                        payload=payload,
                        status=int(status),
                        headers=response_headers,
                        duration_seconds=time.monotonic() - started,
                    )
                if return_headers:
                    return payload, response_headers
                return payload
        except HTTPError as exc:
            if allow_not_modified and exc.code == 304:
                raise HttpApiError(error_message, status=304) from exc
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
