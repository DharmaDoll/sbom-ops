from __future__ import annotations

from urllib.request import Request, urlopen

from sbom_ops.clients.http import HttpApiError, request_json


class KevApiError(RuntimeError):
    """Raised when the CISA KEV feed cannot be retrieved."""


class KevClient:
    def __init__(
        self,
        feed_url: str,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_backoff_seconds: float = 1.0,
    ) -> None:
        self._feed_url = feed_url
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_backoff_seconds = retry_backoff_seconds

    def get_known_exploited_vulnerabilities(self) -> set[str]:
        request = Request(self._feed_url, headers={"Accept": "application/json"})
        try:
            payload = request_json(
                request,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._retry_backoff_seconds,
                error_message="CISA KEV request failed",
                opener=urlopen,
            )
        except HttpApiError as exc:
            detail = f" (HTTP {exc.status})" if exc.status else ""
            raise KevApiError(f"CISA KEV request failed{detail}") from exc
        if not isinstance(payload, dict):
            raise KevApiError("CISA KEV response was not an object")
        return {
            str(item["cveID"])
            for item in payload.get("vulnerabilities", [])
            if item.get("cveID")
        }
