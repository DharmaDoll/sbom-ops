from __future__ import annotations

import json
import time
from pathlib import Path
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
        cache_path: str | None = None,
        cache_ttl_seconds: float = 18_000.0,
        allow_stale_cache: bool = False,
    ) -> None:
        self._feed_url = feed_url
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_backoff_seconds = retry_backoff_seconds
        self._cache_path = Path(cache_path) if cache_path else None
        self._cache_ttl_seconds = cache_ttl_seconds
        self._allow_stale_cache = allow_stale_cache
        self.used_stale_cache = False

    def get_known_exploited_vulnerabilities(self) -> set[str]:
        self.used_stale_cache = False
        cached = self._read_fresh_cache()
        if cached is not None:
            return cached
        cached_record = self._read_cache()
        headers = {"Accept": "application/json"}
        if cached_record is not None:
            metadata = cached_record[2]
            if metadata.get("etag"):
                headers["If-None-Match"] = metadata["etag"]
            if metadata.get("last_modified"):
                headers["If-Modified-Since"] = metadata["last_modified"]
        request = Request(self._feed_url, headers=headers)
        try:
            payload, response_headers = request_json(
                request,
                timeout=self._timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._retry_backoff_seconds,
                error_message="CISA KEV request failed",
                opener=urlopen,
                return_headers=True,
                allow_not_modified=True,
            )
        except HttpApiError as exc:
            if exc.status == 304 and cached_record is not None:
                self._write_cache(cached_record[1], cached_record[2])
                return cached_record[1]
            detail = f" (HTTP {exc.status})" if exc.status else ""
            if self._allow_stale_cache:
                stale = self._read_cache()
                if stale is not None:
                    self.used_stale_cache = True
                    return stale[1]
            raise KevApiError(f"CISA KEV request failed{detail}") from exc
        if not isinstance(payload, dict):
            raise KevApiError("CISA KEV response was not an object")
        cve_ids = {
            str(item["cveID"])
            for item in payload.get("vulnerabilities", [])
            if item.get("cveID")
        }
        self._write_cache(
            cve_ids,
            {
                "etag": response_headers.get("ETag"),
                "last_modified": response_headers.get("Last-Modified"),
            },
        )
        return cve_ids

    def _read_fresh_cache(self) -> set[str] | None:
        cached = self._read_cache()
        if cached is None:
            return None
        fetched_at, cve_ids, _ = cached
        if time.time() - fetched_at > self._cache_ttl_seconds:
            return None
        return cve_ids

    def _read_cache(self) -> tuple[float, set[str], dict[str, str]] | None:
        if self._cache_path is None or self._cache_ttl_seconds < 0:
            return None
        try:
            cached = json.loads(self._cache_path.read_text(encoding="utf-8"))
            fetched_at = float(cached["fetched_at"])
            cve_ids = cached["cve_ids"]
            if not isinstance(cve_ids, list) or not all(
                isinstance(item, str) for item in cve_ids
            ):
                return None
            metadata = cached.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
            return (
                fetched_at,
                set(cve_ids),
                {
                    key: value
                    for key, value in metadata.items()
                    if key in {"etag", "last_modified"} and isinstance(value, str)
                },
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _write_cache(
        self, cve_ids: set[str], metadata: dict[str, str | None] | None = None
    ) -> None:
        if self._cache_path is None:
            return
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(
                json.dumps(
                    {
                        "fetched_at": time.time(),
                        "cve_ids": sorted(cve_ids),
                        "metadata": {
                            key: value
                            for key, value in (metadata or {}).items()
                            if value
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
        except OSError:
            # Cache persistence is an optimization; a successful feed fetch wins.
            return
