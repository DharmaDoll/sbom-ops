from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.request import Request, urlopen

from sbom_ops.clients.http import HttpApiError, request_json


class KevApiError(RuntimeError):
    """Raised when the CISA KEV feed cannot be retrieved."""


_CACHE_SCHEMA_VERSION = 1
_CACHE_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@contextmanager
def _exclusive_cache_lock(path: Path, timeout_seconds: float) -> Iterator[None]:
    """Serialize refreshes with a local SQLite transaction released on exit."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        connection = sqlite3.connect(
            path, timeout=timeout_seconds, isolation_level=None
        )
    except sqlite3.Error as exc:
        raise OSError("unable to open KEV cache lock") from exc
    try:
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise OSError("unable to acquire KEV cache lock") from exc
            raise TimeoutError("KEV cache lock timed out") from exc
        try:
            yield
        finally:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error as exc:
                raise OSError("unable to release KEV cache lock") from exc
    finally:
        connection.close()


def _cache_digest(payload: dict[str, object]) -> str:
    serialized = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


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
        cache_lock_timeout_seconds: float | None = None,
    ) -> None:
        self._feed_url = feed_url
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_backoff_seconds = retry_backoff_seconds
        self._cache_path = Path(cache_path) if cache_path else None
        self._cache_ttl_seconds = cache_ttl_seconds
        self._allow_stale_cache = allow_stale_cache
        if cache_lock_timeout_seconds is not None and (
            not math.isfinite(cache_lock_timeout_seconds)
            or cache_lock_timeout_seconds <= 0
        ):
            raise ValueError("cache_lock_timeout_seconds must be a positive number")
        request_lock_bound = (
            max(0, max_retries + 1) * max(0.0, timeout)
            + max(0, max_retries) * 30.0
            + 5.0
        )
        self._cache_lock_timeout_seconds = (
            cache_lock_timeout_seconds
            if cache_lock_timeout_seconds is not None
            else max(30.0, request_lock_bound)
        )
        self.used_stale_cache = False

    def get_known_exploited_vulnerabilities(
        self, *, force_refresh: bool = False
    ) -> set[str]:
        self.used_stale_cache = False
        if self._cache_path is None:
            return self._get_from_feed(force_refresh=force_refresh)
        lock_path = self._cache_path.with_name(f"{self._cache_path.name}.lock.sqlite3")
        try:
            with _exclusive_cache_lock(lock_path, self._cache_lock_timeout_seconds):
                return self._get_from_feed(force_refresh=force_refresh)
        except TimeoutError as exc:
            raise KevApiError(str(exc)) from exc

    def _get_from_feed(self, *, force_refresh: bool) -> set[str]:
        cached = self._read_fresh_cache()
        if cached is not None and not force_refresh:
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
                self._write_cache_unlocked(cached_record[1], cached_record[2])
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
        self._write_cache_unlocked(
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
            if not isinstance(cached, dict):
                return None
            fetched_at_value = cached["fetched_at"]
            if isinstance(fetched_at_value, bool):
                return None
            fetched_at = float(fetched_at_value)
            if not math.isfinite(fetched_at) or fetched_at <= 0:
                return None
            cve_ids = cached["cve_ids"]
            if not isinstance(cve_ids, list) or not all(
                isinstance(item, str) for item in cve_ids
            ):
                return None
            metadata = cached.get("metadata", {})
            schema_present = "schema_version" in cached
            if not isinstance(metadata, dict):
                if schema_present:
                    return None
                metadata = {}
            schema_version = cached.get("schema_version")
            if schema_present:
                if type(schema_version) is not int or schema_version != 1:
                    return None
                if type(fetched_at_value) not in (int, float):
                    return None
                if not all(
                    key in {"etag", "last_modified"}
                    and isinstance(value, str)
                    and value
                    for key, value in metadata.items()
                ):
                    return None
                digest = cached.get("sha256")
                if (
                    not isinstance(digest, str)
                    or _CACHE_DIGEST_PATTERN.fullmatch(digest) is None
                ):
                    return None
                digest_payload = {
                    "schema_version": schema_version,
                    "fetched_at": fetched_at_value,
                    "cve_ids": cve_ids,
                    "metadata": metadata,
                }
                if not hmac.compare_digest(digest, _cache_digest(digest_payload)):
                    return None
            return (
                fetched_at,
                set(cve_ids),
                {
                    key: value
                    for key, value in metadata.items()
                    if key in {"etag", "last_modified"} and isinstance(value, str)
                },
            )
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            OverflowError,
            json.JSONDecodeError,
        ):
            return None

    def _write_cache(
        self, cve_ids: set[str], metadata: dict[str, str | None] | None = None
    ) -> None:
        if self._cache_path is None:
            return
        try:
            lock_path = self._cache_path.with_name(
                f"{self._cache_path.name}.lock.sqlite3"
            )
            with _exclusive_cache_lock(lock_path, self._cache_lock_timeout_seconds):
                self._write_cache_unlocked(cve_ids, metadata)
        except (OSError, TimeoutError):
            # Cache persistence is an optimization; a successful feed fetch wins.
            return

    def _write_cache_unlocked(
        self, cve_ids: set[str], metadata: dict[str, str | None] | None = None
    ) -> None:
        if self._cache_path is None:
            return
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            fetched_at = time.time()
            cache_payload: dict[str, object] = {
                "schema_version": _CACHE_SCHEMA_VERSION,
                "fetched_at": fetched_at,
                "cve_ids": sorted(cve_ids),
                "metadata": {
                    key: value for key, value in (metadata or {}).items() if value
                },
            }
            cache_payload["sha256"] = _cache_digest(cache_payload)
            self._cache_path.write_text(
                json.dumps(
                    cache_payload,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
        except OSError:
            # Cache persistence is an optimization; a successful feed fetch wins.
            return
