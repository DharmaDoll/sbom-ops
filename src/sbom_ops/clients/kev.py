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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.request import Request, urlopen

from sbom_ops.clients.http import HttpApiError, request_json
from sbom_ops.domain.kev import KevSnapshot, catalog_details


class KevApiError(RuntimeError):
    """Raised when the CISA KEV feed cannot be retrieved."""


_CACHE_SCHEMA_VERSION = 2
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
        self.last_snapshot: KevSnapshot | None = None

    def get_snapshot(self, *, force_refresh: bool = False) -> KevSnapshot:
        self.get_known_exploited_vulnerabilities(force_refresh=force_refresh)
        assert self.last_snapshot is not None
        return self.last_snapshot

    def _snapshot(
        self,
        ids: set[str],
        checked: float,
        metadata: dict[str, str | None],
        catalog: dict[str, object] | None,
        mode: str,
    ) -> None:
        checked_at = datetime.fromtimestamp(checked, UTC)
        ttl = self._cache_ttl_seconds
        if not math.isfinite(ttl):
            raise KevApiError("KEV cache TTL must be finite")
        self.last_snapshot = KevSnapshot(
            source=self._feed_url,
            cve_ids=frozenset(ids),
            checked_at=checked_at,
            expires_at=checked_at + timedelta(seconds=max(0, ttl)),
            mode=mode,
            catalog_version=str(catalog["version"]) if catalog else None,
            released_at=(
                datetime.fromisoformat(str(catalog["released_at"])) if catalog else None
            ),
            complete=catalog is not None,
            etag=metadata.get("etag"),
        )

    def get_known_exploited_vulnerabilities(
        self, *, force_refresh: bool = False
    ) -> set[str]:
        self.used_stale_cache = False
        self.last_snapshot = None
        if self._cache_path is None:
            return self._get_from_feed(force_refresh=force_refresh)
        lock_path = self._cache_path.with_name(f"{self._cache_path.name}.lock.sqlite3")
        try:
            with _exclusive_cache_lock(lock_path, self._cache_lock_timeout_seconds):
                return self._get_from_feed(force_refresh=force_refresh)
        except TimeoutError as exc:
            raise KevApiError(str(exc)) from exc

    def _get_from_feed(self, *, force_refresh: bool) -> set[str]:
        cached_record = self._read_cache()
        if cached_record is not None and not force_refresh:
            checked, ids, metadata, catalog = cached_record
            if 0 <= time.time() - checked < self._cache_ttl_seconds:
                self._snapshot(ids, checked, metadata, catalog, "cache")
                return ids
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
                checked = time.time()
                self._snapshot(
                    cached_record[1],
                    checked,
                    cached_record[2],
                    cached_record[3],
                    "revalidated",
                )
                self._write_cache_unlocked(
                    cached_record[1], cached_record[2], cached_record[3], checked
                )
                return cached_record[1]
            detail = f" (HTTP {exc.status})" if exc.status else ""
            if self._allow_stale_cache:
                stale = self._read_cache()
                if stale is not None:
                    self.used_stale_cache = True
                    self._snapshot(stale[1], stale[0], stale[2], stale[3], "stale")
                    return stale[1]
            raise KevApiError(f"CISA KEV request failed{detail}") from exc
        if not isinstance(payload, dict):
            raise KevApiError("CISA KEV response was not an object")
        rows = payload.get("vulnerabilities", [])
        if not isinstance(rows, list) or any(
            not isinstance(item, dict) for item in rows
        ):
            raise KevApiError("CISA KEV vulnerabilities must be objects")
        cve_ids = {str(item["cveID"]) for item in rows if item.get("cveID")}
        metadata = {
            "etag": response_headers.get("ETag"),
            "last_modified": response_headers.get("Last-Modified"),
        }
        catalog = catalog_details(payload)
        checked = time.time()
        self._snapshot(cve_ids, checked, metadata, catalog, "fetched")
        self._write_cache_unlocked(cve_ids, metadata, catalog, checked)
        return cve_ids

    def _read_cache(
        self,
    ) -> tuple[float, set[str], dict[str, str], dict[str, object] | None] | None:
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
            catalog = None
            if schema_present:
                if type(schema_version) is not int or schema_version not in (1, 2):
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
                if schema_version == 2:
                    if (
                        cached.get("source") != self._feed_url
                        or "catalog" not in cached
                    ):
                        return None
                    catalog = cached["catalog"]
                    digest_payload.update(source=cached["source"], catalog=catalog)
                    if catalog is not None:
                        if not isinstance(catalog, dict):
                            return None
                        validated = catalog_details(
                            {
                                "catalogVersion": catalog.get("version"),
                                "dateReleased": catalog.get("released_at"),
                                "count": catalog.get("count"),
                                "vulnerabilities": [
                                    {"cveID": value} for value in cve_ids
                                ],
                            }
                        )
                        if validated is None or validated != catalog:
                            return None
                if not hmac.compare_digest(digest, _cache_digest(digest_payload)):
                    return None
            datetime.fromtimestamp(fetched_at, UTC)
            return (
                fetched_at,
                set(cve_ids),
                {
                    key: value
                    for key, value in metadata.items()
                    if key in {"etag", "last_modified"} and isinstance(value, str)
                },
                catalog,
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
        self,
        cve_ids: set[str],
        metadata: dict[str, str | None] | None = None,
        catalog: dict[str, object] | None = None,
        fetched_at: float | None = None,
    ) -> None:
        if self._cache_path is None:
            return
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            fetched_at = time.time() if fetched_at is None else fetched_at
            cache_payload: dict[str, object] = {
                "schema_version": _CACHE_SCHEMA_VERSION,
                "fetched_at": fetched_at,
                "cve_ids": sorted(cve_ids),
                "source": self._feed_url,
                "catalog": catalog,
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
