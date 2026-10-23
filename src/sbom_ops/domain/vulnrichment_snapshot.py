"""Versioned CISA input snapshots for persistence without refreshing evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sbom_ops.domain.vulnrichment import (
    VULNRICHMENT_SOURCE,
    VulnrichmentError,
    VulnrichmentReport,
    interpret_vulnrichment,
)

MAX_RECORD_BYTES = 1024 * 1024
MAX_SNAPSHOT_BYTES = 2 * MAX_RECORD_BYTES


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VulnrichmentError("duplicate_snapshot_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise VulnrichmentError("invalid_snapshot_json")


def _decode(value: str, limit: int) -> object:
    try:
        if not isinstance(value, str) or len(value.encode("utf-8")) > limit:
            raise VulnrichmentError("snapshot_size_or_type")
        return json.loads(
            value, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, VulnrichmentError):
            raise
        raise VulnrichmentError("invalid_snapshot_json") from None


def _encode(value: object, limit: int) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(encoded.encode("utf-8")) > limit:
            raise VulnrichmentError("snapshot_size_or_type")
        return encoded
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, VulnrichmentError):
            raise
        raise VulnrichmentError("invalid_snapshot_json") from None


@dataclass(frozen=True)
class VulnrichmentSnapshot:
    cve: str
    revision: str
    retrieved_at: datetime
    max_age: timedelta
    record_json: str

    def __post_init__(self) -> None:
        # Validate persisted data as well as new input; never trust a cached verdict.
        self.report()

    @classmethod
    def capture(
        cls,
        payload: object,
        *,
        cve: str,
        revision: str,
        retrieved_at: datetime,
        max_age: timedelta,
    ) -> VulnrichmentSnapshot:
        return cls(
            cve, revision, retrieved_at, max_age, _encode(payload, MAX_RECORD_BYTES)
        )

    def to_json(self) -> str:
        # Integer microseconds avoid floating-point changes to the stored policy.
        age_us = (
            self.max_age.days * 86400 + self.max_age.seconds
        ) * 1000000 + self.max_age.microseconds
        return _encode(
            {
                "schema_version": 1,
                "source": VULNRICHMENT_SOURCE,
                "cve": self.cve,
                "revision": self.revision,
                "retrieved_at": self.retrieved_at.astimezone(UTC).isoformat(),
                "max_age_microseconds": age_us,
                "record": _decode(self.record_json, MAX_RECORD_BYTES),
            },
            MAX_SNAPSHOT_BYTES,
        )

    @classmethod
    def from_json(cls, value: str) -> VulnrichmentSnapshot:
        data = _decode(value, MAX_SNAPSHOT_BYTES)
        fields = {
            "schema_version",
            "source",
            "cve",
            "revision",
            "retrieved_at",
            "max_age_microseconds",
            "record",
        }
        if not isinstance(data, dict) or set(data) != fields:
            raise VulnrichmentError("invalid_snapshot_fields")
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise VulnrichmentError("unsupported_snapshot_version")
        if data["source"] != VULNRICHMENT_SOURCE:
            raise VulnrichmentError("snapshot_source_mismatch")
        age_us = data["max_age_microseconds"]
        retrieved = data["retrieved_at"]
        if type(age_us) is not int or age_us <= 0:
            raise VulnrichmentError("invalid_max_age")
        if not isinstance(retrieved, str) or len(retrieved) > 64:
            raise VulnrichmentError("invalid_retrieval_time")
        try:
            age = timedelta(microseconds=age_us)
            retrieved_at = datetime.fromisoformat(retrieved)
        except (ValueError, OverflowError):
            raise VulnrichmentError("invalid_snapshot_time") from None
        return cls.capture(
            data["record"],
            cve=data["cve"],
            revision=data["revision"],
            retrieved_at=retrieved_at,
            max_age=age,
        )

    def report(self) -> VulnrichmentReport:
        return interpret_vulnrichment(
            _decode(self.record_json, MAX_RECORD_BYTES),
            cve=self.cve,
            revision=self.revision,
            retrieved_at=self.retrieved_at,
            max_age=self.max_age,
        )
