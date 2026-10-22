"""Catalog membership evidence; independent of priority and transport."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from sbom_ops.domain.triage_evidence import TriageValue

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")


def catalog_details(payload: object) -> dict[str, object] | None:
    """Check the declared catalog's ID coverage, not every advisory field."""
    if not isinstance(payload, dict):
        return None
    version = payload.get("catalogVersion")
    released = payload.get("dateReleased")
    count = payload.get("count")
    rows = payload.get("vulnerabilities")
    if (
        not isinstance(version, str)
        or not version.strip()
        or len(version) > 256
        or not version.isprintable()
        or not isinstance(released, str)
        or len(released) > 64
        or type(count) is not int
        or count < 0
        or not isinstance(rows, list)
        or len(rows) != count
    ):
        return None
    try:
        timestamp = datetime.fromisoformat(released)
        if timestamp.utcoffset() is None:
            return None
        timestamp = timestamp.astimezone(UTC)
    except (ValueError, OverflowError):
        return None
    ids = []
    for row in rows:
        value = row.get("cveID") if isinstance(row, dict) else None
        if not isinstance(value, str) or _CVE.fullmatch(value) is None:
            return None
        ids.append(value)
    if len(set(ids)) != count:
        return None
    return {"version": version, "released_at": timestamp.isoformat(), "count": count}


@dataclass(frozen=True)
class KevSnapshot:
    source: str
    cve_ids: frozenset[str]
    checked_at: datetime
    expires_at: datetime
    mode: str
    catalog_version: str | None = None
    released_at: datetime | None = None
    complete: bool = False
    etag: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("KEV source is required")
        if self.mode not in {"fetched", "cache", "revalidated", "stale"}:
            raise ValueError("invalid KEV retrieval mode")
        if type(self.complete) is not bool:
            raise ValueError("KEV completeness must be boolean")
        if not isinstance(self.cve_ids, (set, frozenset)) or not all(
            isinstance(value, str) for value in self.cve_ids
        ):
            raise ValueError("KEV IDs must be a set of strings")
        object.__setattr__(self, "cve_ids", frozenset(self.cve_ids))
        for field in ("checked_at", "expires_at", "released_at"):
            value = getattr(self, field)
            if field == "released_at" and value is None:
                continue
            if not isinstance(value, datetime) or value.utcoffset() is None:
                raise ValueError("KEV timestamps must be timezone-aware")
            object.__setattr__(self, field, value.astimezone(UTC))
        if self.expires_at < self.checked_at:
            raise ValueError("KEV expiry precedes retrieval")
        if (
            self.complete
            and catalog_details(
                {
                    "catalogVersion": self.catalog_version,
                    "dateReleased": (
                        self.released_at.isoformat() if self.released_at else None
                    ),
                    "count": len(self.cve_ids),
                    "vulnerabilities": [{"cveID": value} for value in self.cve_ids],
                }
            )
            is None
        ):
            raise ValueError(
                "complete KEV snapshot requires catalog provenance and IDs"
            )

    @property
    def revision(self) -> str:
        material = json.dumps(
            [
                self.source,
                self.catalog_version,
                self.released_at.isoformat() if self.released_at else None,
                sorted(self.cve_ids),
            ],
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return "sha256:" + hashlib.sha256(material.encode()).hexdigest()

    def membership(self, cve: str, *, now: datetime) -> TriageValue:
        """Unknown is not absence; freshness is evaluated at the supplied instant."""
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise ValueError("KEV evaluation time must be timezone-aware")
        now = now.astimezone(UTC)
        if (
            not isinstance(cve, str)
            or _CVE.fullmatch(cve) is None
            or not self.complete
            or self.mode == "stale"
            or not self.checked_at <= now < self.expires_at
            or self.released_at is None
            or self.released_at > self.checked_at
        ):
            return TriageValue.UNKNOWN
        return TriageValue.YES if cve in self.cve_ids else TriageValue.NO
