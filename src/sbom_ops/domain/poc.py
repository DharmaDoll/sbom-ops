"""Target selection and interpretation of provider-reported PoC sightings."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from sbom_ops.domain.advisory import (
    EvidenceFreshness,
    EvidenceOutcome,
    VulnerabilityEvidenceObservation,
)

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.IGNORECASE)


class PocRunBusy(RuntimeError):
    """Another local process already owns the PoC operation lock."""


@dataclass(frozen=True)
class PocTargets:
    cves: tuple[str, ...]
    unresolved: tuple[str, ...]

    def summary(self) -> dict[str, str | int]:
        if not self.cves:
            status = "no_resolvable_cves" if self.unresolved else "no_findings"
        else:
            status = "partially_resolved" if self.unresolved else "resolved"
        return {
            "status": status,
            "cve_count": len(self.cves),
            "unresolved_id_count": len(self.unresolved),
        }


@dataclass(frozen=True)
class PocRecord:
    cve: str
    source: str
    last_attempt_at: str
    success: VulnerabilityEvidenceObservation | None = None
    error: str | None = None
    http_status: int | None = None

    def needs_refresh(self, now: datetime, interval: timedelta) -> bool:
        if self.error or self.success is None:
            return True
        return (
            self.success.effective_freshness(now=now) is not EvidenceFreshness.FRESH
            or now >= datetime.fromisoformat(self.success.observed_at) + interval
        )

    def observation(self) -> VulnerabilityEvidenceObservation:
        if self.success is not None:
            return replace(
                self.success,
                freshness=(
                    EvidenceFreshness.UNKNOWN if self.error else self.success.freshness
                ),
                last_attempt_at=self.last_attempt_at,
                last_error=self.error,
                last_http_status=self.http_status,
            )
        attempted = datetime.fromisoformat(self.last_attempt_at)
        return VulnerabilityEvidenceObservation(
            vulnerability_id=self.cve,
            source=self.source,
            signal="published_poc",
            outcome=EvidenceOutcome.UNKNOWN,
            observed_at=self.last_attempt_at,
            source_revision=None,
            freshness=EvidenceFreshness.UNKNOWN,
            record_count=None,
            complete=False,
            expires_at=(attempted + timedelta(seconds=1)).isoformat(),
            last_attempt_at=self.last_attempt_at,
            last_error=self.error,
            last_http_status=self.http_status,
        )


class PocFetchError(Exception):
    """Sanitized transport failure; never contains a response body or API key."""

    def __init__(
        self, code: str, *, status: int | None = None, retry_after: str | None = None
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.retry_after = retry_after


def select_poc_targets(payload: object, *, max_cves: int) -> PocTargets:
    if not 1 <= max_cves <= 1000:
        raise ValueError("max_cves must be between 1 and 1000")
    if not isinstance(payload, dict) or payload.get("status") != "succeeded":
        raise ValueError("PoC input must be a successful sync JSON result")
    rows = payload.get("assessments")
    if not isinstance(rows, list) or len(rows) > 100_000:
        raise ValueError("assessments must be an array of at most 100,000 findings")
    cves: set[str] = set()
    unresolved: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("assessment must be an object")
        identifier = row.get("vulnerability_id")
        aliases = row.get("vulnerability_aliases", [])
        if not isinstance(identifier, str) or not identifier.strip():
            raise ValueError("vulnerability_id must be a non-empty string")
        if not isinstance(aliases, list) or any(
            not isinstance(alias, str) for alias in aliases
        ):
            raise ValueError("vulnerability_aliases must be an array of strings")
        matches = {
            value.strip().upper()
            for value in (identifier, *aliases)
            if _CVE.fullmatch(value.strip())
        }
        cves.update(matches)
        if not matches:
            unresolved.add(identifier.strip())
    if len(cves) > max_cves:
        raise ValueError(
            "CVE count exceeds max_cves; narrow the input or raise the limit"
        )
    return PocTargets(tuple(sorted(cves)), tuple(sorted(unresolved)))


def interpret_poc_sightings(
    payload: object,
    *,
    cve: str,
    source: str,
    observed_at: datetime,
    ttl: timedelta,
) -> VulnerabilityEvidenceObservation:
    """Validate the first result and retain the source's count, not unique exploits."""
    if not isinstance(payload, dict):
        raise ValueError("invalid sighting envelope")
    meta, data = payload.get("metadata"), payload.get("data")
    if not isinstance(meta, dict) or not isinstance(data, list):
        raise ValueError("missing sighting metadata or data")
    count = meta.get("count")
    if type(count) is not int or not 0 <= count <= 2**63 - 1:
        raise ValueError("invalid sighting count")
    if (
        type(meta.get("page")) is not int
        or meta["page"] != 1
        or type(meta.get("per_page")) is not int
        or meta["per_page"] != 1
        or len(data) != min(count, 1)
    ):
        raise ValueError("inconsistent sighting page")
    for item in data:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("vulnerability"), str)
            or item["vulnerability"].upper() != cve
            or item.get("type") != "published-proof-of-concept"
        ):
            raise ValueError("sighting does not match requested CVE and type")
        timestamp = item.get("creation_timestamp")
        if not isinstance(timestamp, str):
            raise ValueError("missing sighting timestamp")
        event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if event_time.tzinfo is None or event_time > observed_at:
            raise ValueError("invalid or future sighting timestamp")
    return VulnerabilityEvidenceObservation(
        vulnerability_id=cve,
        source=source,
        signal="published_poc",
        outcome=EvidenceOutcome.AVAILABLE if count else EvidenceOutcome.NOT_OBSERVED,
        observed_at=observed_at.isoformat(),
        source_revision=None,
        freshness=EvidenceFreshness.FRESH,
        record_count=count,
        complete=count <= 1,
        expires_at=(observed_at + ttl).isoformat(),
    )
