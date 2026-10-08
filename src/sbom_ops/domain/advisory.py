from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


class EvidenceOutcome(StrEnum):
    AVAILABLE = "available"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"


class EvidenceFreshness(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


class ExposureStatus(StrEnum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class AdvisorySnapshotStatus(StrEnum):
    NOT_REQUESTED = "not_requested"
    LOADED = "loaded"
    INVALID = "invalid"


class PocReportStatus(StrEnum):
    REPORTED = "reported"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PocReportSummary:
    """Provider-reported public PoCs, not independently validated exploits."""

    status: PocReportStatus
    sources: tuple[VulnerabilityEvidenceObservation, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "sources": [
                {
                    "vulnerability_id": item.vulnerability_id,
                    "source": item.source,
                    "outcome": item.outcome.value,
                    "record_count": item.record_count,
                    "observed_at": item.observed_at,
                    "freshness": item.freshness.value,
                    "effective_freshness": item.effective_freshness().value,
                    "expires_at": item.expires_at,
                    "complete": item.complete,
                }
                for item in self.sources
            ],
        }


@dataclass(frozen=True)
class AdvisoryReference:
    record_id: str | None
    url: str
    provider: str | None
    kind: str
    upstream_type: str | None = None
    upstream_assertions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "url": self.url,
            "provider": self.provider,
            "kind": self.kind,
            "upstream_type": self.upstream_type,
            "upstream_assertions": list(self.upstream_assertions),
        }


@dataclass(frozen=True)
class VulnerabilityEvidenceObservation:
    vulnerability_id: str
    source: str
    signal: str
    outcome: EvidenceOutcome
    observed_at: str
    source_revision: str | None
    freshness: EvidenceFreshness
    record_count: int | None
    complete: bool
    references: tuple[AdvisoryReference, ...] = ()
    expires_at: str | None = None

    def effective_freshness(self, *, now: datetime | None = None) -> EvidenceFreshness:
        if self.freshness is not EvidenceFreshness.FRESH:
            return self.freshness
        if self.expires_at is None:
            return EvidenceFreshness.UNKNOWN
        current_time = now or datetime.now(UTC)
        expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if expires <= current_time:
            return EvidenceFreshness.STALE
        return EvidenceFreshness.FRESH

    def as_dict(self) -> dict[str, object]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "source": self.source,
            "signal": self.signal,
            "outcome": self.outcome.value,
            "observed_at": self.observed_at,
            "source_revision": self.source_revision,
            "freshness": self.freshness.value,
            "expires_at": self.expires_at,
            "record_count": self.record_count,
            "retained_record_count": len(self.references),
            "complete": self.complete,
            "references": [reference.as_dict() for reference in self.references],
        }


def summarize_poc_reports(
    observations: tuple[VulnerabilityEvidenceObservation, ...],
    *,
    now: datetime | None = None,
) -> PocReportSummary:
    """Summarize only explicit public-PoC signals, without summing providers."""
    sources = tuple(item for item in observations if item.signal == "published_poc")
    fresh = tuple(
        item
        for item in sources
        if item.effective_freshness(now=now) is EvidenceFreshness.FRESH
    )
    if any(item.outcome is EvidenceOutcome.AVAILABLE for item in fresh):
        status = PocReportStatus.REPORTED
    elif (
        sources
        and len(fresh) == len(sources)
        and all(item.outcome is EvidenceOutcome.NOT_OBSERVED for item in fresh)
    ):
        status = PocReportStatus.NOT_OBSERVED
    else:
        status = PocReportStatus.UNKNOWN
    return PocReportSummary(status=status, sources=sources)


@dataclass(frozen=True)
class ProjectExposureObservation:
    project_uuid: str
    environment: str
    status: ExposureStatus
    source: str
    observed_at: str
    expires_at: str
    reviewer: str | None = None

    def effective_status(self, *, now: datetime | None = None) -> ExposureStatus:
        current_time = now or datetime.now(UTC)
        expires_at = datetime.fromisoformat(self.expires_at)
        if expires_at <= current_time:
            return ExposureStatus.UNKNOWN
        return self.status

    def as_dict(self, *, now: datetime | None = None) -> dict[str, object]:
        return {
            "scope": "project_environment",
            "project_uuid": self.project_uuid,
            "environment": self.environment,
            "reported_status": self.status.value,
            "effective_status": self.effective_status(now=now).value,
            "source": self.source,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "reviewer": self.reviewer,
        }


@dataclass(frozen=True)
class AdvisorySnapshot:
    snapshot_id: str
    generated_at: str
    vulnerability_observations: tuple[VulnerabilityEvidenceObservation, ...]
    project_exposure: tuple[ProjectExposureObservation, ...]
    sha256: str | None = None

    def observations_for(
        self, vulnerability_id: str, aliases: tuple[str, ...] = ()
    ) -> tuple[VulnerabilityEvidenceObservation, ...]:
        identifiers = {
            identifier.strip().upper()
            for identifier in (vulnerability_id, *aliases)
            if isinstance(identifier, str) and identifier.strip()
        }
        return tuple(
            observation
            for observation in self.vulnerability_observations
            if observation.vulnerability_id.upper() in identifiers
        )

    def exposure_for_project(
        self, project_uuid: str
    ) -> tuple[ProjectExposureObservation, ...]:
        return tuple(
            observation
            for observation in self.project_exposure
            if observation.project_uuid == project_uuid
        )
