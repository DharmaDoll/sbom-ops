"""Source-reported triage evidence, not priorities, deadlines or approvals.

Callers supply the observations for the selected source revisions. This module
never chooses a newer revision, resolves aliases, or verifies an asset binding.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum


class TriageFactor(StrEnum):
    PUBLIC_EXPOSURE = "public_exposure"
    KEV = "kev"
    AUTOMATABLE = "automatable"
    TECHNICAL_IMPACT = "technical_impact"
    KNOWN_EXPLOITATION = "known_exploitation"


class TriageValue(StrEnum):
    YES = "yes"
    NO = "no"
    TOTAL = "total"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class TriageEvidenceStatus(StrEnum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    EXPIRED = "expired"
    FUTURE = "future"
    CONFLICT = "conflict"


def _text(value: str, name: str) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 2048
        or not value.isprintable()
    ):
        raise ValueError(f"invalid {name}")


def _time(value: datetime) -> None:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("time must be a timezone-aware datetime")


@dataclass(frozen=True)
class VulnerabilityIdentity:
    identifier: str
    namespace: str

    def __post_init__(self) -> None:
        _text(self.identifier, "vulnerability identifier")
        _text(self.namespace, "vulnerability namespace")


@dataclass(frozen=True)
class AssetEvidenceScope:
    service_id: str
    deployable_id: str
    environment: str
    artifact_id: str
    project_uuid: str

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            _text(value, name)


@dataclass(frozen=True)
class EvidenceReview:
    """Declared review metadata; not authenticated identity or risk acceptance."""

    reviewer: str
    reason: str
    reviewed_at: datetime

    def __post_init__(self) -> None:
        _text(self.reviewer, "reviewer")
        _text(self.reason, "review reason")
        _time(self.reviewed_at)


@dataclass(frozen=True)
class TriageObservation:
    evidence_id: str
    vulnerability: VulnerabilityIdentity
    factor: TriageFactor
    value: TriageValue
    source: str
    source_record: str
    source_revision: str
    observed_at: datetime
    expires_at: datetime
    asset: AssetEvidenceScope | None = None
    review: EvidenceReview | None = None

    def __post_init__(self) -> None:
        for name in ("evidence_id", "source", "source_record", "source_revision"):
            _text(getattr(self, name), name)
        if not isinstance(self.vulnerability, VulnerabilityIdentity):
            raise ValueError("vulnerability identity required")
        if not isinstance(self.factor, TriageFactor) or not isinstance(
            self.value, TriageValue
        ):
            raise ValueError("typed triage factor and value required")
        allowed = (
            {TriageValue.TOTAL, TriageValue.PARTIAL, TriageValue.UNKNOWN}
            if self.factor is TriageFactor.TECHNICAL_IMPACT
            else {TriageValue.YES, TriageValue.NO, TriageValue.UNKNOWN}
        )
        if self.value not in allowed:
            raise ValueError("value does not belong to triage factor")
        if self.factor is TriageFactor.PUBLIC_EXPOSURE:
            if not isinstance(self.asset, AssetEvidenceScope):
                raise ValueError("public exposure requires an exact asset scope")
        elif self.asset is not None:
            raise ValueError("vulnerability evidence must not carry an asset scope")
        _time(self.observed_at)
        _time(self.expires_at)
        if self.expires_at.astimezone(UTC) <= self.observed_at.astimezone(UTC):
            raise ValueError("expiry must follow observation")
        if self.review is not None:
            if not isinstance(self.review, EvidenceReview):
                raise ValueError("invalid review metadata")
            if not (
                self.observed_at.astimezone(UTC)
                <= self.review.reviewed_at.astimezone(UTC)
                < self.expires_at.astimezone(UTC)
            ):
                raise ValueError("review must be within observation validity")

    def status_at(self, now: datetime) -> TriageEvidenceStatus:
        _time(now)
        instant = now.astimezone(UTC)
        if instant < self.observed_at.astimezone(UTC) or (
            self.review is not None
            and instant < self.review.reviewed_at.astimezone(UTC)
        ):
            return TriageEvidenceStatus.FUTURE
        if instant >= self.expires_at.astimezone(UTC):
            return TriageEvidenceStatus.EXPIRED
        if self.value is TriageValue.UNKNOWN:
            return TriageEvidenceStatus.UNKNOWN
        return TriageEvidenceStatus.KNOWN

    def as_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "vulnerability": asdict(self.vulnerability),
            "factor": self.factor.value,
            "reported_value": self.value.value,
            "source": self.source,
            "source_record": self.source_record,
            "source_revision": self.source_revision,
            "observed_at": self.observed_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "asset": asdict(self.asset) if self.asset else None,
            "review": (
                {
                    "reviewer": self.review.reviewer,
                    "reason": self.review.reason,
                    "reviewed_at": self.review.reviewed_at.isoformat(),
                }
                if self.review
                else None
            ),
        }


@dataclass(frozen=True)
class TriageSubject:
    finding_key: str
    vulnerability: VulnerabilityIdentity
    asset: AssetEvidenceScope | None = None
    asset_link_verified: bool = False

    def __post_init__(self) -> None:
        _text(self.finding_key, "finding key")
        if not isinstance(self.vulnerability, VulnerabilityIdentity):
            raise ValueError("vulnerability identity required")
        if type(self.asset_link_verified) is not bool:
            raise ValueError("asset link verification must be boolean")
        if self.asset is not None and not isinstance(self.asset, AssetEvidenceScope):
            raise ValueError("invalid asset scope")
        if self.asset_link_verified and self.asset is None:
            raise ValueError("verified asset link requires an asset scope")


@dataclass(frozen=True)
class FactorEvidence:
    factor: TriageFactor
    status: TriageEvidenceStatus
    value: TriageValue
    observations: tuple[TriageObservation, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class TriageEvidenceContext:
    subject: TriageSubject
    evaluated_at: datetime
    factors: tuple[FactorEvidence, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "finding_key": self.subject.finding_key,
            "vulnerability": asdict(self.subject.vulnerability),
            "asset": asdict(self.subject.asset) if self.subject.asset else None,
            "asset_link_verified": self.subject.asset_link_verified,
            "evaluated_at": self.evaluated_at.isoformat(),
            "factors": [
                {
                    "factor": item.factor.value,
                    "status": item.status.value,
                    "value": item.value.value,
                    "reasons": list(item.reasons),
                    "observations": [
                        {
                            **observation.as_dict(),
                            "effective_status": observation.status_at(
                                self.evaluated_at
                            ).value,
                        }
                        for observation in item.observations
                    ],
                }
                for item in self.factors
            ],
        }


def build_triage_evidence(
    subject: TriageSubject,
    observations: tuple[TriageObservation, ...],
    *,
    now: datetime,
) -> TriageEvidenceContext:
    """Resolve exact scope only, preserving uncertain and conflicting evidence."""
    if not isinstance(subject, TriageSubject):
        raise ValueError("typed triage subject required")
    if not isinstance(observations, tuple) or any(
        not isinstance(item, TriageObservation) for item in observations
    ):
        raise ValueError("observations must be a tuple of typed observations")
    if len({item.evidence_id for item in observations}) != len(observations):
        raise ValueError("duplicate evidence identifiers")
    _time(now)
    factors = []
    for factor in TriageFactor:
        matching = tuple(
            sorted(
                (
                    item
                    for item in observations
                    if item.factor is factor
                    and item.vulnerability == subject.vulnerability
                    and (
                        factor is not TriageFactor.PUBLIC_EXPOSURE
                        or item.asset == subject.asset
                    )
                ),
                key=lambda item: item.evidence_id,
            )
        )
        factors.append(
            _resolve_factor(
                factor,
                matching,
                now=now,
                asset_link_verified=subject.asset_link_verified,
            )
        )
    return TriageEvidenceContext(subject, now, tuple(factors))


def _resolve_factor(
    factor: TriageFactor,
    observations: tuple[TriageObservation, ...],
    *,
    now: datetime,
    asset_link_verified: bool,
) -> FactorEvidence:
    statuses = {item.status_at(now) for item in observations}
    values = {
        item.value
        for item in observations
        if item.status_at(now) is TriageEvidenceStatus.KNOWN
    }
    reasons = {
        f"{status.value}_observation"
        for status in statuses
        if status is not TriageEvidenceStatus.KNOWN
    }
    if not observations:
        reasons.add("no_matching_evidence")
    if len(values) > 1:
        reasons.add("conflicting_observations")
    unverified = factor is TriageFactor.PUBLIC_EXPOSURE and not asset_link_verified
    if unverified:
        reasons.add("asset_link_unverified")

    value = TriageValue.UNKNOWN
    if unverified or not observations:
        status = TriageEvidenceStatus.UNKNOWN
    elif len(values) > 1:
        status = TriageEvidenceStatus.CONFLICT
    elif statuses == {TriageEvidenceStatus.KNOWN}:
        status = TriageEvidenceStatus.KNOWN
        value = next(iter(values))
    elif statuses == {TriageEvidenceStatus.EXPIRED}:
        status = TriageEvidenceStatus.EXPIRED
    elif statuses == {TriageEvidenceStatus.FUTURE}:
        status = TriageEvidenceStatus.FUTURE
    else:
        # Never silently pick a newer revision or discard uncertain reports.
        status = TriageEvidenceStatus.UNKNOWN
    return FactorEvidence(factor, status, value, observations, tuple(sorted(reasons)))
