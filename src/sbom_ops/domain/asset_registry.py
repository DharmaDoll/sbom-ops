from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.assets import BusinessCriticality, DeploymentStatus

_IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]*\Z")


def validate_identifier(value: str, *, label: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase identifier")
    return value


@dataclass(frozen=True)
class RegisteredService:
    service_id: str
    owner: str
    criticality: BusinessCriticality
    impact_reason: str

    def __post_init__(self) -> None:
        validate_identifier(self.service_id, label="service_id")
        if not self.owner.strip():
            raise ValueError("owner is required")
        if not self.impact_reason.strip():
            raise ValueError("impact_reason is required")


@dataclass(frozen=True)
class RegisteredDeployable:
    service_id: str
    deployable_id: str

    def __post_init__(self) -> None:
        validate_identifier(self.service_id, label="service_id")
        validate_identifier(self.deployable_id, label="deployable_id")

    @property
    def project_name(self) -> str:
        return f"{self.service_id}/{self.deployable_id}"


@dataclass(frozen=True)
class ReviewedProjectLink:
    project_uuid: str
    project_name: str
    project_version: str
    service_id: str
    deployable_id: str
    reviewer: str
    reviewed_at: str


@dataclass(frozen=True)
class ReportedDeployment:
    """An append-only human claim, not independently verified runtime evidence."""

    service_id: str
    deployable_id: str
    environment: str
    artifact_id: str
    deployment_status: DeploymentStatus
    exposure_status: ExposureStatus
    reviewer: str
    evidence: str
    observed_at: str
    expires_at: str
    report_id: int | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.service_id, label="service_id")
        validate_identifier(self.deployable_id, label="deployable_id")
        validate_identifier(self.environment, label="environment")
        if not self.artifact_id or self.artifact_id != self.artifact_id.strip():
            raise ValueError("artifact_id must be a non-empty exact identifier")
        if len(self.artifact_id) > 512 or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.artifact_id
        ):
            raise ValueError("artifact_id must be at most 512 printable characters")
        if not self.reviewer.strip() or not self.evidence.strip():
            raise ValueError("reviewer and evidence are required")
        if any(
            len(value) > limit
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            for value, limit in ((self.reviewer, 128), (self.evidence, 1000))
        ):
            raise ValueError(
                "reviewer or evidence contains control text or is too long"
            )
        try:
            observed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
            expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("deployment timestamps must be ISO-8601") from exc
        if (
            observed.tzinfo is None
            or expires.tzinfo is None
            or observed.utcoffset() is None
            or expires.utcoffset() is None
            or expires <= observed
        ):
            raise ValueError(
                "deployment expiry must follow a timezone-aware observation"
            )
        if (
            self.deployment_status is not DeploymentStatus.DEPLOYED
            and self.exposure_status is ExposureStatus.CONFIRMED
        ):
            raise ValueError("confirmed exposure requires a deployed artifact claim")

    def is_current(self, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        observed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        return observed <= current < expires

    def is_future(self, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        observed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        return observed > current


@dataclass(frozen=True)
class AssetRegistrySnapshot:
    services: tuple[RegisteredService, ...]
    links: tuple[ReviewedProjectLink, ...]
    deployment_reports: tuple[ReportedDeployment, ...] = ()


class RegistrySnapshotStatus(StrEnum):
    NOT_REQUESTED = "not_requested"
    LOADED = "loaded"


class RegistryProjectStatus(StrEnum):
    MATCHED = "matched"
    UNLINKED = "unlinked"
    IDENTITY_CHANGED = "identity_changed"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class RegistryProjectObservation:
    project_uuid: str
    dt_name: str
    dt_version: str | None
    status: RegistryProjectStatus
    reviewed_name: str | None = None
    reviewed_version: str | None = None
    service_id: str | None = None
    deployable_id: str | None = None
    owner: str | None = None
    criticality: BusinessCriticality | None = None
    reviewer: str | None = None
    reviewed_at: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "project_uuid": self.project_uuid,
            "dt_name": self.dt_name,
            "dt_version": self.dt_version,
            "status": self.status.value,
            "reviewed_name": self.reviewed_name,
            "reviewed_version": self.reviewed_version,
            "service_id": self.service_id,
            "deployable_id": self.deployable_id,
            "owner": self.owner,
            "criticality": self.criticality.value if self.criticality else None,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
        }


class RegistryDeploymentStatus(StrEnum):
    UNVERIFIED_LINK = "unverified_link"
    UNREPORTED = "unreported"
    OTHER_ARTIFACT = "other_artifact"
    EXPIRED = "expired"
    FUTURE_OBSERVATION = "future_observation"
    CONFLICT = "conflict"
    REPORTED = "reported"


@dataclass(frozen=True)
class RegistryDeploymentObservation:
    """A claim matched to a reviewed Project identity, never runtime proof."""

    project_uuid: str
    environment: str | None
    artifact_id: str | None
    status: RegistryDeploymentStatus
    report_ids: tuple[int, ...] = ()
    other_artifact_ids: tuple[str, ...] = ()
    deployment_status: DeploymentStatus | None = None
    exposure_status: ExposureStatus | None = None
    reviewer: str | None = None
    observed_at: str | None = None
    expires_at: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "project_uuid": self.project_uuid,
            "environment": self.environment,
            "artifact_id": self.artifact_id,
            "status": self.status.value,
            "source": "human_reported" if self.report_ids else None,
            "report_ids": list(self.report_ids),
            "other_artifact_ids": list(self.other_artifact_ids),
            "deployment_status": (
                self.deployment_status.value if self.deployment_status else None
            ),
            "exposure_status": (
                self.exposure_status.value if self.exposure_status else None
            ),
            "reviewer": self.reviewer,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class ProjectCandidate:
    project_uuid: str
    project_name: str
    project_version: str
    service_id: str
    deployable_id: str
    status: str


class ProjectLinkAuditStatus(StrEnum):
    MATCHED = "matched"
    NOT_VISIBLE = "not_visible"
    IDENTITY_CHANGED = "identity_changed"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class ProjectLinkAudit:
    link: ReviewedProjectLink
    status: ProjectLinkAuditStatus
    current_name: str | None
    current_version: str | None


def project_candidate(
    *,
    project_uuid: str,
    project_name: str,
    project_version: str | None,
    deployable: RegisteredDeployable,
    linked_uuid: str | None,
    uuid_linked_elsewhere: bool,
    coordinates_unique: bool,
) -> ProjectCandidate:
    if project_name != deployable.project_name:
        raise ValueError("Project name does not match registered deployable")
    version = (project_version or "").strip()
    if not version:
        status = "missing_version"
    elif project_version != version:
        status = "conflict"
    elif not coordinates_unique or uuid_linked_elsewhere:
        status = "conflict"
    elif linked_uuid is None:
        status = "candidate"
    elif linked_uuid == project_uuid:
        status = "reviewed"
    else:
        status = "conflict"
    return ProjectCandidate(
        project_uuid=project_uuid,
        project_name=project_name,
        project_version=version,
        service_id=deployable.service_id,
        deployable_id=deployable.deployable_id,
        status=status,
    )
