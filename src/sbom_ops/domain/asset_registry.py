from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from sbom_ops.domain.assets import BusinessCriticality

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
class AssetRegistrySnapshot:
    services: tuple[RegisteredService, ...]
    links: tuple[ReviewedProjectLink, ...]


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
