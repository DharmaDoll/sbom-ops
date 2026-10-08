from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sbom_ops.domain.advisory import ExposureStatus


class AssetInventoryStatus(StrEnum):
    NOT_REQUESTED = "not_requested"
    LOADED = "loaded"
    INVALID = "invalid"


class DeploymentStatus(StrEnum):
    DEPLOYED = "deployed"
    NOT_DEPLOYED = "not_deployed"
    UNKNOWN = "unknown"


class BusinessCriticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    STANDARD = "standard"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AssetDeployment:
    project_uuid: str
    service_id: str
    environment: str
    owner: str | None
    deployed_version: str | None
    deployment_status: DeploymentStatus
    exposure_status: ExposureStatus
    criticality: BusinessCriticality
    source: str
    observed_at: str
    expires_at: str
    reviewer: str | None = None

    def is_current(self, *, now: datetime | None = None) -> bool:
        current_time = now or datetime.now(UTC)
        expires_at = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        return expires_at > current_time

    def as_dict(self, *, now: datetime | None = None) -> dict[str, object]:
        current = self.is_current(now=now)
        return {
            "project_uuid": self.project_uuid,
            "service_id": self.service_id,
            "environment": self.environment,
            "reported_owner": self.owner,
            "effective_owner": self.owner if current else None,
            "reported_deployed_version": self.deployed_version,
            "effective_deployed_version": (
                self.deployed_version
                if current and self.deployment_status is DeploymentStatus.DEPLOYED
                else None
            ),
            "reported_deployment_status": self.deployment_status.value,
            "effective_deployment_status": (
                self.deployment_status.value
                if current
                else DeploymentStatus.UNKNOWN.value
            ),
            "reported_exposure_status": self.exposure_status.value,
            "effective_exposure_status": (
                self.exposure_status.value if current else ExposureStatus.UNKNOWN.value
            ),
            "reported_criticality": self.criticality.value,
            "effective_criticality": (
                self.criticality.value if current else BusinessCriticality.UNKNOWN.value
            ),
            "freshness": "current" if current else "expired",
            "source": self.source,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "reviewer": self.reviewer,
        }


@dataclass(frozen=True)
class AssetInventorySnapshot:
    snapshot_id: str
    generated_at: str
    deployments: tuple[AssetDeployment, ...]
    sha256: str | None = None

    def for_project(self, project_uuid: str) -> tuple[AssetDeployment, ...]:
        return tuple(
            deployment
            for deployment in self.deployments
            if deployment.project_uuid == project_uuid
        )
