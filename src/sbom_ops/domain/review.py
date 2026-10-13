"""Read-only review projections; no priority or remediation decisions."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from sbom_ops.domain.asset_registry import (
    RegistryDeploymentObservation,
    RegistryProjectObservation,
    RegistryProjectStatus,
    RegistrySnapshotStatus,
)
from sbom_ops.domain.models import FindingAssessment
from sbom_ops.domain.priority import order_assessments_for_review


@dataclass(frozen=True)
class FindingReview:
    """One Finding, with zero or more environments; never one row per CVE."""

    assessment: FindingAssessment
    asset_status: str
    asset: RegistryProjectObservation | None
    environments: tuple[RegistryDeploymentObservation, ...]

    def as_dict(self) -> dict[str, object]:
        item = self.assessment
        return {
            "finding_key": item.finding_key,
            "project_uuid": item.project_uuid,
            "vulnerability_id": item.vulnerability_id,
            "vulnerability_source": item.vulnerability_source,
            "vulnerability_aliases": list(item.vulnerability_aliases),
            "component_uuid": item.component_uuid,
            "component_purl": item.component_purl,
            "component_name": item.component_name,
            "component_version": item.component_version,
            "priority": item.priority.value,
            "severity": item.severity.value,
            "cvss_score": item.cvss_score,
            "epss_score": item.epss_score,
            "in_kev": item.in_kev,
            "rationale": list(item.rationale),
            "analysis_state": item.analysis_state.value,
            "is_suppressed": item.is_suppressed,
            "poc_reports": item.poc_reports.as_dict(),
            "asset_status": self.asset_status,
            "asset": self.asset.as_dict() if self.asset else None,
            "environments": [item.as_dict() for item in self.environments],
        }


def build_review_queue(
    assessments: Sequence[FindingAssessment],
    snapshot_status: RegistrySnapshotStatus,
    projects: Sequence[RegistryProjectObservation],
    deployments: Sequence[RegistryDeploymentObservation],
) -> tuple[FindingReview, ...]:
    """Join only reviewed registry observations, not the legacy asset inventory."""
    by_project: dict[str, list[RegistryProjectObservation]] = defaultdict(list)
    by_environment: dict[str, list[RegistryDeploymentObservation]] = defaultdict(list)
    for project in projects:
        by_project[project.project_uuid].append(project)
    for deployment in deployments:
        by_environment[deployment.project_uuid].append(deployment)
    result = []
    for item in order_assessments_for_review(assessments):
        candidates = by_project[item.project_uuid]
        asset = None
        environments = ()
        if snapshot_status is RegistrySnapshotStatus.NOT_REQUESTED:
            status = snapshot_status.value
        elif len(candidates) > 1:
            status = RegistryProjectStatus.AMBIGUOUS.value
        elif not candidates:
            status = RegistryProjectStatus.UNLINKED.value
        else:
            project = candidates[0]
            status = project.status.value
            if project.status is RegistryProjectStatus.MATCHED:
                asset = project
                environments = tuple(by_environment[item.project_uuid])
        result.append(FindingReview(item, status, asset, environments))
    return tuple(result)
