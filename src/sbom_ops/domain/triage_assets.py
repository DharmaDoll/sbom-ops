"""Read-only linkage of exact asset claims; not proof of runtime exposure."""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime

from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegistryProjectObservation,
    RegistryProjectStatus,
    ReportedDeployment,
    effective_deployment_reports,
)
from sbom_ops.domain.assets import DeploymentStatus
from sbom_ops.domain.triage_evidence import (
    AssetEvidenceScope,
    TriageFactor,
    TriageObservation,
    TriageValue,
    VulnerabilityIdentity,
)


@dataclass(frozen=True)
class AssetTriageEvidence:
    asset: AssetEvidenceScope | None
    reports: tuple[ReportedDeployment, ...]
    pending_corrections: tuple[ReportedDeployment, ...]
    observations: tuple[TriageObservation, ...]
    reasons: tuple[str, ...]


def join_asset_evidence(
    snapshot: AssetRegistrySnapshot,
    project: RegistryProjectObservation,
    vulnerability: VulnerabilityIdentity,
    *,
    environment: str,
    now: datetime,
) -> AssetTriageEvidence:
    if now.utcoffset() is None:
        raise ValueError("evaluation time must be timezone-aware")
    if not isinstance(vulnerability, VulnerabilityIdentity):
        raise ValueError("typed vulnerability identity required")
    rejected = AssetTriageEvidence(None, (), (), (), ("asset_link_unverified",))
    if (
        project.status is not RegistryProjectStatus.MATCHED
        or project.project_uuid in snapshot.revoked_project_uuids
        or project.service_id in snapshot.retired_services
        or (project.service_id, project.deployable_id) in snapshot.retired_deployables
    ):
        return rejected
    links = [
        link for link in snapshot.links if link.project_uuid == project.project_uuid
    ]
    if len(links) != 1:
        return rejected
    link = links[0]
    if (
        link.project_name,
        link.project_version,
        link.service_id,
        link.deployable_id,
    ) != (
        project.dt_name,
        project.dt_version,
        project.service_id,
        project.deployable_id,
    ):
        return rejected
    reviewed = datetime.fromisoformat(link.reviewed_at)
    if reviewed.utcoffset() is None or reviewed > now:
        return rejected
    asset = AssetEvidenceScope(
        link.service_id,
        link.deployable_id,
        environment,
        link.project_version,
        link.project_uuid,
    )
    all_reports = snapshot.deployment_reports
    ids = [report.report_id for report in all_reports]
    if any(type(value) is not int or value <= 0 for value in ids) or len(
        set(ids)
    ) != len(ids):
        raise ValueError("persisted reports require unique positive IDs")
    effective = effective_deployment_reports(all_reports, now=now)
    exact = tuple(
        report
        for report in effective
        if (
            report.service_id,
            report.deployable_id,
            report.environment,
            report.artifact_id,
        )
        == (asset.service_id, asset.deployable_id, asset.environment, asset.artifact_id)
    )
    pending = tuple(
        report
        for report in exact
        if report.supersedes_report_id is not None and report.is_future(now=now)
    )
    reports = tuple(
        sorted(
            (report for report in exact if report not in pending),
            key=lambda report: report.report_id,
        )
    )
    observations = []
    reasons = set()
    for report in reports:
        value = TriageValue.UNKNOWN
        if report.deployment_status is not DeploymentStatus.DEPLOYED:
            reasons.add("deployment_not_confirmed")
        elif report.exposure_status is ExposureStatus.CONFIRMED:
            value = TriageValue.YES
        elif report.exposure_status is ExposureStatus.REJECTED:
            value = TriageValue.NO
        if report.exposure_status is ExposureStatus.CONFLICT:
            reasons.add("exposure_conflict")
        revision = hashlib.sha256(
            json.dumps(asdict(report), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        observations.append(
            TriageObservation(
                evidence_id=f"asset-report:{report.report_id}",
                vulnerability=vulnerability,
                factor=TriageFactor.PUBLIC_EXPOSURE,
                value=value,
                source="asset-registry:human-report",
                source_record=str(report.report_id),
                source_revision=f"sha256:{revision}",
                observed_at=datetime.fromisoformat(report.observed_at),
                expires_at=datetime.fromisoformat(report.expires_at),
                asset=asset,
            )
        )
    if not reports:
        reasons.add("no_matching_deployment_report")
    return AssetTriageEvidence(
        asset, reports, pending, tuple(observations), tuple(sorted(reasons))
    )
