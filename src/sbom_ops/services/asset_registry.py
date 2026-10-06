from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from sbom_ops.clients.dependency_track import DependencyTrackProject
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    ProjectCandidate,
    ProjectLinkAudit,
    ProjectLinkAuditStatus,
    RegistryProjectObservation,
    RegistryProjectStatus,
    ReviewedProjectLink,
    project_candidate,
)
from sbom_ops.storage.asset_registry import AssetRegistry


def observe_registry_projects(
    snapshot: AssetRegistrySnapshot,
    all_projects: Sequence[DependencyTrackProject],
    selected_projects: Sequence[DependencyTrackProject],
) -> tuple[RegistryProjectObservation, ...]:
    """Report reviewed registry context without granting it workflow authority."""
    by_uuid: dict[str, list[DependencyTrackProject]] = {}
    for project in all_projects:
        by_uuid.setdefault(project.uuid, []).append(project)
    coordinate_counts = Counter(
        (project.name, project.version) for project in all_projects
    )
    links = {link.project_uuid: link for link in snapshot.links}
    services = {service.service_id: service for service in snapshot.services}
    observations: list[RegistryProjectObservation] = []
    for project_uuid in sorted({project.uuid for project in selected_projects}):
        current = by_uuid[project_uuid][0]
        link = links.get(project_uuid)
        if link is None:
            observations.append(
                RegistryProjectObservation(
                    project_uuid=project_uuid,
                    dt_name=current.name,
                    dt_version=current.version,
                    status=RegistryProjectStatus.UNLINKED,
                )
            )
            continue
        if (
            len(by_uuid[project_uuid]) != 1
            or coordinate_counts[(current.name, current.version)] != 1
        ):
            status = RegistryProjectStatus.AMBIGUOUS
        elif (current.name, current.version) != (
            link.project_name,
            link.project_version,
        ):
            status = RegistryProjectStatus.IDENTITY_CHANGED
        else:
            status = RegistryProjectStatus.MATCHED
        service = services.get(link.service_id)
        if service is None:
            raise ValueError(
                f"reviewed Project link refers to missing service: {link.service_id}"
            )
        matched = status is RegistryProjectStatus.MATCHED
        observations.append(
            RegistryProjectObservation(
                project_uuid=project_uuid,
                dt_name=current.name,
                dt_version=current.version,
                status=status,
                reviewed_name=link.project_name,
                reviewed_version=link.project_version,
                service_id=link.service_id if matched else None,
                deployable_id=link.deployable_id if matched else None,
                owner=service.owner if matched else None,
                criticality=service.criticality if matched else None,
                reviewer=link.reviewer,
                reviewed_at=link.reviewed_at,
            )
        )
    return tuple(observations)


def audit_reviewed_project_links(
    registry: AssetRegistry,
    projects: Sequence[DependencyTrackProject],
) -> tuple[ProjectLinkAudit, ...]:
    by_uuid: dict[str, list[DependencyTrackProject]] = {}
    coordinates = Counter((project.name, project.version) for project in projects)
    for project in projects:
        by_uuid.setdefault(project.uuid, []).append(project)

    results: list[ProjectLinkAudit] = []
    for link in registry.list_links():
        matches = by_uuid.get(link.project_uuid, [])
        if not matches:
            status = ProjectLinkAuditStatus.NOT_VISIBLE
            current_name = None
            current_version = None
        else:
            current_name = matches[0].name
            current_version = matches[0].version
            if len(matches) != 1 or coordinates[(current_name, current_version)] != 1:
                status = ProjectLinkAuditStatus.AMBIGUOUS
            elif (current_name, current_version) != (
                link.project_name,
                link.project_version,
            ):
                status = ProjectLinkAuditStatus.IDENTITY_CHANGED
            else:
                status = ProjectLinkAuditStatus.MATCHED
        results.append(ProjectLinkAudit(link, status, current_name, current_version))
    return tuple(results)


def discover_project_candidates(
    registry: AssetRegistry,
    projects: Sequence[DependencyTrackProject],
) -> tuple[ProjectCandidate, ...]:
    deployables = {item.project_name: item for item in registry.list_deployables()}
    coordinates = Counter(
        (project.name, project.version)
        for project in projects
        if project.version is not None
    )
    candidates: list[ProjectCandidate] = []
    for project in projects:
        deployable = deployables.get(project.name)
        if deployable is None:
            continue
        existing_coordinates = registry.linked_coordinates(project.uuid)
        candidates.append(
            project_candidate(
                project_uuid=project.uuid,
                project_name=project.name,
                project_version=project.version,
                deployable=deployable,
                linked_uuid=(
                    registry.linked_uuid(project.name, project.version)
                    if project.version
                    else None
                ),
                uuid_linked_elsewhere=(
                    existing_coordinates is not None
                    and existing_coordinates != (project.name, project.version)
                ),
                coordinates_unique=coordinates[(project.name, project.version)] == 1,
            )
        )
    return tuple(
        sorted(candidates, key=lambda item: (item.project_name, item.project_version))
    )


def approve_project_link(
    registry: AssetRegistry,
    projects: Sequence[DependencyTrackProject],
    *,
    service_id: str,
    deployable_id: str,
    project_uuid: str,
    reviewer: str,
) -> ReviewedProjectLink:
    deployable = registry.get_deployable(service_id, deployable_id)
    if deployable is None:
        raise ValueError(f"deployable is not registered: {service_id}/{deployable_id}")
    matches = [project for project in projects if project.uuid == project_uuid]
    if len(matches) != 1:
        raise ValueError("Project UUID is not uniquely visible in Dependency-Track")
    project = matches[0]
    if (
        project.name != deployable.project_name
        or not project.version
        or project.version != project.version.strip()
    ):
        raise ValueError("Project name/version does not match registered deployable")
    if (
        sum(
            other.name == project.name and other.version == project.version
            for other in projects
        )
        != 1
    ):
        raise ValueError("Project name/version is ambiguous in Dependency-Track")
    return registry.link_project(
        deployable=deployable,
        project_uuid=project.uuid,
        project_version=project.version,
        reviewer=reviewer,
    )
