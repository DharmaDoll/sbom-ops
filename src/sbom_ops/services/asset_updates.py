"""Local asset changes; no Dependency-Track or remediation workflow writes."""

from __future__ import annotations

from sbom_ops.domain.asset_registry import (
    LifecycleAction,
    LifecycleChange,
    RegisteredService,
    ServiceUpdate,
)
from sbom_ops.domain.assets import BusinessCriticality
from sbom_ops.storage.asset_registry import AssetRegistry


def plan_lifecycle_change(
    registry: AssetRegistry,
    *,
    action: LifecycleAction,
    actor: str,
    reason: str,
    service_id: str | None = None,
    deployable_id: str | None = None,
    project_uuid: str | None = None,
) -> LifecycleChange:
    links = registry.list_links()
    if action is LifecycleAction.REVOKE_LINK:
        matches = tuple(link for link in links if link.project_uuid == project_uuid)
        if len(matches) != 1:
            raise ValueError("Project link is not currently approved")
        service_id, deployable_id = matches[0].service_id, matches[0].deployable_id
    else:
        if service_id is None or registry.get_service(service_id) is None:
            raise ValueError("service is not registered")
        if action is LifecycleAction.RETIRE_DEPLOYABLE and (
            deployable_id is None
            or registry.get_deployable(service_id, deployable_id) is None
        ):
            raise ValueError("deployable is not registered")
        if registry.is_retired(service_id, deployable_id):
            raise ValueError("asset is already retired")
        matches = tuple(
            link
            for link in links
            if link.service_id == service_id
            and (deployable_id is None or link.deployable_id == deployable_id)
        )
    return LifecycleChange(
        action,
        service_id,
        deployable_id,
        project_uuid,
        actor.strip(),
        reason.strip(),
        matches,
    )


def plan_service_update(
    registry: AssetRegistry,
    *,
    service_id: str,
    owner: str | None = None,
    criticality: BusinessCriticality | None = None,
    impact_reason: str | None = None,
    actor: str,
    reason: str,
) -> ServiceUpdate:
    current = registry.get_service(service_id)
    if current is None:
        raise ValueError(f"service is not registered: {service_id}")
    return ServiceUpdate(
        before=current,
        after=RegisteredService(
            service_id=current.service_id,
            owner=owner.strip() if owner is not None else current.owner,
            criticality=criticality if criticality is not None else current.criticality,
            impact_reason=(
                impact_reason.strip()
                if impact_reason is not None
                else current.impact_reason
            ),
        ),
        actor=actor.strip(),
        reason=reason.strip(),
    )
