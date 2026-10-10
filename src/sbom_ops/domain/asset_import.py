from __future__ import annotations

from dataclasses import dataclass

from sbom_ops.domain.asset_registry import RegisteredDeployable, RegisteredService
from sbom_ops.domain.assets import BusinessCriticality


@dataclass(frozen=True)
class AssetRegistrationBatch:
    """New services and deployables; never a DT link or deployment claim."""

    services: tuple[RegisteredService, ...]
    deployables: tuple[RegisteredDeployable, ...]


def _record(value: object, *, label: str, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} must contain exactly {sorted(fields)}")
    return value


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def parse_asset_registration(value: object) -> AssetRegistrationBatch:
    """Validate a bounded v1 registration document using the CLI domain models."""
    document = _record(
        value,
        label="asset registration",
        fields={"schema_version", "services", "deployables"},
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValueError("asset registration schema_version must be 1")
    raw_services = document["services"]
    raw_deployables = document["deployables"]
    if not isinstance(raw_services, list) or not isinstance(raw_deployables, list):
        raise ValueError("services and deployables must be arrays")
    if not raw_services or len(raw_services) > 1000 or len(raw_deployables) > 1000:
        raise ValueError("provide 1-1000 services and at most 1000 deployables")

    services: list[RegisteredService] = []
    for index, raw in enumerate(raw_services):
        item = _record(
            raw,
            label=f"services[{index}]",
            fields={"service_id", "owner", "criticality", "impact_reason"},
        )
        services.append(
            RegisteredService(
                service_id=_string(item["service_id"], label="service_id"),
                owner=_string(item["owner"], label="owner"),
                criticality=BusinessCriticality(
                    _string(item["criticality"], label="criticality")
                ),
                impact_reason=_string(item["impact_reason"], label="impact_reason"),
            )
        )
    service_ids = [service.service_id for service in services]
    if len(service_ids) != len(set(service_ids)):
        raise ValueError("duplicate service_id in asset registration")

    deployables: list[RegisteredDeployable] = []
    for index, raw in enumerate(raw_deployables):
        item = _record(
            raw,
            label=f"deployables[{index}]",
            fields={"service_id", "deployable_id"},
        )
        deployable = RegisteredDeployable(
            service_id=_string(item["service_id"], label="service_id"),
            deployable_id=_string(item["deployable_id"], label="deployable_id"),
        )
        if deployable.service_id not in service_ids:
            raise ValueError(
                f"deployable refers to a service outside this batch: "
                f"{deployable.project_name}"
            )
        deployables.append(deployable)
    names = [deployable.project_name for deployable in deployables]
    if len(names) != len(set(names)):
        raise ValueError("duplicate deployable in asset registration")
    return AssetRegistrationBatch(tuple(services), tuple(deployables))
