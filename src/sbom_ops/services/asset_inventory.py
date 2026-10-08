from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from pathlib import Path

from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.assets import (
    AssetDeployment,
    AssetInventorySnapshot,
    BusinessCriticality,
    DeploymentStatus,
)

_MAX_SNAPSHOT_BYTES = 1024 * 1024
_MAX_DEPLOYMENTS = 2_000
_ROOT_KEYS = {"schema_version", "snapshot_id", "generated_at", "deployments"}
_DEPLOYMENT_KEYS = {
    "project_uuid",
    "service_id",
    "environment",
    "owner",
    "deployed_version",
    "deployment_status",
    "exposure_status",
    "criticality",
    "source",
    "observed_at",
    "expires_at",
    "reviewer",
}


def _object(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _known_keys(item: dict[str, object], allowed: set[str], field: str) -> None:
    unknown = set(item) - allowed
    if unknown:
        raise ValueError(f"{field} has unknown key(s): {', '.join(sorted(unknown))}")


def _required_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _optional_string(value: object, field: str) -> str | None:
    return None if value is None else _required_string(value, field)


def _timestamp(value: object, field: str) -> tuple[str, datetime]:
    text = _required_string(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return text, parsed


def _enum[T: Enum](enum_type: type[T], value: object, field: str) -> T:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        choices = ", ".join(item.value for item in enum_type)
        raise ValueError(f"{field} must be one of: {choices}") from exc


def load_asset_inventory(path: str | Path) -> AssetInventorySnapshot:
    """Load reviewed deployment facts without contacting an asset system."""
    snapshot_path = Path(path)
    if snapshot_path.stat().st_size > _MAX_SNAPSHOT_BYTES:
        raise ValueError("asset inventory exceeds the 1 MiB size limit")
    raw_snapshot = snapshot_path.read_bytes()
    if len(raw_snapshot) > _MAX_SNAPSHOT_BYTES:
        raise ValueError("asset inventory exceeds the 1 MiB size limit")
    try:
        payload = json.loads(raw_snapshot)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid asset inventory JSON: {exc.msg}") from exc

    root = _object(payload, "asset inventory")
    _known_keys(root, _ROOT_KEYS, "asset inventory")
    version = root.get("schema_version")
    if type(version) is not int or version != 1:
        raise ValueError("asset inventory schema_version must be 1")
    snapshot_id = _required_string(root.get("snapshot_id"), "snapshot_id")
    generated_at, _ = _timestamp(root.get("generated_at"), "generated_at")
    raw_deployments = root.get("deployments")
    if not isinstance(raw_deployments, list):
        raise ValueError("deployments must be an array")
    if len(raw_deployments) > _MAX_DEPLOYMENTS:
        raise ValueError("deployments exceeds the 2,000 item limit")

    deployments: list[AssetDeployment] = []
    identities: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(raw_deployments):
        field = f"deployments[{index}]"
        item = _object(raw, field)
        _known_keys(item, _DEPLOYMENT_KEYS, field)
        project_uuid = _required_string(
            item.get("project_uuid"), f"{field}.project_uuid"
        )
        service_id = _required_string(item.get("service_id"), f"{field}.service_id")
        environment = _required_string(item.get("environment"), f"{field}.environment")
        identity = (project_uuid, service_id.casefold(), environment.casefold())
        if identity in identities:
            raise ValueError(f"duplicate asset deployment: {field}")
        identities.add(identity)
        observed_at, observed = _timestamp(
            item.get("observed_at"), f"{field}.observed_at"
        )
        expires_at, expires = _timestamp(item.get("expires_at"), f"{field}.expires_at")
        if expires <= observed:
            raise ValueError(f"{field}.expires_at must be later than observed_at")
        deployment_status = _enum(
            DeploymentStatus,
            item.get("deployment_status"),
            f"{field}.deployment_status",
        )
        deployed_version = _optional_string(
            item.get("deployed_version"), f"{field}.deployed_version"
        )
        if deployment_status is DeploymentStatus.NOT_DEPLOYED and deployed_version:
            raise ValueError(f"{field}.deployed_version must be null when not_deployed")
        deployments.append(
            AssetDeployment(
                project_uuid=project_uuid,
                service_id=service_id,
                environment=environment,
                owner=_optional_string(item.get("owner"), f"{field}.owner"),
                deployed_version=deployed_version,
                deployment_status=deployment_status,
                exposure_status=_enum(
                    ExposureStatus,
                    item.get("exposure_status"),
                    f"{field}.exposure_status",
                ),
                criticality=_enum(
                    BusinessCriticality,
                    item.get("criticality"),
                    f"{field}.criticality",
                ),
                source=_required_string(item.get("source"), f"{field}.source"),
                observed_at=observed_at,
                expires_at=expires_at,
                reviewer=_optional_string(item.get("reviewer"), f"{field}.reviewer"),
            )
        )
    return AssetInventorySnapshot(
        snapshot_id=snapshot_id,
        generated_at=generated_at,
        deployments=tuple(deployments),
        sha256=hashlib.sha256(raw_snapshot).hexdigest(),
    )
