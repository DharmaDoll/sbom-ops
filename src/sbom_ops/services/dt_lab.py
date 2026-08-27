from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml

from sbom_ops.domain.dt_lab import (
    LabManifest,
    LabManifestError,
    LabScenario,
    LabTarget,
    Observation,
    OpenApiInventory,
    OpenApiOperation,
    ScenarioCategory,
    ScenarioStatus,
    ScenarioStep,
)

RELEVANT_OPENAPI_TAGS = (
    "analysis",
    "bom",
    "component",
    "dependencyGraph",
    "event",
    "finding",
    "metrics",
    "project",
    "search",
    "service",
    "vex",
    "violation",
    "violationanalysis",
    "vulnerability",
)

_HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}
_STRONG_PERMISSION_PATTERN = re.compile(r"<strong>([A-Z][A-Z0-9_]+)</strong>")
_PLAIN_PERMISSION_PATTERN = re.compile(
    r"Requires permissions?\s+([A-Z][A-Z0-9_]+)", re.IGNORECASE
)


def _mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LabManifestError(f"{field_name} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _list(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise LabManifestError(f"{field_name} must be a list")
    return value


def _reject_unknown(
    payload: dict[str, Any], allowed: set[str], field_name: str
) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise LabManifestError(
            f"{field_name} contains unknown keys: {', '.join(unknown)}"
        )


def _required_string(payload: dict[str, Any], key: str, field_name: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise LabManifestError(f"{field_name}.{key} must be a non-empty string")
    return value


def _load_step(payload: Any, scenario_id: str) -> ScenarioStep:
    step = _mapping(payload, f"scenario {scenario_id} step")
    _reject_unknown(step, {"id", "bom", "observe"}, f"scenario {scenario_id} step")
    observations = tuple(
        Observation(str(item))
        for item in _list(step.get("observe"), f"scenario {scenario_id} observe")
    )
    return ScenarioStep(
        id=_required_string(step, "id", f"scenario {scenario_id} step"),
        bom=_required_string(step, "bom", f"scenario {scenario_id} step"),
        observations=observations,
    )


def _load_scenario(payload: Any) -> LabScenario:
    scenario = _mapping(payload, "scenario")
    _reject_unknown(
        scenario,
        {"id", "category", "status", "purpose", "project", "steps"},
        "scenario",
    )
    scenario_id = _required_string(scenario, "id", "scenario")
    project = _mapping(scenario.get("project"), f"scenario {scenario_id}.project")
    _reject_unknown(project, {"name", "version"}, f"scenario {scenario_id}.project")
    raw_steps = scenario.get("steps", [])
    steps = tuple(
        _load_step(item, scenario_id)
        for item in _list(raw_steps, f"scenario {scenario_id}.steps")
    )
    try:
        category = ScenarioCategory(
            _required_string(scenario, "category", f"scenario {scenario_id}")
        )
        status = ScenarioStatus(
            _required_string(scenario, "status", f"scenario {scenario_id}")
        )
    except ValueError as exc:
        raise LabManifestError(f"scenario {scenario_id!r} has an invalid enum") from exc
    return LabScenario(
        id=scenario_id,
        category=category,
        status=status,
        purpose=_required_string(scenario, "purpose", f"scenario {scenario_id}"),
        project_name=_required_string(
            project, "name", f"scenario {scenario_id}.project"
        ),
        project_version=_required_string(
            project, "version", f"scenario {scenario_id}.project"
        ),
        steps=steps,
    )


def load_lab_manifest(path: str | Path) -> LabManifest:
    manifest_path = Path(path)
    payload = _mapping(
        yaml.safe_load(manifest_path.read_text(encoding="utf-8")), "manifest"
    )
    _reject_unknown(payload, {"schema_version", "target", "scenarios"}, "manifest")
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, int):
        raise LabManifestError("manifest.schema_version must be an integer")
    target_payload = _mapping(payload.get("target"), "manifest.target")
    _reject_unknown(
        target_payload,
        {"dependency_track_version", "cyclonedx_versions"},
        "manifest.target",
    )
    target = LabTarget(
        dependency_track_version=_required_string(
            target_payload, "dependency_track_version", "manifest.target"
        ),
        cyclonedx_versions=tuple(
            str(item)
            for item in _list(
                target_payload.get("cyclonedx_versions"),
                "manifest.target.cyclonedx_versions",
            )
        ),
    )
    manifest = LabManifest(
        schema_version=schema_version,
        target=target,
        scenarios=tuple(
            _load_scenario(item)
            for item in _list(payload.get("scenarios"), "manifest.scenarios")
        ),
    )
    manifest_root = manifest_path.resolve().parent
    for scenario in manifest.scenarios:
        for step in scenario.steps:
            bom_path = (manifest_root / step.bom).resolve()
            if not bom_path.is_relative_to(manifest_root):
                raise LabManifestError(
                    f"scenario {scenario.id!r} BOM escapes manifest directory: "
                    f"{step.bom}"
                )
            if not bom_path.is_file():
                raise LabManifestError(
                    f"scenario {scenario.id!r} BOM does not exist: {step.bom}"
                )
    return manifest


def _permissions(description: Any) -> tuple[str, ...]:
    if not isinstance(description, str):
        return ()
    strong = _STRONG_PERMISSION_PATTERN.findall(description)
    if strong:
        return tuple(sorted(set(strong)))
    plain = _PLAIN_PERMISSION_PATTERN.findall(description)
    return tuple(sorted({item.upper() for item in plain}))


def _response_details(
    responses: Any,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    if not isinstance(responses, dict):
        return (), (), ()
    statuses: set[str] = set()
    headers: set[str] = set()
    media_types: set[str] = set()
    for status, raw_response in responses.items():
        statuses.add(str(status))
        if not isinstance(raw_response, dict):
            continue
        raw_headers = raw_response.get("headers")
        if isinstance(raw_headers, dict):
            headers.update(str(header) for header in raw_headers)
        content = raw_response.get("content")
        if isinstance(content, dict):
            media_types.update(str(media_type) for media_type in content)
    return tuple(sorted(statuses)), tuple(sorted(headers)), tuple(sorted(media_types))


def build_openapi_inventory(
    payload: dict[str, Any],
    *,
    selected_tags: tuple[str, ...] | None = RELEVANT_OPENAPI_TAGS,
) -> OpenApiInventory:
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI document must contain a paths mapping")
    operations: list[OpenApiOperation] = []
    all_tags: set[str] = set()
    operation_count = 0
    selected = set(selected_tags) if selected_tags is not None else None
    for path, raw_path_item in paths.items():
        if not isinstance(raw_path_item, dict):
            continue
        for method, raw_operation in raw_path_item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(
                raw_operation, dict
            ):
                continue
            operation_count += 1
            tags = tuple(sorted(str(tag) for tag in raw_operation.get("tags", [])))
            all_tags.update(tags)
            if selected is not None and not selected.intersection(tags):
                continue
            parameters = raw_operation.get("parameters", [])
            query_parameters = tuple(
                sorted(
                    str(parameter["name"])
                    for parameter in parameters
                    if isinstance(parameter, dict)
                    and parameter.get("in") == "query"
                    and parameter.get("name")
                )
            )
            statuses, headers, media_types = _response_details(
                raw_operation.get("responses")
            )
            operations.append(
                OpenApiOperation(
                    method=method.upper(),
                    path=str(path),
                    operation_id=(
                        str(raw_operation["operationId"])
                        if raw_operation.get("operationId")
                        else None
                    ),
                    tags=tags,
                    summary=(
                        str(raw_operation["summary"])
                        if raw_operation.get("summary")
                        else None
                    ),
                    permissions=_permissions(raw_operation.get("description")),
                    query_parameters=query_parameters,
                    response_statuses=statuses,
                    response_headers=headers,
                    response_media_types=media_types,
                    deprecated=bool(raw_operation.get("deprecated", False)),
                )
            )
    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return OpenApiInventory(
        title=str(info["title"]) if info.get("title") else None,
        api_version=str(info["version"]) if info.get("version") else None,
        openapi_version=(str(payload["openapi"]) if payload.get("openapi") else None),
        contract_sha256=hashlib.sha256(canonical).hexdigest(),
        path_count=len(paths),
        operation_count=operation_count,
        tag_count=len(all_tags),
        selected_tags=(
            tuple(sorted(all_tags)) if selected_tags is None else tuple(selected_tags)
        ),
        operations=tuple(
            sorted(
                operations,
                key=lambda operation: (
                    operation.tags,
                    operation.path,
                    operation.method,
                ),
            )
        ),
    )


def openapi_inventory_dict(inventory: OpenApiInventory) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": {
            "title": inventory.title,
            "api_version": inventory.api_version,
            "openapi_version": inventory.openapi_version,
            "contract_sha256": inventory.contract_sha256,
        },
        "summary": {
            "path_count": inventory.path_count,
            "operation_count": inventory.operation_count,
            "tag_count": inventory.tag_count,
            "selected_operation_count": len(inventory.operations),
            "selected_tags": list(inventory.selected_tags),
        },
        "operations": [
            {
                "method": operation.method,
                "path": operation.path,
                "operation_id": operation.operation_id,
                "tags": list(operation.tags),
                "summary": operation.summary,
                "permissions": list(operation.permissions),
                "query_parameters": list(operation.query_parameters),
                "response_statuses": list(operation.response_statuses),
                "response_headers": list(operation.response_headers),
                "response_media_types": list(operation.response_media_types),
                "deprecated": operation.deprecated,
            }
            for operation in inventory.operations
        ],
    }
