from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

import yaml

from sbom_ops.clients.dependency_track import (
    BomUpload,
    DependencyTrackObservation,
)
from sbom_ops.domain.dt_lab import (
    LabManifest,
    LabManifestError,
    LabRunResult,
    LabScenario,
    LabStepResult,
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


def _validate_json_bom(
    bom_path: Path,
    *,
    cyclonedx_versions: tuple[str, ...],
    scenario_id: str,
    step_id: str,
) -> str:
    try:
        payload = json.loads(bom_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} BOM is not valid JSON"
        ) from exc
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} is not a CycloneDX BOM"
        )
    spec_version = str(payload.get("specVersion") or "")
    if spec_version not in cyclonedx_versions:
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} uses undeclared "
            f"CycloneDX version {spec_version!r}"
        )
    serial_number = payload.get("serialNumber")
    if not isinstance(serial_number, str) or not serial_number.startswith("urn:uuid:"):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} requires a UUID serialNumber"
        )
    metadata = payload.get("metadata")
    root_component = metadata.get("component") if isinstance(metadata, dict) else None
    root_ref = (
        root_component.get("bom-ref") if isinstance(root_component, dict) else None
    )
    components = payload.get("components", [])
    if not isinstance(components, list):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} components must be a list"
        )
    component_refs = [
        component.get("bom-ref")
        for component in components
        if isinstance(component, dict) and component.get("bom-ref")
    ]
    if len(component_refs) != len(components):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} requires bom-ref on every "
            "component"
        )
    known_refs = set(component_refs)
    if root_ref:
        known_refs.add(str(root_ref))
    if len(component_refs) != len(set(component_refs)):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} has duplicate bom-ref values"
        )
    dependencies = payload.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} dependencies must be a list"
        )
    referenced: set[str] = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict) or not dependency.get("ref"):
            raise LabManifestError(
                f"scenario {scenario_id!r} step {step_id!r} has an invalid "
                "dependency entry"
            )
        referenced.add(str(dependency["ref"]))
        depends_on = dependency.get("dependsOn", [])
        if not isinstance(depends_on, list):
            raise LabManifestError(
                f"scenario {scenario_id!r} step {step_id!r} dependsOn must be a list"
            )
        referenced.update(str(item) for item in depends_on)
    unknown_refs = sorted(referenced - known_refs)
    if unknown_refs:
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} has unknown dependency "
            f"references: {', '.join(unknown_refs)}"
        )
    return serial_number


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
    serial_numbers: set[str] = set()
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
            if bom_path.suffix == ".json":
                serial_number = _validate_json_bom(
                    bom_path,
                    cyclonedx_versions=manifest.target.cyclonedx_versions,
                    scenario_id=scenario.id,
                    step_id=step.id,
                )
                if serial_number in serial_numbers:
                    raise LabManifestError(
                        f"duplicate CycloneDX serialNumber in lab corpus: "
                        f"{serial_number}"
                    )
                serial_numbers.add(serial_number)
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


class DependencyTrackLabApi(Protocol):
    def upload_bom_by_project_coordinates(
        self, project_name: str, project_version: str, bom_path: str | Path
    ) -> BomUpload: ...

    def wait_for_bom_processing(
        self,
        token: str,
        *,
        timeout: float = 120.0,
        poll_interval: float = 5.0,
    ) -> None: ...

    def observe_project_lookup(
        self, project_name: str, project_version: str
    ) -> DependencyTrackObservation: ...

    def observe_project(self, project_uuid: str) -> DependencyTrackObservation: ...

    def observe_project_components(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...

    def observe_project_dependency_graph(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...

    def observe_project_findings(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...

    def observe_project_vulnerabilities(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...

    def observe_project_metrics(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...

    def observe_project_bom_export(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...


def _observation_dict(observation: DependencyTrackObservation) -> dict[str, Any]:
    return {
        "request": {
            "method": observation.method,
            "path": observation.path,
            "query": dict(observation.query),
        },
        "response": {
            "status": observation.status,
            "headers": dict(observation.headers),
            "duration_seconds": observation.duration_seconds,
            "payload": observation.payload,
        },
    }


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        f"{json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)}\n",
        encoding="utf-8",
    )


def _payload_list(observation: DependencyTrackObservation | None) -> list[Any]:
    if observation is None or not isinstance(observation.payload, list):
        return []
    return observation.payload


def _component_identity(component: Any) -> str:
    if not isinstance(component, dict):
        return str(component)
    purl = component.get("purl") or component.get("purlCoordinates")
    if purl:
        return str(purl)
    if component.get("cpe"):
        return str(component["cpe"])
    return ":".join(
        str(component.get(key) or "") for key in ("group", "name", "version")
    )


def _step_summary(
    observations: dict[Observation, DependencyTrackObservation],
) -> dict[str, Any]:
    components = _payload_list(observations.get(Observation.COMPONENTS))
    findings = _payload_list(observations.get(Observation.FINDINGS))
    vulnerabilities = _payload_list(observations.get(Observation.VULNERABILITIES))
    component_projection = [
        {
            "identity": _component_identity(component),
            "uuid": component.get("uuid") if isinstance(component, dict) else None,
            "group": component.get("group") if isinstance(component, dict) else None,
            "name": component.get("name") if isinstance(component, dict) else None,
            "version": (
                component.get("version") if isinstance(component, dict) else None
            ),
            "purl": (
                component.get("purl") or component.get("purlCoordinates")
                if isinstance(component, dict)
                else None
            ),
            "cpe": component.get("cpe") if isinstance(component, dict) else None,
        }
        for component in components
    ]
    component_projection.sort(key=lambda component: str(component["identity"]))
    return {
        "component_count": len(components),
        "finding_count": len(findings),
        "vulnerability_count": len(vulnerabilities),
        "components": component_projection,
    }


def _step_delta(
    previous_summary: dict[str, Any] | None, current_summary: dict[str, Any]
) -> dict[str, Any] | None:
    if previous_summary is None:
        return None
    previous = {
        str(component["identity"]): component
        for component in previous_summary.get("components", [])
    }
    current = {
        str(component["identity"]): component
        for component in current_summary.get("components", [])
    }
    retained = sorted(previous.keys() & current.keys())
    return {
        "components_added": sorted(current.keys() - previous.keys()),
        "components_removed": sorted(previous.keys() - current.keys()),
        "components_retained": retained,
        "retained_uuid_changes": [
            {
                "identity": identity,
                "before": previous[identity].get("uuid"),
                "after": current[identity].get("uuid"),
            }
            for identity in retained
            if previous[identity].get("uuid") != current[identity].get("uuid")
        ],
        "finding_count_before": previous_summary.get("finding_count"),
        "finding_count_after": current_summary.get("finding_count"),
    }


def _capture_observation(
    client: DependencyTrackLabApi,
    observation: Observation,
    project_uuid: str,
) -> DependencyTrackObservation:
    observers: dict[Observation, Callable[[str], DependencyTrackObservation]] = {
        Observation.PROJECT: client.observe_project,
        Observation.COMPONENTS: client.observe_project_components,
        Observation.DEPENDENCY_GRAPH: client.observe_project_dependency_graph,
        Observation.FINDINGS: client.observe_project_findings,
        Observation.VULNERABILITIES: client.observe_project_vulnerabilities,
        Observation.METRICS: client.observe_project_metrics,
        Observation.BOM_EXPORT: client.observe_project_bom_export,
    }
    observer = observers.get(observation)
    if observer is None:
        raise LabManifestError(
            f"observation {observation.value!r} is not implemented by the lab runner"
        )
    return observer(project_uuid)


def _selected_scenarios(
    manifest: LabManifest, scenario_ids: tuple[str, ...]
) -> tuple[LabScenario, ...]:
    implemented = tuple(
        scenario
        for scenario in manifest.scenarios
        if scenario.status is ScenarioStatus.IMPLEMENTED
    )
    if not scenario_ids:
        return implemented
    available = {scenario.id: scenario for scenario in implemented}
    unknown = sorted(set(scenario_ids) - set(available))
    if unknown:
        raise LabManifestError(
            f"unknown or unimplemented lab scenarios: {', '.join(unknown)}"
        )
    return tuple(available[scenario_id] for scenario_id in scenario_ids)


def run_lab_scenarios(
    manifest: LabManifest,
    *,
    manifest_path: str | Path,
    upload_client: DependencyTrackLabApi,
    read_client: DependencyTrackLabApi,
    output_directory: str | Path,
    scenario_ids: tuple[str, ...] = (),
    processing_timeout: float = 120.0,
    poll_interval: float = 5.0,
    openapi_contract_sha256: str | None = None,
) -> LabRunResult:
    run_id = str(uuid4())
    run_directory = Path(output_directory) / run_id
    run_directory.mkdir(parents=True, exist_ok=False)
    manifest_root = Path(manifest_path).resolve().parent
    results: list[LabStepResult] = []
    selected = _selected_scenarios(manifest, scenario_ids)
    started_at = datetime.now(UTC).isoformat()
    run_metadata = {
        "run_id": run_id,
        "status": "running",
        "started_at": started_at,
        "dependency_track_version": manifest.target.dependency_track_version,
        "openapi_contract_sha256": openapi_contract_sha256,
        "scenarios": [scenario.id for scenario in selected],
    }
    _write_json(
        run_directory / "run.json",
        run_metadata,
    )
    for scenario in selected:
        project_version = f"{scenario.project_version}-lab-{run_id[:8]}"
        previous_summary: dict[str, Any] | None = None
        for index, step in enumerate(scenario.steps, start=1):
            upload = upload_client.upload_bom_by_project_coordinates(
                scenario.project_name,
                project_version,
                manifest_root / step.bom,
            )
            upload_client.wait_for_bom_processing(
                upload.token,
                timeout=processing_timeout,
                poll_interval=poll_interval,
            )
            lookup = read_client.observe_project_lookup(
                scenario.project_name, project_version
            )
            if not isinstance(lookup.payload, dict) or not lookup.payload.get("uuid"):
                raise LabManifestError(
                    f"scenario {scenario.id!r} Project lookup returned no UUID"
                )
            project_uuid = str(lookup.payload["uuid"])
            step_directory = run_directory / scenario.id / f"{index:02d}-{step.id}"
            step_directory.mkdir(parents=True, exist_ok=False)
            _write_json(
                step_directory / "project-lookup.json", _observation_dict(lookup)
            )
            captured: dict[Observation, DependencyTrackObservation] = {}
            for observation in step.observations:
                result = _capture_observation(read_client, observation, project_uuid)
                captured[observation] = result
                _write_json(
                    step_directory / f"{observation.value}.json",
                    _observation_dict(result),
                )
            summary = _step_summary(captured)
            _write_json(step_directory / "summary.json", summary)
            delta = _step_delta(previous_summary, summary)
            if delta is not None:
                _write_json(step_directory / "delta.json", delta)
            previous_summary = summary
            results.append(
                LabStepResult(
                    scenario_id=scenario.id,
                    step_id=step.id,
                    project_uuid=project_uuid,
                    snapshot_directory=str(step_directory),
                    observation_count=len(captured) + 1,
                )
            )
    _write_json(
        run_directory / "run.json",
        {
            **run_metadata,
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
            "step_count": len(results),
        },
    )
    return LabRunResult(
        run_id=run_id,
        output_directory=str(run_directory),
        steps=tuple(results),
    )
