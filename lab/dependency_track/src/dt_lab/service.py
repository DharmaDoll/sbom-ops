from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

import yaml

from dt_lab.domain import (
    AnalysisAction,
    AnalysisJustification,
    AnalysisResponse,
    AnalysisState,
    BomUpload,
    CorpusArtifact,
    CorpusArtifactInspection,
    CorpusCatalog,
    CorpusSourceKind,
    DependencyTrackObservation,
    LabManifest,
    LabManifestError,
    LabProjectRecord,
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
    "team",
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


def _required_string_tuple(
    payload: dict[str, Any], key: str, field_name: str
) -> tuple[str, ...]:
    values = _list(payload.get(key), f"{field_name}.{key}")
    result: list[str] = []
    for index, value in enumerate(values):
        if not isinstance(value, str) or not value.strip():
            raise LabManifestError(
                f"{field_name}.{key}[{index}] must be a non-empty string"
            )
        result.append(value)
    return tuple(result)


def _required_bool(payload: dict[str, Any], key: str, field_name: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise LabManifestError(f"{field_name}.{key} must be a boolean")
    return value


def _load_analysis_action(
    payload: Any, scenario_id: str, step_id: str
) -> AnalysisAction:
    field_name = f"scenario {scenario_id} step {step_id} analysis action"
    action = _mapping(payload, field_name)
    _reject_unknown(
        action,
        {
            "id",
            "component_purl",
            "vulnerability_id",
            "vulnerability_source",
            "state",
            "justification",
            "response",
            "detail",
            "comment",
            "suppressed",
        },
        field_name,
    )
    action_id = _required_string(action, "id", field_name)
    enum_field = f"{field_name} {action_id}"
    try:
        state = AnalysisState(_required_string(action, "state", enum_field))
        justification = AnalysisJustification(
            _required_string(action, "justification", enum_field)
        )
        response = AnalysisResponse(_required_string(action, "response", enum_field))
    except ValueError as exc:
        raise LabManifestError(f"{enum_field!r} has an invalid enum") from exc
    return AnalysisAction(
        id=action_id,
        component_purl=_required_string(action, "component_purl", enum_field),
        vulnerability_id=_required_string(action, "vulnerability_id", enum_field),
        vulnerability_source=_required_string(
            action, "vulnerability_source", enum_field
        ),
        state=state,
        justification=justification,
        response=response,
        detail=_required_string(action, "detail", enum_field),
        comment=_required_string(action, "comment", enum_field),
        suppressed=_required_bool(action, "suppressed", enum_field),
    )


def _load_step(payload: Any, scenario_id: str) -> ScenarioStep:
    step = _mapping(payload, f"scenario {scenario_id} step")
    _reject_unknown(
        step,
        {"id", "bom", "observe", "project_version", "analysis_actions"},
        f"scenario {scenario_id} step",
    )
    step_id = _required_string(step, "id", f"scenario {scenario_id} step")
    observations = tuple(
        Observation(str(item))
        for item in _list(step.get("observe"), f"scenario {scenario_id} observe")
    )
    return ScenarioStep(
        id=step_id,
        bom=_required_string(step, "bom", f"scenario {scenario_id} step"),
        observations=observations,
        project_version=(
            _required_string(step, "project_version", f"scenario {scenario_id} step")
            if step.get("project_version") is not None
            else None
        ),
        analysis_actions=tuple(
            _load_analysis_action(item, scenario_id, step_id)
            for item in _list(
                step.get("analysis_actions", []),
                f"scenario {scenario_id} step {step_id}.analysis_actions",
            )
        ),
    )


def _load_scenario(payload: Any) -> LabScenario:
    scenario = _mapping(payload, "scenario")
    _reject_unknown(
        scenario,
        {
            "id",
            "category",
            "status",
            "purpose",
            "hypotheses",
            "decision_questions",
            "project",
            "steps",
        },
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
        hypotheses=_required_string_tuple(
            scenario, "hypotheses", f"scenario {scenario_id}"
        ),
        decision_questions=_required_string_tuple(
            scenario, "decision_questions", f"scenario {scenario_id}"
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
    services = payload.get("services", [])
    if not isinstance(services, list):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} services must be a list"
        )
    service_refs = [
        service.get("bom-ref")
        for service in services
        if isinstance(service, dict) and service.get("bom-ref")
    ]
    if len(service_refs) != len(services):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} requires bom-ref on every "
            "service"
        )
    known_refs = set(component_refs) | set(service_refs)
    if root_ref:
        known_refs.add(str(root_ref))
    all_inventory_refs = component_refs + service_refs
    if len(all_inventory_refs) != len(set(all_inventory_refs)):
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


def _load_corpus_artifact(payload: Any) -> CorpusArtifact:
    artifact = _mapping(payload, "corpus artifact")
    _reject_unknown(
        artifact,
        {
            "id",
            "ecosystem",
            "source_kind",
            "source",
            "release",
            "license",
            "integrity",
            "sha256",
            "local_path",
            "cyclonedx_version",
            "project",
            "purpose",
            "hypotheses",
            "decision_questions",
        },
        "corpus artifact",
    )
    artifact_id = _required_string(artifact, "id", "corpus artifact")
    project = _mapping(
        artifact.get("project"), f"corpus artifact {artifact_id}.project"
    )
    _reject_unknown(
        project, {"name", "version"}, f"corpus artifact {artifact_id}.project"
    )
    try:
        source_kind = CorpusSourceKind(
            _required_string(artifact, "source_kind", f"corpus artifact {artifact_id}")
        )
    except ValueError as exc:
        raise LabManifestError(
            f"corpus artifact {artifact_id!r} has an invalid source_kind"
        ) from exc
    return CorpusArtifact(
        id=artifact_id,
        ecosystem=_required_string(
            artifact, "ecosystem", f"corpus artifact {artifact_id}"
        ),
        source_kind=source_kind,
        source=_required_string(artifact, "source", f"corpus artifact {artifact_id}"),
        release=_required_string(artifact, "release", f"corpus artifact {artifact_id}"),
        license=_required_string(artifact, "license", f"corpus artifact {artifact_id}"),
        integrity=_required_string(
            artifact, "integrity", f"corpus artifact {artifact_id}"
        ),
        sha256=_required_string(artifact, "sha256", f"corpus artifact {artifact_id}"),
        local_path=_required_string(
            artifact, "local_path", f"corpus artifact {artifact_id}"
        ),
        cyclonedx_version=_required_string(
            artifact, "cyclonedx_version", f"corpus artifact {artifact_id}"
        ),
        project_name=_required_string(
            project, "name", f"corpus artifact {artifact_id}.project"
        ),
        project_version=_required_string(
            project, "version", f"corpus artifact {artifact_id}.project"
        ),
        purpose=_required_string(artifact, "purpose", f"corpus artifact {artifact_id}"),
        hypotheses=_required_string_tuple(
            artifact, "hypotheses", f"corpus artifact {artifact_id}"
        ),
        decision_questions=_required_string_tuple(
            artifact, "decision_questions", f"corpus artifact {artifact_id}"
        ),
    )


def load_corpus_catalog(path: str | Path) -> CorpusCatalog:
    catalog_path = Path(path)
    payload = _mapping(
        yaml.safe_load(catalog_path.read_text(encoding="utf-8")), "corpus catalog"
    )
    _reject_unknown(
        payload, {"schema_version", "target", "artifacts"}, "corpus catalog"
    )
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, int):
        raise LabManifestError("corpus catalog.schema_version must be an integer")
    target_payload = _mapping(payload.get("target"), "corpus catalog.target")
    _reject_unknown(
        target_payload,
        {"dependency_track_version", "cyclonedx_versions"},
        "corpus catalog.target",
    )
    return CorpusCatalog(
        schema_version=schema_version,
        target=LabTarget(
            dependency_track_version=_required_string(
                target_payload,
                "dependency_track_version",
                "corpus catalog.target",
            ),
            cyclonedx_versions=tuple(
                str(item)
                for item in _list(
                    target_payload.get("cyclonedx_versions"),
                    "corpus catalog.target.cyclonedx_versions",
                )
            ),
        ),
        artifacts=tuple(
            _load_corpus_artifact(item)
            for item in _list(payload.get("artifacts"), "corpus catalog.artifacts")
        ),
    )


def inspect_corpus_artifact(
    artifact: CorpusArtifact, artifact_directory: str | Path
) -> CorpusArtifactInspection:
    root = Path(artifact_directory).resolve()
    path = (root / artifact.local_path).resolve()
    if not path.is_relative_to(root):
        raise LabManifestError(
            f"corpus artifact {artifact.id!r} escapes the artifact directory"
        )
    if not path.is_file():
        raise LabManifestError(
            f"corpus artifact {artifact.id!r} is not available locally: {path}"
        )
    content = path.read_bytes()
    observed_sha256 = hashlib.sha256(content).hexdigest()
    if observed_sha256 != artifact.sha256:
        raise LabManifestError(
            f"corpus artifact {artifact.id!r} SHA-256 mismatch: "
            f"expected {artifact.sha256}, observed {observed_sha256}"
        )
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise LabManifestError(
            f"corpus artifact {artifact.id!r} is not valid JSON"
        ) from exc
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise LabManifestError(
            f"corpus artifact {artifact.id!r} is not a CycloneDX BOM"
        )
    if payload.get("specVersion") != artifact.cyclonedx_version:
        raise LabManifestError(
            f"corpus artifact {artifact.id!r} declares CycloneDX "
            f"{payload.get('specVersion')!r}, expected {artifact.cyclonedx_version!r}"
        )

    def count_list(field_name: str) -> int:
        value = payload.get(field_name, [])
        if not isinstance(value, list):
            raise LabManifestError(
                f"corpus artifact {artifact.id!r} {field_name} must be a list"
            )
        return len(value)

    return CorpusArtifactInspection(
        artifact_id=artifact.id,
        path=str(path),
        byte_count=len(content),
        component_count=count_list("components"),
        dependency_count=count_list("dependencies"),
        service_count=count_list("services"),
        vulnerability_count=count_list("vulnerabilities"),
    )


def inspect_corpus_catalog(
    catalog: CorpusCatalog, artifact_directory: str | Path
) -> tuple[CorpusArtifactInspection, ...]:
    return tuple(
        inspect_corpus_artifact(artifact, artifact_directory)
        for artifact in catalog.artifacts
    )


def build_corpus_lab_manifest(
    catalog: CorpusCatalog,
    artifact_directory: str | Path,
    artifact_ids: tuple[str, ...],
) -> LabManifest:
    if not artifact_ids:
        raise LabManifestError("real-world corpus runs require explicit artifact IDs")
    available = {artifact.id: artifact for artifact in catalog.artifacts}
    unknown = sorted(set(artifact_ids) - set(available))
    if unknown:
        raise LabManifestError(f"unknown corpus artifacts: {', '.join(unknown)}")
    if len(artifact_ids) != len(set(artifact_ids)):
        raise LabManifestError("corpus artifact IDs must not be repeated")
    root = Path(artifact_directory).resolve()
    scenarios: list[LabScenario] = []
    for artifact_id in artifact_ids:
        artifact = available[artifact_id]
        inspection = inspect_corpus_artifact(artifact, root)
        scenarios.append(
            LabScenario(
                id=artifact.id,
                category=ScenarioCategory.CORPUS,
                status=ScenarioStatus.IMPLEMENTED,
                purpose=artifact.purpose,
                project_name=artifact.project_name,
                project_version=artifact.project_version,
                hypotheses=artifact.hypotheses,
                decision_questions=artifact.decision_questions,
                steps=(
                    ScenarioStep(
                        id="import",
                        bom=inspection.path,
                        observations=(
                            Observation.PROJECT,
                            Observation.COMPONENTS,
                            Observation.DIRECT_COMPONENTS,
                            Observation.DEPENDENCY_GRAPH,
                            Observation.FINDINGS,
                            Observation.VULNERABILITIES,
                            Observation.METRICS,
                            Observation.BOM_EXPORT,
                        ),
                    ),
                ),
            )
        )
    return LabManifest(
        schema_version=3, target=catalog.target, scenarios=tuple(scenarios)
    )


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

    def observe_current_team(self) -> DependencyTrackObservation: ...

    def observe_project(self, project_uuid: str) -> DependencyTrackObservation: ...

    def observe_project_components(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...

    def observe_project_direct_components(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...

    def observe_project_services(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...

    def observe_project_dependency_graph(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...

    def observe_project_findings(
        self, project_uuid: str, *, suppressed: bool = False
    ) -> DependencyTrackObservation: ...

    def observe_analysis_trail(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> DependencyTrackObservation: ...

    def record_analysis_decision(
        self,
        *,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        action: AnalysisAction,
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
    request: dict[str, Any] = {
        "method": observation.method,
        "path": observation.path,
        "query": dict(observation.query),
    }
    if observation.request_payload is not None:
        request["payload"] = observation.request_payload
    return {
        "request": request,
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


def _project_record_dict(record: LabProjectRecord) -> dict[str, Any]:
    return {
        "scenario_id": record.scenario_id,
        "step_id": record.step_id,
        "project_name": record.project_name,
        "project_version": record.project_version,
        "project_uuid": record.project_uuid,
    }


def _write_project_ledger(
    run_directory: Path,
    run_id: str,
    records: list[LabProjectRecord],
) -> None:
    ledger_path = run_directory / "projects.json"
    temporary_path = run_directory / "projects.json.tmp"
    _write_json(
        temporary_path,
        {
            "schema_version": 1,
            "run_id": run_id,
            "projects": [_project_record_dict(record) for record in records],
        },
    )
    temporary_path.replace(ledger_path)


def _project_count(records: list[LabProjectRecord]) -> int:
    return len({(record.project_name, record.project_version) for record in records})


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


_ALIAS_ID_FIELDS = (
    "cveId",
    "ghsaId",
    "osvId",
    "sonatypeId",
    "snykId",
    "gsdId",
    "vulnDbId",
    "internalId",
)


def _vulnerability_aliases(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    aliases: set[str] = set()
    for alias in value:
        if isinstance(alias, str) and alias:
            aliases.add(alias)
        elif isinstance(alias, dict):
            aliases.update(
                str(alias[field]) for field in _ALIAS_ID_FIELDS if alias.get(field)
            )
    return sorted(aliases)


def _vulnerability_projection(vulnerability: Any) -> dict[str, Any]:
    if not isinstance(vulnerability, dict):
        vulnerability = {}
    return {
        "uuid": vulnerability.get("uuid"),
        "id": (
            vulnerability.get("vulnId")
            or vulnerability.get("vulnID")
            or vulnerability.get("id")
        ),
        "source": vulnerability.get("source"),
        "aliases": _vulnerability_aliases(vulnerability.get("aliases")),
        "severity": vulnerability.get("severity"),
        "epss_score": vulnerability.get("epssScore"),
        "epss_percentile": vulnerability.get("epssPercentile"),
        "cvss_v4_score": vulnerability.get("cvssV4Score"),
        "cvss_v3_base_score": vulnerability.get("cvssV3BaseScore"),
        "cvss_v2_base_score": vulnerability.get("cvssV2BaseScore"),
    }


def _finding_projection(finding: Any) -> dict[str, Any]:
    if not isinstance(finding, dict):
        finding = {}
    component = finding.get("component")
    if not isinstance(component, dict):
        component = {}
    analysis = finding.get("analysis")
    if not isinstance(analysis, dict):
        analysis = {}
    vulnerability = _vulnerability_projection(finding.get("vulnerability"))
    return {
        "finding_uuid": finding.get("uuid"),
        "component_uuid": component.get("uuid"),
        "component_identity": _component_identity(component),
        "vulnerability_uuid": vulnerability["uuid"],
        "vulnerability_id": vulnerability["id"],
        "vulnerability_source": vulnerability["source"],
        "aliases": vulnerability["aliases"],
        "severity": vulnerability["severity"],
        "epss_score": vulnerability["epss_score"],
        "epss_percentile": vulnerability["epss_percentile"],
        "cvss_v4_score": vulnerability["cvss_v4_score"],
        "cvss_v3_base_score": vulnerability["cvss_v3_base_score"],
        "cvss_v2_base_score": vulnerability["cvss_v2_base_score"],
        "analysis_state": analysis.get("state"),
        "analysis_suppressed": analysis.get("isSuppressed"),
    }


def _has_value(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def _finding_triage_coverage(findings: list[Any]) -> dict[str, int]:
    coverage = Counter[str]()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        component = finding.get("component")
        vulnerability = finding.get("vulnerability")
        analysis = finding.get("analysis")
        attribution = finding.get("attribution")
        if not isinstance(component, dict):
            component = {}
        if not isinstance(vulnerability, dict):
            vulnerability = {}
        if not isinstance(analysis, dict):
            analysis = {}
        if not isinstance(attribution, dict):
            attribution = {}
        candidates = {
            "component_latest_version": component.get("latestVersion"),
            "vulnerability_aliases": _vulnerability_aliases(
                vulnerability.get("aliases")
            ),
            "severity": vulnerability.get("severity"),
            "epss_score": vulnerability.get("epssScore"),
            "epss_percentile": vulnerability.get("epssPercentile"),
            "cvss_v4": vulnerability.get("cvssV4Score")
            or vulnerability.get("cvssV4BaseScore"),
            "cvss_v3": vulnerability.get("cvssV3BaseScore"),
            "cvss_v2": vulnerability.get("cvssV2BaseScore"),
            "description": vulnerability.get("description"),
            "recommendation": vulnerability.get("recommendation"),
            "references": vulnerability.get("references"),
            "cwe": vulnerability.get("cwes") or vulnerability.get("cweId"),
            "published": vulnerability.get("published"),
            "analysis_state": analysis.get("state"),
            "analysis_suppressed": analysis.get("isSuppressed"),
            "analyzer_attribution": attribution.get("analyzerIdentity"),
        }
        coverage.update(
            field_name for field_name, value in candidates.items() if _has_value(value)
        )
    return dict(sorted(coverage.items()))


def _step_summary(
    observations: dict[Observation, DependencyTrackObservation],
) -> dict[str, Any]:
    components = _payload_list(observations.get(Observation.COMPONENTS))
    direct_components = _payload_list(observations.get(Observation.DIRECT_COMPONENTS))
    services = _payload_list(observations.get(Observation.SERVICES))
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
    finding_projection = [_finding_projection(finding) for finding in findings]
    finding_projection.sort(
        key=lambda finding: (
            str(finding["component_identity"]),
            str(finding["vulnerability_source"]),
            str(finding["vulnerability_id"]),
        )
    )
    vulnerability_projection = [
        _vulnerability_projection(vulnerability) for vulnerability in vulnerabilities
    ]
    vulnerability_projection.sort(
        key=lambda vulnerability: (
            str(vulnerability["source"]),
            str(vulnerability["id"]),
        )
    )
    finding_sources = Counter(
        str(finding["vulnerability_source"] or "UNKNOWN")
        for finding in finding_projection
    )
    unique_vulnerabilities = {
        (finding["vulnerability_source"], finding["vulnerability_id"])
        for finding in finding_projection
        if finding["vulnerability_id"]
    }
    return {
        "component_count": len(components),
        "direct_component_count": len(direct_components),
        "service_count": len(services),
        "finding_count": len(findings),
        "unique_vulnerability_count": len(unique_vulnerabilities),
        "vulnerability_count": len(vulnerabilities),
        "components": component_projection,
        "finding_sources": dict(sorted(finding_sources.items())),
        "findings": finding_projection,
        "triage_field_coverage": _finding_triage_coverage(findings),
        "vulnerabilities": vulnerability_projection,
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
        Observation.DIRECT_COMPONENTS: client.observe_project_direct_components,
        Observation.SERVICES: client.observe_project_services,
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


def _scenario_mutates_analysis(scenario: LabScenario) -> bool:
    return any(step.analysis_actions for step in scenario.steps)


def _validate_analysis_team(
    observation: DependencyTrackObservation,
) -> None:
    payload = observation.payload
    if not isinstance(payload, dict) or not isinstance(
        payload.get("permissions"), list
    ):
        raise LabManifestError(
            "analysis key team response does not contain a permissions list"
        )
    permission_names = {
        str(permission.get("name"))
        for permission in payload["permissions"]
        if isinstance(permission, dict) and permission.get("name")
    }
    required = "VULNERABILITY_ANALYSIS"
    allowed = {
        required,
        "VIEW_BADGES",
        "VIEW_POLICY_VIOLATION",
        "VIEW_PORTFOLIO",
        "VIEW_VULNERABILITY",
    }
    if required not in permission_names:
        rendered = ", ".join(sorted(permission_names)) or "none"
        raise LabManifestError(
            "analysis key team must include VULNERABILITY_ANALYSIS; observed: "
            f"{rendered}"
        )
    disallowed = permission_names - allowed
    if disallowed:
        rendered = ", ".join(sorted(disallowed))
        raise LabManifestError(
            "analysis key team has permissions outside the lab analysis allowlist: "
            f"{rendered}"
        )


def _selected_scenarios(
    manifest: LabManifest, scenario_ids: tuple[str, ...]
) -> tuple[LabScenario, ...]:
    implemented = tuple(
        scenario
        for scenario in manifest.scenarios
        if scenario.status is ScenarioStatus.IMPLEMENTED
    )
    if not scenario_ids:
        return tuple(
            scenario
            for scenario in implemented
            if not _scenario_mutates_analysis(scenario)
        )
    available = {scenario.id: scenario for scenario in implemented}
    unknown = sorted(set(scenario_ids) - set(available))
    if unknown:
        raise LabManifestError(
            f"unknown or unimplemented lab scenarios: {', '.join(unknown)}"
        )
    return tuple(available[scenario_id] for scenario_id in scenario_ids)


def _matching_finding(finding: Any, action: AnalysisAction) -> bool:
    if not isinstance(finding, dict):
        return False
    component = finding.get("component")
    vulnerability = finding.get("vulnerability")
    if not isinstance(component, dict) or not isinstance(vulnerability, dict):
        return False
    component_purl = component.get("purl") or component.get("purlCoordinates")
    vulnerability_id = (
        vulnerability.get("vulnId")
        or vulnerability.get("vulnID")
        or vulnerability.get("id")
    )
    return (
        component_purl == action.component_purl
        and vulnerability_id == action.vulnerability_id
        and str(vulnerability.get("source") or "").upper()
        == action.vulnerability_source.upper()
    )


def _analysis_target(
    findings: DependencyTrackObservation, action: AnalysisAction
) -> tuple[str, str, dict[str, Any]] | None:
    matches = [
        finding
        for finding in _payload_list(findings)
        if _matching_finding(finding, action)
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise LabManifestError(
            f"analysis action {action.id!r} matched {len(matches)} findings"
        )
    finding = matches[0]
    component = finding.get("component")
    vulnerability = finding.get("vulnerability")
    component_uuid = component.get("uuid") if isinstance(component, dict) else None
    vulnerability_uuid = (
        vulnerability.get("uuid") if isinstance(vulnerability, dict) else None
    )
    if not component_uuid or not vulnerability_uuid:
        raise LabManifestError(
            f"analysis action {action.id!r} target has no component or "
            "vulnerability UUID"
        )
    return str(component_uuid), str(vulnerability_uuid), finding


def _wait_for_analysis_target(
    *,
    client: DependencyTrackLabApi,
    project_uuid: str,
    action: AnalysisAction,
    timeout: float,
    poll_interval: float,
) -> tuple[DependencyTrackObservation, str, str, dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while True:
        findings = client.observe_project_findings(project_uuid)
        target = _analysis_target(findings, action)
        if target is None:
            suppressed_findings = client.observe_project_findings(
                project_uuid, suppressed=True
            )
            suppressed_target = _analysis_target(suppressed_findings, action)
            if suppressed_target is not None:
                findings = suppressed_findings
                target = suppressed_target
        if target is not None:
            component_uuid, vulnerability_uuid, finding = target
            return findings, component_uuid, vulnerability_uuid, finding
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LabManifestError(
                f"analysis action {action.id!r} target finding was not observed"
            )
        time.sleep(min(max(0.0, poll_interval), remaining))


def _analysis_state(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return None
    return payload.get("analysisState") or payload.get("state")


def _analysis_suppressed(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return None
    if "isSuppressed" in payload:
        return payload["isSuppressed"]
    return payload.get("suppressed")


def _analysis_verification(
    *,
    action: AnalysisAction,
    update: DependencyTrackObservation,
    trail: DependencyTrackObservation,
    finding: dict[str, Any],
) -> dict[str, Any]:
    finding_analysis = finding.get("analysis")
    if not isinstance(finding_analysis, dict):
        finding_analysis = {}
    return {
        "action_id": action.id,
        "expected": {
            "state": action.state.value,
            "suppressed": action.suppressed,
        },
        "observed": {
            "update_state": _analysis_state(update.payload),
            "update_suppressed": _analysis_suppressed(update.payload),
            "trail_state": _analysis_state(trail.payload),
            "trail_suppressed": _analysis_suppressed(trail.payload),
            "finding_state": _analysis_state(finding_analysis),
            "finding_suppressed": _analysis_suppressed(finding_analysis),
            "trail_comment_count": (
                len(trail.payload.get("analysisComments", []))
                if isinstance(trail.payload, dict)
                and isinstance(trail.payload.get("analysisComments"), list)
                else None
            ),
        },
    }


def _run_analysis_actions(
    *,
    step: ScenarioStep,
    step_directory: Path,
    project_uuid: str,
    read_client: DependencyTrackLabApi,
    analysis_client: DependencyTrackLabApi,
    timeout: float,
    poll_interval: float,
) -> int:
    observation_count = 0
    for index, action in enumerate(step.analysis_actions, start=1):
        action_directory = (
            step_directory / "analysis-actions" / f"{index:02d}-{action.id}"
        )
        action_directory.mkdir(parents=True, exist_ok=False)
        before, component_uuid, vulnerability_uuid, _ = _wait_for_analysis_target(
            client=read_client,
            project_uuid=project_uuid,
            action=action,
            timeout=timeout,
            poll_interval=poll_interval,
        )
        _write_json(
            action_directory / "findings-before.json", _observation_dict(before)
        )
        update = analysis_client.record_analysis_decision(
            project_uuid=project_uuid,
            component_uuid=component_uuid,
            vulnerability_uuid=vulnerability_uuid,
            action=action,
        )
        _write_json(action_directory / "update.json", _observation_dict(update))
        trail = read_client.observe_analysis_trail(
            project_uuid, component_uuid, vulnerability_uuid
        )
        _write_json(action_directory / "trail.json", _observation_dict(trail))
        after = read_client.observe_project_findings(
            project_uuid, suppressed=action.suppressed
        )
        _write_json(action_directory / "findings-after.json", _observation_dict(after))
        target = _analysis_target(after, action)
        if target is None:
            raise LabManifestError(
                f"analysis action {action.id!r} target disappeared after update"
            )
        metrics = read_client.observe_project_metrics(project_uuid)
        _write_json(action_directory / "metrics.json", _observation_dict(metrics))
        _write_json(
            action_directory / "verification.json",
            _analysis_verification(
                action=action,
                update=update,
                trail=trail,
                finding=target[2],
            ),
        )
        observation_count += 5
    return observation_count


def _run_scenario_steps(
    *,
    selected: tuple[LabScenario, ...],
    manifest_root: Path,
    run_directory: Path,
    run_id: str,
    upload_client: DependencyTrackLabApi,
    read_client: DependencyTrackLabApi,
    analysis_client: DependencyTrackLabApi | None,
    processing_timeout: float,
    poll_interval: float,
    results: list[LabStepResult],
    project_records: list[LabProjectRecord],
) -> None:
    for scenario in selected:
        previous_summary: dict[str, Any] | None = None
        for index, step in enumerate(scenario.steps, start=1):
            declared_version = step.project_version or scenario.project_version
            project_version = f"{declared_version}-lab-{run_id[:8]}"
            record_index = len(project_records)
            project_records.append(
                LabProjectRecord(
                    scenario_id=scenario.id,
                    step_id=step.id,
                    project_name=scenario.project_name,
                    project_version=project_version,
                )
            )
            _write_project_ledger(run_directory, run_id, project_records)
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
            if (
                not isinstance(lookup.payload, dict)
                or not lookup.payload.get("uuid")
                or lookup.payload.get("name") != scenario.project_name
                or lookup.payload.get("version") != project_version
            ):
                raise LabManifestError(
                    f"scenario {scenario.id!r} Project lookup identity mismatch"
                )
            project_uuid = str(lookup.payload["uuid"])
            project_records[record_index] = LabProjectRecord(
                scenario_id=scenario.id,
                step_id=step.id,
                project_name=scenario.project_name,
                project_version=project_version,
                project_uuid=project_uuid,
            )
            _write_project_ledger(run_directory, run_id, project_records)
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
            analysis_observation_count = 0
            if step.analysis_actions:
                if analysis_client is None:
                    raise LabManifestError(
                        f"scenario {scenario.id!r} requires an analysis client"
                    )
                analysis_observation_count = _run_analysis_actions(
                    step=step,
                    step_directory=step_directory,
                    project_uuid=project_uuid,
                    read_client=read_client,
                    analysis_client=analysis_client,
                    timeout=processing_timeout,
                    poll_interval=poll_interval,
                )
            results.append(
                LabStepResult(
                    scenario_id=scenario.id,
                    step_id=step.id,
                    project_uuid=project_uuid,
                    snapshot_directory=str(step_directory),
                    observation_count=len(captured) + 1 + analysis_observation_count,
                )
            )


def run_lab_scenarios(
    manifest: LabManifest,
    *,
    manifest_path: str | Path,
    upload_client: DependencyTrackLabApi,
    read_client: DependencyTrackLabApi,
    output_directory: str | Path,
    analysis_client: DependencyTrackLabApi | None = None,
    scenario_ids: tuple[str, ...] = (),
    processing_timeout: float = 120.0,
    poll_interval: float = 5.0,
    openapi_contract_sha256: str | None = None,
    allow_analysis_mutation: bool = False,
) -> LabRunResult:
    selected = _selected_scenarios(manifest, scenario_ids)
    mutating_scenarios = [
        scenario.id for scenario in selected if _scenario_mutates_analysis(scenario)
    ]
    if mutating_scenarios and not allow_analysis_mutation:
        raise LabManifestError(
            "analysis mutation requires explicit opt-in for scenarios: "
            + ", ".join(mutating_scenarios)
        )
    if mutating_scenarios and analysis_client is None:
        raise LabManifestError(
            "analysis mutation requires a VULNERABILITY_ANALYSIS client"
        )
    analysis_team: DependencyTrackObservation | None = None
    if mutating_scenarios and analysis_client is not None:
        analysis_team = analysis_client.observe_current_team()
        _validate_analysis_team(analysis_team)
    run_id = str(uuid4())
    run_directory = Path(output_directory) / run_id
    run_directory.mkdir(parents=True, exist_ok=False)
    manifest_root = Path(manifest_path).resolve().parent
    results: list[LabStepResult] = []
    project_records: list[LabProjectRecord] = []
    started_at = datetime.now(UTC).isoformat()
    run_metadata = {
        "run_id": run_id,
        "status": "running",
        "started_at": started_at,
        "dependency_track_version": manifest.target.dependency_track_version,
        "openapi_contract_sha256": openapi_contract_sha256,
        "scenarios": [scenario.id for scenario in selected],
        "analysis_mutation_enabled": bool(mutating_scenarios),
        "project_ledger": "projects.json",
    }
    _write_json(
        run_directory / "run.json",
        run_metadata,
    )
    if analysis_team is not None:
        _write_json(
            run_directory / "analysis-key-team.json",
            _observation_dict(analysis_team),
        )
    _write_project_ledger(run_directory, run_id, project_records)
    try:
        _run_scenario_steps(
            selected=selected,
            manifest_root=manifest_root,
            run_directory=run_directory,
            run_id=run_id,
            upload_client=upload_client,
            read_client=read_client,
            analysis_client=analysis_client,
            processing_timeout=processing_timeout,
            poll_interval=poll_interval,
            results=results,
            project_records=project_records,
        )
    except Exception as exc:
        _write_json(
            run_directory / "run.json",
            {
                **run_metadata,
                "status": "failed",
                "failed_at": datetime.now(UTC).isoformat(),
                "completed_step_count": len(results),
                "project_count": _project_count(project_records),
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
            },
        )
        raise
    _write_json(
        run_directory / "run.json",
        {
            **run_metadata,
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
            "step_count": len(results),
            "project_count": _project_count(project_records),
        },
    )
    return LabRunResult(
        run_id=run_id,
        output_directory=str(run_directory),
        steps=tuple(results),
    )
