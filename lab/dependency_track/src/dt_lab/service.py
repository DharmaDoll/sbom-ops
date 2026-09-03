from __future__ import annotations

import hashlib
import json
import re
import time
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Callable
from copy import deepcopy
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
    BomUploadAttempt,
    CorpusArtifact,
    CorpusArtifactInspection,
    CorpusCatalog,
    CorpusSourceKind,
    DependencyTrackObservation,
    ExpectedBomRejection,
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
    VexRoundTrip,
    VexTargetingProbe,
    VexUpload,
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
    "projectProperty",
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


def _load_vex_round_trip(payload: Any, scenario_id: str, step_id: str) -> VexRoundTrip:
    field_name = f"scenario {scenario_id} step {step_id}.vex_round_trip"
    round_trip = _mapping(payload, field_name)
    _reject_unknown(round_trip, {"id", "seed_analysis", "replay_import"}, field_name)
    return VexRoundTrip(
        id=_required_string(round_trip, "id", field_name),
        seed_analysis=_load_analysis_action(
            round_trip.get("seed_analysis"), scenario_id, step_id
        ),
        replay_import=_required_bool(round_trip, "replay_import", field_name),
    )


def _load_vex_targeting_probe(
    payload: Any, scenario_id: str, step_id: str
) -> VexTargetingProbe:
    field_name = f"scenario {scenario_id} step {step_id}.vex_targeting_probe"
    probe = _mapping(payload, field_name)
    _reject_unknown(
        probe,
        {"id", "decision", "control_component_purl", "input_component_bom_ref"},
        field_name,
    )
    return VexTargetingProbe(
        id=_required_string(probe, "id", field_name),
        decision=_load_analysis_action(probe.get("decision"), scenario_id, step_id),
        control_component_purl=_required_string(
            probe, "control_component_purl", field_name
        ),
        input_component_bom_ref=_required_string(
            probe, "input_component_bom_ref", field_name
        ),
    )


def _load_expected_bom_rejection(
    payload: Any, scenario_id: str, step_id: str
) -> ExpectedBomRejection:
    field_name = f"scenario {scenario_id} step {step_id}.expected_bom_rejection"
    rejection = _mapping(payload, field_name)
    _reject_unknown(rejection, {"status", "media_type", "project_created"}, field_name)
    status = rejection.get("status")
    if not isinstance(status, int) or isinstance(status, bool):
        raise LabManifestError(f"{field_name}.status must be an integer")
    return ExpectedBomRejection(
        status=status,
        media_type=_required_string(rejection, "media_type", field_name),
        project_created=_required_bool(rejection, "project_created", field_name),
    )


def _load_step(payload: Any, scenario_id: str) -> ScenarioStep:
    step = _mapping(payload, f"scenario {scenario_id} step")
    _reject_unknown(
        step,
        {
            "id",
            "bom",
            "observe",
            "project_name",
            "project_version",
            "parent_step",
            "project_tags",
            "probe_project_properties",
            "analysis_actions",
            "vex_round_trip",
            "vex_targeting_probe",
            "expected_bom_rejection",
            "equivalent_to_step",
        },
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
        project_name=(
            _required_string(step, "project_name", f"scenario {scenario_id} step")
            if step.get("project_name") is not None
            else None
        ),
        project_version=(
            _required_string(step, "project_version", f"scenario {scenario_id} step")
            if step.get("project_version") is not None
            else None
        ),
        parent_step=(
            _required_string(step, "parent_step", f"scenario {scenario_id} step")
            if step.get("parent_step") is not None
            else None
        ),
        project_tags=tuple(
            str(item)
            for item in _list(
                step.get("project_tags", []),
                f"scenario {scenario_id} step {step_id}.project_tags",
            )
        ),
        probe_project_properties=(
            _required_bool(
                step,
                "probe_project_properties",
                f"scenario {scenario_id} step {step_id}",
            )
            if step.get("probe_project_properties") is not None
            else False
        ),
        analysis_actions=tuple(
            _load_analysis_action(item, scenario_id, step_id)
            for item in _list(
                step.get("analysis_actions", []),
                f"scenario {scenario_id} step {step_id}.analysis_actions",
            )
        ),
        vex_round_trip=(
            _load_vex_round_trip(step["vex_round_trip"], scenario_id, step_id)
            if step.get("vex_round_trip") is not None
            else None
        ),
        vex_targeting_probe=(
            _load_vex_targeting_probe(step["vex_targeting_probe"], scenario_id, step_id)
            if step.get("vex_targeting_probe") is not None
            else None
        ),
        expected_bom_rejection=(
            _load_expected_bom_rejection(
                step["expected_bom_rejection"], scenario_id, step_id
            )
            if step.get("expected_bom_rejection") is not None
            else None
        ),
        equivalent_to_step=(
            _required_string(step, "equivalent_to_step", f"scenario {scenario_id} step")
            if step.get("equivalent_to_step") is not None
            else None
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


def _validate_xml_bom(
    bom_path: Path,
    *,
    cyclonedx_versions: tuple[str, ...],
    scenario_id: str,
    step_id: str,
) -> str:
    try:
        root = ET.parse(bom_path).getroot()
    except ET.ParseError as exc:
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} BOM is not valid XML"
        ) from exc
    namespace_match = re.fullmatch(
        r"\{http://cyclonedx\.org/schema/bom/([0-9]+\.[0-9]+)\}bom", root.tag
    )
    if namespace_match is None:
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} is not a CycloneDX BOM"
        )
    spec_version = namespace_match.group(1)
    if spec_version not in cyclonedx_versions:
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} uses undeclared "
            f"CycloneDX version {spec_version!r}"
        )
    serial_number = root.get("serialNumber")
    if not isinstance(serial_number, str) or not serial_number.startswith("urn:uuid:"):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} requires a UUID serialNumber"
        )
    namespace = {"cdx": f"http://cyclonedx.org/schema/bom/{spec_version}"}
    root_component = root.find("cdx:metadata/cdx:component", namespace)
    component_elements = root.findall("cdx:components/cdx:component", namespace)
    service_elements = root.findall("cdx:services/cdx:service", namespace)
    inventory_elements = component_elements + service_elements
    inventory_refs = [element.get("bom-ref") for element in inventory_elements]
    if any(not reference for reference in inventory_refs):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} requires bom-ref on every "
            "component and service"
        )
    known_refs = {str(reference) for reference in inventory_refs}
    if root_component is not None and root_component.get("bom-ref"):
        known_refs.add(str(root_component.get("bom-ref")))
    if len(inventory_refs) != len(set(inventory_refs)):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} has duplicate bom-ref values"
        )
    referenced = {
        str(element.get("ref"))
        for element in root.findall(".//cdx:dependencies//cdx:dependency", namespace)
        if element.get("ref")
    }
    dependency_elements = root.findall(".//cdx:dependencies//cdx:dependency", namespace)
    if any(not element.get("ref") for element in dependency_elements):
        raise LabManifestError(
            f"scenario {scenario_id!r} step {step_id!r} has an invalid dependency entry"
        )
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
    serial_number_sources: dict[str, Path] = {}
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
            elif bom_path.suffix == ".xml":
                serial_number = _validate_xml_bom(
                    bom_path,
                    cyclonedx_versions=manifest.target.cyclonedx_versions,
                    scenario_id=scenario.id,
                    step_id=step.id,
                )
            else:
                continue
                if bom_path.suffix in {".json", ".xml"}:
                    existing_source = serial_number_sources.get(serial_number)
                    if existing_source is not None and existing_source != bom_path:
                        raise LabManifestError(
                            f"duplicate CycloneDX serialNumber in lab corpus: "
                            f"{serial_number}"
                        )
                    serial_number_sources[serial_number] = bom_path
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
        self,
        project_name: str,
        project_version: str,
        bom_path: str | Path,
        *,
        parent_project_uuid: str | None = None,
        project_tags: tuple[str, ...] = (),
    ) -> BomUpload: ...

    def attempt_bom_upload_by_project_coordinates(
        self,
        project_name: str,
        project_version: str,
        bom_path: str | Path,
        *,
        parent_project_uuid: str | None = None,
        project_tags: tuple[str, ...] = (),
    ) -> BomUploadAttempt: ...

    def wait_for_bom_processing(
        self,
        token: str,
        *,
        timeout: float = 120.0,
        poll_interval: float = 5.0,
    ) -> None: ...

    def upload_vex_for_project(
        self, project_uuid: str, vex_path: str | Path
    ) -> VexUpload: ...

    def observe_project_lookup(
        self, project_name: str, project_version: str
    ) -> DependencyTrackObservation: ...

    def observe_project_lookup_if_present(
        self, project_name: str, project_version: str
    ) -> DependencyTrackObservation: ...

    def observe_project_children(
        self, project_uuid: str
    ) -> DependencyTrackObservation: ...

    def observe_projects_by_tag(self, tag: str) -> DependencyTrackObservation: ...

    def attempt_observe_project_properties(
        self, project_uuid: str
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

    def observe_analysis_trail_if_present(
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

    def observe_project_vex_export(
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


def _without_uuid_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _without_uuid_fields(item)
            for key, item in value.items()
            if str(key).lower() != "uuid" and not str(key).lower().endswith("_uuid")
        }
    if isinstance(value, list):
        return [_without_uuid_fields(item) for item in value]
    return value


def _identity_uuid_projection(summary: dict[str, Any]) -> dict[str, Any]:
    components = {
        str(component.get("identity")): component.get("uuid")
        for component in summary.get("components", [])
        if isinstance(component, dict)
    }
    findings = {
        "|".join(
            (
                str(finding.get("component_identity")),
                str(finding.get("vulnerability_source")),
                str(finding.get("vulnerability_id")),
            )
        ): {
            "finding_uuid": finding.get("finding_uuid"),
            "component_uuid": finding.get("component_uuid"),
            "vulnerability_uuid": finding.get("vulnerability_uuid"),
        }
        for finding in summary.get("findings", [])
        if isinstance(finding, dict)
    }
    vulnerabilities = {
        f"{vulnerability.get('source')}|{vulnerability.get('id')}": (
            vulnerability.get("uuid")
        )
        for vulnerability in summary.get("vulnerabilities", [])
        if isinstance(vulnerability, dict)
    }
    return {
        "components": dict(sorted(components.items())),
        "findings": dict(sorted(findings.items())),
        "vulnerabilities": dict(sorted(vulnerabilities.items())),
    }


def _dependency_graph_projection(
    observation: DependencyTrackObservation | None,
) -> dict[str, Any]:
    semantic: list[dict[str, Any]] = []
    uuids: dict[str, Any] = {}
    for component in _payload_list(observation):
        if not isinstance(component, dict):
            continue
        identity = _component_identity(component)
        semantic.append(
            {
                "identity": identity,
                "group": component.get("group"),
                "name": component.get("name"),
                "version": component.get("version"),
                "purl": component.get("purl") or component.get("purlCoordinates"),
                "cpe": component.get("cpe"),
            }
        )
        uuids[identity] = component.get("uuid")
    semantic.sort(key=lambda component: str(component["identity"]))
    return {"semantic": semantic, "uuids": dict(sorted(uuids.items()))}


def _cyclonedx_component_projection(component: Any) -> dict[str, Any]:
    if not isinstance(component, dict):
        return {}
    return {
        "bom-ref": component.get("bom-ref"),
        "type": component.get("type"),
        "group": component.get("group"),
        "name": component.get("name"),
        "version": component.get("version"),
        "purl": component.get("purl"),
        "cpe": component.get("cpe"),
        "scope": component.get("scope"),
    }


def _bom_export_projection(
    observation: DependencyTrackObservation | None,
) -> dict[str, Any] | None:
    if observation is None or not isinstance(observation.payload, dict):
        return None
    payload = observation.payload
    metadata = payload.get("metadata")
    metadata_component = (
        metadata.get("component") if isinstance(metadata, dict) else None
    )
    components = [
        _cyclonedx_component_projection(component)
        for component in payload.get("components", [])
        if isinstance(component, dict)
    ]
    components.sort(
        key=lambda component: (
            str(component.get("purl")),
            str(component.get("group")),
            str(component.get("name")),
            str(component.get("version")),
        )
    )
    services = [
        {
            "bom-ref": service.get("bom-ref"),
            "group": service.get("group"),
            "name": service.get("name"),
            "version": service.get("version"),
            "endpoints": sorted(str(item) for item in service.get("endpoints", [])),
            "authenticated": service.get("authenticated"),
            "x-trust-boundary": service.get("x-trust-boundary"),
        }
        for service in payload.get("services", [])
        if isinstance(service, dict)
    ]
    services.sort(
        key=lambda service: (
            str(service.get("group")),
            str(service.get("name")),
            str(service.get("version")),
        )
    )
    dependencies = [
        {
            "ref": dependency.get("ref"),
            "dependsOn": sorted(str(item) for item in dependency.get("dependsOn", [])),
        }
        for dependency in payload.get("dependencies", [])
        if isinstance(dependency, dict)
    ]
    dependencies.sort(key=lambda dependency: str(dependency.get("ref")))
    return {
        "specVersion": payload.get("specVersion"),
        "metadata_component": _cyclonedx_component_projection(metadata_component),
        "components": components,
        "services": services,
        "dependencies": dependencies,
    }


def _format_equivalence_projection(
    summary: dict[str, Any],
    observations: dict[Observation, DependencyTrackObservation],
) -> dict[str, Any]:
    return {
        "summary_semantics": _without_uuid_fields(summary),
        "identity_uuids": _identity_uuid_projection(summary),
        "dependency_graph": _dependency_graph_projection(
            observations.get(Observation.DEPENDENCY_GRAPH)
        ),
        "bom_export": _bom_export_projection(observations.get(Observation.BOM_EXPORT)),
    }


def _step_equivalence(
    *,
    reference_step_id: str,
    reference_summary: dict[str, Any],
    reference_observations: dict[Observation, DependencyTrackObservation],
    candidate_summary: dict[str, Any],
    candidate_observations: dict[Observation, DependencyTrackObservation],
) -> dict[str, Any]:
    reference = _format_equivalence_projection(
        reference_summary, reference_observations
    )
    candidate = _format_equivalence_projection(
        candidate_summary, candidate_observations
    )
    checks = {
        key: reference[key] == candidate[key]
        for key in (
            "summary_semantics",
            "identity_uuids",
            "dependency_graph",
            "bom_export",
        )
    }
    return {
        "reference_step": reference_step_id,
        "equivalent": all(checks.values()),
        "checks": checks,
        "reference": reference,
        "candidate": candidate,
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
        Observation.VEX_EXPORT: client.observe_project_vex_export,
    }
    observer = observers.get(observation)
    if observer is None:
        raise LabManifestError(
            f"observation {observation.value!r} is not implemented by the lab runner"
        )
    return observer(project_uuid)


def _scenario_mutates_analysis(scenario: LabScenario) -> bool:
    return any(
        step.analysis_actions
        or step.vex_round_trip is not None
        or step.vex_targeting_probe is not None
        for step in scenario.steps
    )


def _scenario_requires_explicit_selection(scenario: LabScenario) -> bool:
    return _scenario_mutates_analysis(scenario) or any(
        step.expected_bom_rejection is not None for step in scenario.steps
    )


def _validate_analysis_team(
    observation: DependencyTrackObservation,
) -> None:
    permission_names = _team_permission_names(observation)
    required = "VULNERABILITY_ANALYSIS"
    allowed = {
        required,
        "VIEW_BADGES",
        "VIEW_POLICY_VIOLATION",
        "VIEW_PORTFOLIO",
        "VIEW_VULNERABILITY",
    }
    if required not in permission_names:
        rendered = ", ".join(permission_names) or "none"
        raise LabManifestError(
            "analysis key team must include VULNERABILITY_ANALYSIS; observed: "
            f"{rendered}"
        )
    disallowed = set(permission_names) - allowed
    if disallowed:
        rendered = ", ".join(sorted(disallowed))
        raise LabManifestError(
            "analysis key team has permissions outside the lab analysis allowlist: "
            f"{rendered}"
        )


def _team_permission_names(
    observation: DependencyTrackObservation,
) -> tuple[str, ...]:
    payload = observation.payload
    if not isinstance(payload, dict) or not isinstance(
        payload.get("permissions"), list
    ):
        raise LabManifestError("team response does not contain a permissions list")
    return tuple(
        sorted(
            str(permission.get("name"))
            for permission in payload["permissions"]
            if isinstance(permission, dict) and permission.get("name")
        )
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
            if not _scenario_requires_explicit_selection(scenario)
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


def _json_digest(payload: Any) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _analysis_field(payload: Any, *names: str) -> Any:
    if not isinstance(payload, dict):
        return None
    for name in names:
        if name in payload:
            return payload[name]
    return None


def _analysis_decision_projection(payload: Any) -> dict[str, Any]:
    return {
        "state": _analysis_state(payload),
        "justification": _analysis_field(
            payload, "analysisJustification", "justification"
        ),
        "response": _analysis_field(payload, "analysisResponse", "response"),
        "detail": _analysis_field(payload, "analysisDetails", "detail"),
        "suppressed": _analysis_suppressed(payload),
    }


def _requested_analysis_projection(action: AnalysisAction) -> dict[str, Any]:
    return {
        "state": action.state.value,
        "justification": action.justification.value,
        "response": action.response.value,
        "detail": action.detail,
        "suppressed": action.suppressed,
    }


def _analysis_comments(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(
        payload.get("analysisComments"), list
    ):
        return []
    return [
        {
            "timestamp": comment.get("timestamp"),
            "comment": comment.get("comment"),
            "commenter": comment.get("commenter"),
        }
        for comment in payload["analysisComments"]
        if isinstance(comment, dict)
    ]


def _observation_validators(
    observation: DependencyTrackObservation,
) -> dict[str, str | None]:
    headers = {str(key).lower(): str(value) for key, value in observation.headers}
    return {
        "etag": headers.get("etag"),
        "last_modified": headers.get("last-modified"),
    }


def _analysis_reconciliation_entry(
    *,
    action: AnalysisAction,
    trail: DependencyTrackObservation,
    findings: DependencyTrackObservation,
    finding: dict[str, Any],
    default_finding_present: bool,
    including_suppressed_finding_present: bool,
) -> dict[str, Any]:
    finding_analysis = finding.get("analysis")
    request_decision = _requested_analysis_projection(action)
    trail_decision = _analysis_decision_projection(trail.payload)
    finding_decision = _analysis_decision_projection(finding_analysis)
    comments = _analysis_comments(trail.payload)
    timestamps = [
        timestamp
        for comment in comments
        if isinstance((timestamp := comment.get("timestamp")), int)
    ]
    audit_projection = {"decision": trail_decision, "comments": comments}
    return {
        "action_id": action.id,
        "request_comment": action.comment,
        "request_decision": request_decision,
        "request_decision_sha256": _json_digest(request_decision),
        "trail_decision": trail_decision,
        "trail_decision_sha256": _json_digest(trail_decision),
        "finding_decision": finding_decision,
        "finding_decision_sha256": _json_digest(finding_decision),
        "audit_sha256": _json_digest(audit_projection),
        "audit_comment_count": len(comments),
        "last_comment_timestamp": max(timestamps) if timestamps else None,
        "trail_validators": _observation_validators(trail),
        "finding_validators": _observation_validators(findings),
        "default_finding_present": default_finding_present,
        "including_suppressed_finding_present": (including_suppressed_finding_present),
    }


def _with_reconciliation_delta(
    current: dict[str, Any], previous: dict[str, Any] | None
) -> dict[str, Any]:
    result = dict(current)
    if previous is None:
        result["delta_from_previous"] = None
        return result
    current_timestamp = current.get("last_comment_timestamp")
    previous_timestamp = previous.get("last_comment_timestamp")
    result["delta_from_previous"] = {
        "request_decision_changed": (
            current["request_decision_sha256"] != previous["request_decision_sha256"]
        ),
        "trail_decision_changed": (
            current["trail_decision_sha256"] != previous["trail_decision_sha256"]
        ),
        "finding_decision_changed": (
            current["finding_decision_sha256"] != previous["finding_decision_sha256"]
        ),
        "audit_changed": current["audit_sha256"] != previous["audit_sha256"],
        "audit_comment_count_delta": (
            current["audit_comment_count"] - previous["audit_comment_count"]
        ),
        "last_comment_timestamp_advanced": (
            isinstance(current_timestamp, int)
            and isinstance(previous_timestamp, int)
            and current_timestamp > previous_timestamp
        ),
    }
    return result


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
    reconciliation_entries: list[dict[str, Any]] = []
    targets: dict[tuple[str, str, str], tuple[AnalysisAction, str, str]] = {}
    try:
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
            target_key = (
                action.component_purl,
                action.vulnerability_source,
                action.vulnerability_id,
            )
            targets[target_key] = (action, component_uuid, vulnerability_uuid)
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
            after_default = read_client.observe_project_findings(project_uuid)
            _write_json(
                action_directory / "findings-after-default.json",
                _observation_dict(after_default),
            )
            after_including_suppressed = read_client.observe_project_findings(
                project_uuid, suppressed=True
            )
            _write_json(
                action_directory / "findings-after-including-suppressed.json",
                _observation_dict(after_including_suppressed),
            )
            default_target = _analysis_target(after_default, action)
            including_suppressed_target = _analysis_target(
                after_including_suppressed, action
            )
            if including_suppressed_target is None:
                raise LabManifestError(
                    f"analysis action {action.id!r} target disappeared after update"
                )
            after = after_including_suppressed if action.suppressed else after_default
            target = including_suppressed_target
            _write_json(
                action_directory / "findings-after.json", _observation_dict(after)
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
            entry = _analysis_reconciliation_entry(
                action=action,
                trail=trail,
                findings=after_including_suppressed,
                finding=target[2],
                default_finding_present=default_target is not None,
                including_suppressed_finding_present=(
                    including_suppressed_target is not None
                ),
            )
            reconciliation_entries.append(
                _with_reconciliation_delta(
                    entry,
                    reconciliation_entries[-1] if reconciliation_entries else None,
                )
            )
            observation_count += 6

        _write_json(
            step_directory / "analysis-actions" / "reconciliation.json",
            {
                "finding_etag_observed": any(
                    entry["finding_validators"]["etag"] is not None
                    for entry in reconciliation_entries
                ),
                "finding_last_modified_observed": any(
                    entry["finding_validators"]["last_modified"] is not None
                    for entry in reconciliation_entries
                ),
                "trail_etag_observed": any(
                    entry["trail_validators"]["etag"] is not None
                    for entry in reconciliation_entries
                ),
                "trail_last_modified_observed": any(
                    entry["trail_validators"]["last_modified"] is not None
                    for entry in reconciliation_entries
                ),
                "actions": reconciliation_entries,
            },
        )
    except Exception:
        if targets:
            emergency_directory = (
                step_directory / "analysis-actions" / "emergency-restore"
            )
            emergency_directory.mkdir(parents=True, exist_ok=True)
            try:
                for index, (action, component_uuid, vulnerability_uuid) in enumerate(
                    targets.values(), start=1
                ):
                    reset = _not_set_action(
                        action,
                        action_id=f"emergency-restore-{index}",
                        detail=(
                            "DT lab restores Analysis after a failed action sequence."
                        ),
                        comment="DT lab emergency-restores the disposable Finding.",
                    )
                    update = analysis_client.record_analysis_decision(
                        project_uuid=project_uuid,
                        component_uuid=component_uuid,
                        vulnerability_uuid=vulnerability_uuid,
                        action=reset,
                    )
                    _write_json(
                        emergency_directory / f"{index:02d}-update.json",
                        _observation_dict(update),
                    )
                    findings, finding = _wait_for_analysis_projection(
                        client=read_client,
                        project_uuid=project_uuid,
                        action=reset,
                        timeout=timeout,
                        poll_interval=poll_interval,
                        expected_suppressed=False,
                    )
                    _write_json(
                        emergency_directory / f"{index:02d}-findings.json",
                        _observation_dict(findings),
                    )
                    _write_json(
                        emergency_directory / f"{index:02d}-verification.json",
                        _finding_analysis_projection(finding),
                    )
            except Exception as restore_error:
                raise LabManifestError(
                    "Analysis action sequence failed and emergency restore also failed"
                ) from restore_error
        raise
    return observation_count


def _not_set_action(
    source: AnalysisAction, *, action_id: str, detail: str, comment: str
) -> AnalysisAction:
    return AnalysisAction(
        id=action_id,
        component_purl=source.component_purl,
        vulnerability_id=source.vulnerability_id,
        vulnerability_source=source.vulnerability_source,
        state=AnalysisState.NOT_SET,
        justification=AnalysisJustification.NOT_SET,
        response=AnalysisResponse.NOT_SET,
        detail=detail,
        comment=comment,
        suppressed=False,
    )


def _wait_for_analysis_projection(
    *,
    client: DependencyTrackLabApi,
    project_uuid: str,
    action: AnalysisAction,
    timeout: float,
    poll_interval: float,
    expected_suppressed: bool | None,
) -> tuple[DependencyTrackObservation, dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while True:
        observations = [client.observe_project_findings(project_uuid)]
        observations.append(
            client.observe_project_findings(project_uuid, suppressed=True)
        )
        for observation in observations:
            target = _analysis_target(observation, action)
            if target is None:
                continue
            finding = target[2]
            finding_analysis = finding.get("analysis")
            if not isinstance(finding_analysis, dict):
                finding_analysis = {}
            state_matches = _analysis_state(finding_analysis) == action.state.value
            suppression_matches = (
                expected_suppressed is None
                or _analysis_suppressed(finding_analysis) == expected_suppressed
            )
            if state_matches and suppression_matches:
                return observation, finding
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LabManifestError(
                f"analysis state {action.state.value!r} was not observed for "
                f"VEX round-trip {action.id!r}"
            )
        time.sleep(min(max(0.0, poll_interval), remaining))


def _matching_vex_entry(payload: Any, action: AnalysisAction) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(
        payload.get("vulnerabilities"), list
    ):
        raise LabManifestError("VEX export does not contain a vulnerabilities list")
    matches = [
        entry
        for entry in payload["vulnerabilities"]
        if isinstance(entry, dict)
        and entry.get("id") == action.vulnerability_id
        and isinstance(entry.get("source"), dict)
        and str(entry["source"].get("name") or "").upper()
        == action.vulnerability_source.upper()
    ]
    if len(matches) != 1:
        raise LabManifestError(
            f"VEX export matched {len(matches)} entries for "
            f"{action.vulnerability_source}:{action.vulnerability_id}"
        )
    return matches[0]


def _vex_affects_refs(entry: dict[str, Any]) -> list[str]:
    affects = entry.get("affects")
    if not isinstance(affects, list):
        return []
    return [
        str(affected["ref"])
        for affected in affects
        if isinstance(affected, dict) and affected.get("ref")
    ]


def _analysis_comment_count(observation: DependencyTrackObservation) -> int | None:
    if not isinstance(observation.payload, dict):
        return None
    comments = observation.payload.get("analysisComments")
    return len(comments) if isinstance(comments, list) else None


def _retarget_analysis_action(
    source: AnalysisAction, *, action_id: str, component_purl: str
) -> AnalysisAction:
    return AnalysisAction(
        id=action_id,
        component_purl=component_purl,
        vulnerability_id=source.vulnerability_id,
        vulnerability_source=source.vulnerability_source,
        state=source.state,
        justification=source.justification,
        response=source.response,
        detail=source.detail,
        comment=source.comment,
        suppressed=source.suppressed,
    )


def _component_by_purl(payload: Any, component_purl: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("components"), list):
        raise LabManifestError("CycloneDX export does not contain Components")
    matches = [
        component
        for component in payload["components"]
        if isinstance(component, dict) and component.get("purl") == component_purl
    ]
    if len(matches) != 1:
        raise LabManifestError(
            f"CycloneDX export matched {len(matches)} Components for {component_purl}"
        )
    return matches[0]


def _component_bom_ref(component: dict[str, Any], component_purl: str) -> str:
    bom_ref = component.get("bom-ref")
    if not isinstance(bom_ref, str) or not bom_ref:
        raise LabManifestError(f"CycloneDX Component {component_purl} has no bom-ref")
    return bom_ref


def _analysis_to_vex(action: AnalysisAction) -> dict[str, Any]:
    analysis: dict[str, Any] = {
        "state": action.state.value.lower(),
        "detail": action.detail,
    }
    if action.justification is not AnalysisJustification.NOT_SET:
        analysis["justification"] = action.justification.value.lower()
    if action.response is not AnalysisResponse.NOT_SET:
        analysis["response"] = [action.response.value.lower()]
    return analysis


def _targeted_vex_document(
    source_payload: Any,
    source_entry: dict[str, Any],
    *,
    affects_ref: str,
    action: AnalysisAction,
    components: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    if not isinstance(source_payload, dict):
        raise LabManifestError("VEX export is not a JSON object")
    required = ("bomFormat", "specVersion", "metadata")
    missing = [key for key in required if key not in source_payload]
    if missing:
        raise LabManifestError(
            "VEX export is missing required fields: " + ", ".join(missing)
        )
    document = {
        key: deepcopy(source_payload[key])
        for key in ("bomFormat", "specVersion", "metadata")
    }
    document["serialNumber"] = f"urn:uuid:{uuid4()}"
    document["version"] = 1
    if components:
        document["components"] = deepcopy(list(components))
    target_entry = deepcopy(source_entry)
    target_entry["analysis"] = _analysis_to_vex(action)
    target_entry["affects"] = [{"ref": affects_ref}]
    document["vulnerabilities"] = [target_entry]
    return document


def _finding_analysis_projection(finding: dict[str, Any]) -> dict[str, Any]:
    analysis = finding.get("analysis")
    if not isinstance(analysis, dict):
        analysis = {}
    return {
        "state": _analysis_state(analysis),
        "suppressed": _analysis_suppressed(analysis),
    }


def _capture_vex_targeting_projection(
    *,
    client: DependencyTrackLabApi,
    project_uuid: str,
    action: AnalysisAction,
    component_uuid: str,
    vulnerability_uuid: str,
    directory: Path,
    prefix: str,
    timeout: float,
    poll_interval: float,
) -> dict[str, Any]:
    findings, observed_component_uuid, observed_vulnerability_uuid, finding = (
        _wait_for_analysis_target(
            client=client,
            project_uuid=project_uuid,
            action=action,
            timeout=timeout,
            poll_interval=poll_interval,
        )
    )
    if (
        observed_component_uuid != component_uuid
        or observed_vulnerability_uuid != vulnerability_uuid
    ):
        raise LabManifestError(
            f"VEX targeting probe {action.id!r} target identity changed"
        )
    _write_json(directory / f"{prefix}-findings.json", _observation_dict(findings))
    trail = client.observe_analysis_trail_if_present(
        project_uuid, component_uuid, vulnerability_uuid
    )
    _write_json(directory / f"{prefix}-trail.json", _observation_dict(trail))
    return {
        **_finding_analysis_projection(finding),
        "trail_present": trail.status != 404,
        "trail_comment_count": _analysis_comment_count(trail),
    }


def _restore_vex_targeting_targets(
    *,
    targets: tuple[tuple[str, AnalysisAction, str, str], ...],
    project_uuid: str,
    read_client: DependencyTrackLabApi,
    analysis_client: DependencyTrackLabApi,
    directory: Path,
    phase: str,
    timeout: float,
    poll_interval: float,
) -> dict[str, dict[str, Any]]:
    phase_directory = directory / phase
    phase_directory.mkdir(parents=True, exist_ok=True)
    verification: dict[str, dict[str, Any]] = {}
    for label, selector, component_uuid, vulnerability_uuid in targets:
        reset = _not_set_action(
            selector,
            action_id=f"{phase}-{label}",
            detail=f"DT lab {phase} restores the VEX targeting probe to NOT_SET.",
            comment=f"DT lab {phase} restores the {label} Finding.",
        )
        update = analysis_client.record_analysis_decision(
            project_uuid=project_uuid,
            component_uuid=component_uuid,
            vulnerability_uuid=vulnerability_uuid,
            action=reset,
        )
        _write_json(phase_directory / f"{label}-update.json", _observation_dict(update))
        findings, finding = _wait_for_analysis_projection(
            client=read_client,
            project_uuid=project_uuid,
            action=reset,
            timeout=timeout,
            poll_interval=poll_interval,
            expected_suppressed=False,
        )
        _write_json(
            phase_directory / f"{label}-findings.json",
            _observation_dict(findings),
        )
        verification[label] = _finding_analysis_projection(finding)
    _write_json(phase_directory / "verification.json", verification)
    return verification


def _apply_vex_targeting_document(
    *,
    label: str,
    vex_path: Path,
    targets: tuple[tuple[str, AnalysisAction, str, str], ...],
    project_uuid: str,
    read_client: DependencyTrackLabApi,
    analysis_client: DependencyTrackLabApi,
    directory: Path,
    timeout: float,
    poll_interval: float,
) -> dict[str, dict[str, Any]]:
    upload = analysis_client.upload_vex_for_project(project_uuid, vex_path)
    _write_json(directory / f"{label}-upload.json", {"token": upload.token})
    analysis_client.wait_for_bom_processing(
        upload.token, timeout=timeout, poll_interval=poll_interval
    )
    return {
        target_label: _capture_vex_targeting_projection(
            client=read_client,
            project_uuid=project_uuid,
            action=action,
            component_uuid=component_uuid,
            vulnerability_uuid=vulnerability_uuid,
            directory=directory,
            prefix=f"{label}-{target_label}",
            timeout=timeout,
            poll_interval=poll_interval,
        )
        for target_label, action, component_uuid, vulnerability_uuid in targets
    }


def _run_vex_round_trip(
    *,
    round_trip: VexRoundTrip,
    step_directory: Path,
    project_uuid: str,
    read_client: DependencyTrackLabApi,
    analysis_client: DependencyTrackLabApi,
    timeout: float,
    poll_interval: float,
) -> int:
    directory = step_directory / "vex-round-trip" / round_trip.id
    directory.mkdir(parents=True, exist_ok=False)
    seed = round_trip.seed_analysis
    before, component_uuid, vulnerability_uuid, _ = _wait_for_analysis_target(
        client=read_client,
        project_uuid=project_uuid,
        action=seed,
        timeout=timeout,
        poll_interval=poll_interval,
    )
    _write_json(directory / "findings-before.json", _observation_dict(before))
    reset = _not_set_action(
        seed,
        action_id="reset-before-import",
        detail="DT lab clears the seeded Analysis state before VEX import.",
        comment="DT lab resets the disposable Finding before VEX re-import.",
    )
    final_reset = _not_set_action(
        seed,
        action_id="final-restore-not-set",
        detail="DT lab VEX round-trip completed and restored to NOT_SET.",
        comment="DT lab restores the disposable Finding after VEX verification.",
    )
    restored = False
    observation_count = 1
    try:
        seed_update = analysis_client.record_analysis_decision(
            project_uuid=project_uuid,
            component_uuid=component_uuid,
            vulnerability_uuid=vulnerability_uuid,
            action=seed,
        )
        _write_json(directory / "seed-update.json", _observation_dict(seed_update))
        seed_findings, seed_finding = _wait_for_analysis_projection(
            client=read_client,
            project_uuid=project_uuid,
            action=seed,
            timeout=timeout,
            poll_interval=poll_interval,
            expected_suppressed=seed.suppressed,
        )
        _write_json(directory / "seed-findings.json", _observation_dict(seed_findings))
        seed_trail = read_client.observe_analysis_trail(
            project_uuid, component_uuid, vulnerability_uuid
        )
        _write_json(directory / "seed-trail.json", _observation_dict(seed_trail))
        source_vex = analysis_client.observe_project_vex_export(project_uuid)
        _write_json(directory / "source-vex.json", _observation_dict(source_vex))
        source_entry = _matching_vex_entry(source_vex.payload, seed)
        source_vex_path = directory / "source-vex.cdx.json"
        _write_json(source_vex_path, source_vex.payload)
        observation_count += 4

        reset_update = analysis_client.record_analysis_decision(
            project_uuid=project_uuid,
            component_uuid=component_uuid,
            vulnerability_uuid=vulnerability_uuid,
            action=reset,
        )
        _write_json(directory / "reset-update.json", _observation_dict(reset_update))
        reset_findings, reset_finding = _wait_for_analysis_projection(
            client=read_client,
            project_uuid=project_uuid,
            action=reset,
            timeout=timeout,
            poll_interval=poll_interval,
            expected_suppressed=False,
        )
        _write_json(
            directory / "reset-findings.json", _observation_dict(reset_findings)
        )
        observation_count += 2

        upload = analysis_client.upload_vex_for_project(project_uuid, source_vex_path)
        _write_json(directory / "vex-upload.json", {"token": upload.token})
        analysis_client.wait_for_bom_processing(
            upload.token, timeout=timeout, poll_interval=poll_interval
        )
        imported_findings, imported_finding = _wait_for_analysis_projection(
            client=read_client,
            project_uuid=project_uuid,
            action=seed,
            timeout=timeout,
            poll_interval=poll_interval,
            expected_suppressed=None,
        )
        _write_json(
            directory / "imported-findings.json",
            _observation_dict(imported_findings),
        )
        imported_trail = read_client.observe_analysis_trail(
            project_uuid, component_uuid, vulnerability_uuid
        )
        _write_json(
            directory / "imported-trail.json", _observation_dict(imported_trail)
        )
        imported_vex = analysis_client.observe_project_vex_export(project_uuid)
        _write_json(directory / "imported-vex.json", _observation_dict(imported_vex))
        imported_entry = _matching_vex_entry(imported_vex.payload, seed)
        observation_count += 4

        replayed_finding: dict[str, Any] | None = None
        replayed_trail: DependencyTrackObservation | None = None
        replayed_entry: dict[str, Any] | None = None
        if round_trip.replay_import:
            replay_upload = analysis_client.upload_vex_for_project(
                project_uuid, source_vex_path
            )
            _write_json(
                directory / "vex-replay-upload.json", {"token": replay_upload.token}
            )
            analysis_client.wait_for_bom_processing(
                replay_upload.token, timeout=timeout, poll_interval=poll_interval
            )
            replayed_findings, replayed_finding = _wait_for_analysis_projection(
                client=read_client,
                project_uuid=project_uuid,
                action=seed,
                timeout=timeout,
                poll_interval=poll_interval,
                expected_suppressed=None,
            )
            _write_json(
                directory / "replayed-findings.json",
                _observation_dict(replayed_findings),
            )
            replayed_trail = read_client.observe_analysis_trail(
                project_uuid, component_uuid, vulnerability_uuid
            )
            _write_json(
                directory / "replayed-trail.json",
                _observation_dict(replayed_trail),
            )
            replayed_vex = analysis_client.observe_project_vex_export(project_uuid)
            _write_json(
                directory / "replayed-vex.json", _observation_dict(replayed_vex)
            )
            replayed_entry = _matching_vex_entry(replayed_vex.payload, seed)
            observation_count += 4

        source_analysis = source_entry.get("analysis")
        imported_analysis = imported_entry.get("analysis")
        source_affects = _vex_affects_refs(source_entry)
        imported_affects = _vex_affects_refs(imported_entry)
        imported_suppressed = _analysis_suppressed(imported_finding.get("analysis"))
        replayed_analysis = (
            replayed_entry.get("analysis") if replayed_entry is not None else None
        )
        replayed_affects = (
            _vex_affects_refs(replayed_entry) if replayed_entry is not None else None
        )
        imported_comment_count = _analysis_comment_count(imported_trail)
        replayed_comment_count = (
            _analysis_comment_count(replayed_trail)
            if replayed_trail is not None
            else None
        )

        _write_json(
            directory / "verification.json",
            {
                "expected": {
                    "state": seed.state.value,
                    "seed_suppressed": seed.suppressed,
                },
                "seed": {
                    "finding_state": _analysis_state(seed_finding.get("analysis")),
                    "finding_suppressed": _analysis_suppressed(
                        seed_finding.get("analysis")
                    ),
                    "vex_analysis": source_analysis,
                    "vex_affects": source_affects,
                },
                "reset": {
                    "finding_state": _analysis_state(reset_finding.get("analysis")),
                    "finding_suppressed": _analysis_suppressed(
                        reset_finding.get("analysis")
                    ),
                },
                "imported": {
                    "finding_state": _analysis_state(imported_finding.get("analysis")),
                    "finding_suppressed": imported_suppressed,
                    "vex_analysis": imported_analysis,
                    "vex_affects": imported_affects,
                    "trail_comment_count": imported_comment_count,
                },
                "replayed": {
                    "enabled": round_trip.replay_import,
                    "finding_state": (
                        _analysis_state(replayed_finding.get("analysis"))
                        if replayed_finding is not None
                        else None
                    ),
                    "finding_suppressed": (
                        _analysis_suppressed(replayed_finding.get("analysis"))
                        if replayed_finding is not None
                        else None
                    ),
                    "vex_analysis": replayed_analysis,
                    "vex_affects": replayed_affects,
                    "trail_comment_count": replayed_comment_count,
                },
                "comparison": {
                    "finding_state_preserved": (
                        _analysis_state(imported_finding.get("analysis"))
                        == seed.state.value
                    ),
                    "vex_analysis_preserved": source_analysis == imported_analysis,
                    "vex_affects_preserved": source_affects == imported_affects,
                    "source_affects_component_purl": (
                        seed.component_purl in source_affects
                    ),
                    "suppression_projection_matches_seed": (
                        imported_suppressed == seed.suppressed
                    ),
                    "replay_state_idempotent": (
                        not round_trip.replay_import
                        or (
                            replayed_finding is not None
                            and _analysis_state(replayed_finding.get("analysis"))
                            == _analysis_state(imported_finding.get("analysis"))
                        )
                    ),
                    "replay_vex_analysis_idempotent": (
                        not round_trip.replay_import
                        or replayed_analysis == imported_analysis
                    ),
                    "replay_audit_comment_delta": (
                        replayed_comment_count - imported_comment_count
                        if replayed_comment_count is not None
                        and imported_comment_count is not None
                        else None
                    ),
                },
            },
        )

        final_update = analysis_client.record_analysis_decision(
            project_uuid=project_uuid,
            component_uuid=component_uuid,
            vulnerability_uuid=vulnerability_uuid,
            action=final_reset,
        )
        _write_json(
            directory / "final-reset-update.json", _observation_dict(final_update)
        )
        final_findings, final_finding = _wait_for_analysis_projection(
            client=read_client,
            project_uuid=project_uuid,
            action=final_reset,
            timeout=timeout,
            poll_interval=poll_interval,
            expected_suppressed=False,
        )
        _write_json(
            directory / "final-findings.json", _observation_dict(final_findings)
        )
        _write_json(
            directory / "final-verification.json",
            {
                "expected": {"state": "NOT_SET", "suppressed": False},
                "observed": {
                    "state": _analysis_state(final_finding.get("analysis")),
                    "suppressed": _analysis_suppressed(final_finding.get("analysis")),
                },
            },
        )
        observation_count += 2
        restored = True
    except Exception:
        if not restored:
            emergency_directory = directory / "emergency-restore"
            emergency_directory.mkdir(parents=True, exist_ok=True)
            try:
                emergency_update = analysis_client.record_analysis_decision(
                    project_uuid=project_uuid,
                    component_uuid=component_uuid,
                    vulnerability_uuid=vulnerability_uuid,
                    action=final_reset,
                )
                _write_json(
                    emergency_directory / "update.json",
                    _observation_dict(emergency_update),
                )
                emergency_findings, emergency_finding = _wait_for_analysis_projection(
                    client=read_client,
                    project_uuid=project_uuid,
                    action=final_reset,
                    timeout=timeout,
                    poll_interval=poll_interval,
                    expected_suppressed=False,
                )
                _write_json(
                    emergency_directory / "findings.json",
                    _observation_dict(emergency_findings),
                )
                _write_json(
                    emergency_directory / "verification.json",
                    {
                        "expected": {"state": "NOT_SET", "suppressed": False},
                        "observed": {
                            "state": _analysis_state(emergency_finding.get("analysis")),
                            "suppressed": _analysis_suppressed(
                                emergency_finding.get("analysis")
                            ),
                        },
                    },
                )
            except Exception as restore_error:
                raise LabManifestError(
                    "VEX round-trip failed and emergency Analysis restore also failed"
                ) from restore_error
        raise
    return observation_count


def _run_vex_targeting_probe(
    *,
    probe: VexTargetingProbe,
    step_directory: Path,
    project_uuid: str,
    read_client: DependencyTrackLabApi,
    analysis_client: DependencyTrackLabApi,
    timeout: float,
    poll_interval: float,
) -> int:
    directory = step_directory / "vex-targeting" / probe.id
    directory.mkdir(parents=True, exist_ok=False)
    primary = probe.decision
    control = _retarget_analysis_action(
        primary,
        action_id="control-component",
        component_purl=probe.control_component_purl,
    )
    (
        primary_before,
        primary_component_uuid,
        primary_vulnerability_uuid,
        primary_finding,
    ) = _wait_for_analysis_target(
        client=read_client,
        project_uuid=project_uuid,
        action=primary,
        timeout=timeout,
        poll_interval=poll_interval,
    )
    _write_json(
        directory / "primary-findings-before.json",
        _observation_dict(primary_before),
    )
    (
        control_before,
        control_component_uuid,
        control_vulnerability_uuid,
        control_finding,
    ) = _wait_for_analysis_target(
        client=read_client,
        project_uuid=project_uuid,
        action=control,
        timeout=timeout,
        poll_interval=poll_interval,
    )
    _write_json(
        directory / "control-findings-before.json",
        _observation_dict(control_before),
    )
    before = {
        "primary": _finding_analysis_projection(primary_finding),
        "control": _finding_analysis_projection(control_finding),
    }
    if any(
        projection["state"] not in (None, AnalysisState.NOT_SET.value)
        or projection["suppressed"] is True
        for projection in before.values()
    ):
        raise LabManifestError(
            f"VEX targeting probe {probe.id!r} requires clean unsuppressed Findings"
        )

    bom_export = read_client.observe_project_bom_export(project_uuid)
    _write_json(directory / "bom-export.json", _observation_dict(bom_export))
    exported_primary_component = _component_by_purl(
        bom_export.payload, primary.component_purl
    )
    exported_control_component = _component_by_purl(
        bom_export.payload, control.component_purl
    )
    exported_component_ref = _component_bom_ref(
        exported_primary_component, primary.component_purl
    )
    control_component_ref = _component_bom_ref(
        exported_control_component, control.component_purl
    )
    source_vex = analysis_client.observe_project_vex_export(project_uuid)
    _write_json(directory / "source-vex.json", _observation_dict(source_vex))
    source_entry = _matching_vex_entry(source_vex.payload, primary)
    project_refs = _vex_affects_refs(source_entry)
    if len(project_refs) != 1:
        raise LabManifestError(
            f"VEX targeting probe {probe.id!r} expected one Project affects ref"
        )
    project_ref = project_refs[0]
    exported_component_vex_path = directory / "exported-component-targeted-vex.cdx.json"
    _write_json(
        exported_component_vex_path,
        _targeted_vex_document(
            source_vex.payload,
            source_entry,
            affects_ref=exported_component_ref,
            action=primary,
        ),
    )
    input_component_vex_path = directory / "input-component-targeted-vex.cdx.json"
    _write_json(
        input_component_vex_path,
        _targeted_vex_document(
            source_vex.payload,
            source_entry,
            affects_ref=probe.input_component_bom_ref,
            action=primary,
        ),
    )
    declared_component_vex_path = directory / "declared-component-targeted-vex.cdx.json"
    _write_json(
        declared_component_vex_path,
        _targeted_vex_document(
            source_vex.payload,
            source_entry,
            affects_ref=exported_component_ref,
            action=primary,
            components=(exported_primary_component,),
        ),
    )
    project_vex_path = directory / "project-targeted-vex.cdx.json"
    _write_json(
        project_vex_path,
        _targeted_vex_document(
            source_vex.payload,
            source_entry,
            affects_ref=project_ref,
            action=primary,
        ),
    )
    targets = (
        (
            "primary",
            primary,
            primary_component_uuid,
            primary_vulnerability_uuid,
        ),
        (
            "control",
            control,
            control_component_uuid,
            control_vulnerability_uuid,
        ),
    )
    observation_count = 4
    restored = False
    try:
        exported_component_scope = _apply_vex_targeting_document(
            label="exported-component-scope",
            vex_path=exported_component_vex_path,
            targets=targets,
            project_uuid=project_uuid,
            read_client=read_client,
            analysis_client=analysis_client,
            directory=directory,
            timeout=timeout,
            poll_interval=poll_interval,
        )
        observation_count += 5

        after_exported_component_restore = _restore_vex_targeting_targets(
            targets=targets,
            project_uuid=project_uuid,
            read_client=read_client,
            analysis_client=analysis_client,
            directory=directory,
            phase="after-exported-component-restore",
            timeout=timeout,
            poll_interval=poll_interval,
        )
        observation_count += 4

        input_component_scope = _apply_vex_targeting_document(
            label="input-component-scope",
            vex_path=input_component_vex_path,
            targets=targets,
            project_uuid=project_uuid,
            read_client=read_client,
            analysis_client=analysis_client,
            directory=directory,
            timeout=timeout,
            poll_interval=poll_interval,
        )
        observation_count += 5

        after_input_component_restore = _restore_vex_targeting_targets(
            targets=targets,
            project_uuid=project_uuid,
            read_client=read_client,
            analysis_client=analysis_client,
            directory=directory,
            phase="after-input-component-restore",
            timeout=timeout,
            poll_interval=poll_interval,
        )
        observation_count += 4

        declared_component_scope = _apply_vex_targeting_document(
            label="declared-component-scope",
            vex_path=declared_component_vex_path,
            targets=targets,
            project_uuid=project_uuid,
            read_client=read_client,
            analysis_client=analysis_client,
            directory=directory,
            timeout=timeout,
            poll_interval=poll_interval,
        )
        observation_count += 5

        after_declared_component_restore = _restore_vex_targeting_targets(
            targets=targets,
            project_uuid=project_uuid,
            read_client=read_client,
            analysis_client=analysis_client,
            directory=directory,
            phase="after-declared-component-restore",
            timeout=timeout,
            poll_interval=poll_interval,
        )
        observation_count += 4

        project_scope = _apply_vex_targeting_document(
            label="project-scope",
            vex_path=project_vex_path,
            targets=targets,
            project_uuid=project_uuid,
            read_client=read_client,
            analysis_client=analysis_client,
            directory=directory,
            timeout=timeout,
            poll_interval=poll_interval,
        )
        observation_count += 5

        _write_json(
            directory / "verification.json",
            {
                "references": {
                    "project": project_ref,
                    "exported_primary_component": exported_component_ref,
                    "exported_control_component": control_component_ref,
                    "input_primary_component": probe.input_component_bom_ref,
                },
                "before": before,
                "exported_component_scope": exported_component_scope,
                "after_exported_component_restore": (after_exported_component_restore),
                "input_component_scope": input_component_scope,
                "after_input_component_restore": after_input_component_restore,
                "declared_component_scope": declared_component_scope,
                "after_declared_component_restore": (after_declared_component_restore),
                "project_scope": project_scope,
                "comparison": {
                    "exported_component_scope_primary_changed": (
                        exported_component_scope["primary"]["state"]
                        == primary.state.value
                    ),
                    "exported_component_scope_control_unchanged": (
                        exported_component_scope["control"]["state"]
                        in (None, AnalysisState.NOT_SET.value)
                    ),
                    "input_component_scope_primary_changed": (
                        input_component_scope["primary"]["state"] == primary.state.value
                    ),
                    "input_component_scope_control_unchanged": (
                        input_component_scope["control"]["state"]
                        in (None, AnalysisState.NOT_SET.value)
                    ),
                    "declared_component_scope_primary_changed": (
                        declared_component_scope["primary"]["state"]
                        == primary.state.value
                    ),
                    "declared_component_scope_control_unchanged": (
                        declared_component_scope["control"]["state"]
                        in (None, AnalysisState.NOT_SET.value)
                    ),
                    "project_scope_primary_changed": (
                        project_scope["primary"]["state"] == primary.state.value
                    ),
                    "project_scope_control_changed": (
                        project_scope["control"]["state"] == primary.state.value
                    ),
                },
            },
        )

        final_verification = _restore_vex_targeting_targets(
            targets=targets,
            project_uuid=project_uuid,
            read_client=read_client,
            analysis_client=analysis_client,
            directory=directory,
            phase="final-restore",
            timeout=timeout,
            poll_interval=poll_interval,
        )
        observation_count += 4
        if any(
            projection["state"] != AnalysisState.NOT_SET.value
            or projection["suppressed"] is not False
            for projection in final_verification.values()
        ):
            raise LabManifestError(
                f"VEX targeting probe {probe.id!r} final restore did not converge"
            )
        restored = True
    except Exception:
        if not restored:
            try:
                _restore_vex_targeting_targets(
                    targets=targets,
                    project_uuid=project_uuid,
                    read_client=read_client,
                    analysis_client=analysis_client,
                    directory=directory,
                    phase="emergency-restore",
                    timeout=timeout,
                    poll_interval=poll_interval,
                )
            except Exception as restore_error:
                raise LabManifestError(
                    "VEX targeting probe failed and emergency restore also failed"
                ) from restore_error
        raise
    return observation_count


def _base_media_type(observation: DependencyTrackObservation) -> str:
    content_type = next(
        (value for key, value in observation.headers if key.lower() == "content-type"),
        "",
    )
    return content_type.split(";", 1)[0].strip().lower()


def _project_uuid_from_lookup(
    observation: DependencyTrackObservation,
    *,
    scenario_id: str,
    project_name: str,
    project_version: str,
) -> str:
    if (
        observation.status != 200
        or not isinstance(observation.payload, dict)
        or not observation.payload.get("uuid")
        or observation.payload.get("name") != project_name
        or observation.payload.get("version") != project_version
    ):
        raise LabManifestError(
            f"scenario {scenario_id!r} Project lookup identity mismatch"
        )
    return str(observation.payload["uuid"])


def _project_parent_uuid(observation: DependencyTrackObservation) -> str | None:
    if not isinstance(observation.payload, dict):
        return None
    parent = observation.payload.get("parent")
    if not isinstance(parent, dict) or not parent.get("uuid"):
        return None
    return str(parent["uuid"])


def _project_risk_projection(
    project: DependencyTrackObservation,
    metrics: DependencyTrackObservation,
) -> dict[str, Any]:
    project_payload = project.payload if isinstance(project.payload, dict) else {}
    metrics_payload = metrics.payload if isinstance(metrics.payload, dict) else {}
    return {
        "project": {
            "uuid": project_payload.get("uuid"),
            "name": project_payload.get("name"),
            "version": project_payload.get("version"),
            "collection_logic": project_payload.get("collectionLogic"),
            "last_inherited_risk_score": project_payload.get("lastInheritedRiskScore"),
        },
        "metrics": {
            key: metrics_payload.get(key)
            for key in (
                "collectionLogic",
                "components",
                "vulnerabilities",
                "findingsTotal",
                "critical",
                "high",
                "medium",
                "low",
                "inheritedRiskScore",
                "firstOccurrence",
                "lastOccurrence",
            )
        },
    }


def _capture_parent_relationship(
    *,
    step: ScenarioStep,
    step_directory: Path,
    child_uuid: str,
    parent_uuid: str,
    child_project: DependencyTrackObservation,
    child_metrics: DependencyTrackObservation,
    read_client: DependencyTrackLabApi,
) -> int:
    parent_project = read_client.observe_project(parent_uuid)
    parent_metrics = read_client.observe_project_metrics(parent_uuid)
    parent_children = read_client.observe_project_children(parent_uuid)
    _write_json(
        step_directory / "parent-project.json", _observation_dict(parent_project)
    )
    _write_json(
        step_directory / "parent-metrics.json", _observation_dict(parent_metrics)
    )
    _write_json(
        step_directory / "parent-children.json", _observation_dict(parent_children)
    )
    observed_parent_uuid = _project_parent_uuid(child_project)
    children = _payload_list(parent_children)
    matching_children = [
        child
        for child in children
        if isinstance(child, dict) and str(child.get("uuid")) == child_uuid
    ]
    verification = {
        "parent_step": step.parent_step,
        "relationship_verified": (
            observed_parent_uuid == parent_uuid and len(matching_children) == 1
        ),
        "child_parent_uuid": observed_parent_uuid,
        "parent_uuid": parent_uuid,
        "children_count": len(children),
        "matching_child_count": len(matching_children),
        "parent": _project_risk_projection(parent_project, parent_metrics),
        "child": _project_risk_projection(child_project, child_metrics),
    }
    _write_json(step_directory / "hierarchy.json", verification)
    if verification["relationship_verified"] is not True:
        raise LabManifestError(
            f"scenario step {step.id!r} parent-child relationship did not verify"
        )
    return 3


def _project_tag_names(project: DependencyTrackObservation) -> tuple[str, ...]:
    if not isinstance(project.payload, dict):
        raise LabManifestError("Project tag projection requires an object response")
    raw_tags = project.payload.get("tags", [])
    if not isinstance(raw_tags, list):
        raise LabManifestError("Project tags response must be a list")
    tags = tuple(
        sorted(
            str(tag["name"])
            for tag in raw_tags
            if isinstance(tag, dict) and tag.get("name")
        )
    )
    if len(tags) != len(raw_tags) or len(tags) != len(set(tags)):
        raise LabManifestError("Project tags response contains invalid entries")
    return tags


def _response_total_count(observation: DependencyTrackObservation) -> int | None:
    raw_value = next(
        (value for key, value in observation.headers if key.lower() == "x-total-count"),
        None,
    )
    if raw_value is None:
        return None
    try:
        return int(raw_value)
    except ValueError as exc:
        raise LabManifestError(
            f"response has invalid X-Total-Count: {raw_value!r}"
        ) from exc


def _capture_routing_metadata(
    *,
    step: ScenarioStep,
    step_directory: Path,
    project_uuid: str,
    project: DependencyTrackObservation,
    previous_tags: tuple[str, ...],
    upload_key_permissions: tuple[str, ...],
    read_client: DependencyTrackLabApi,
) -> tuple[int, tuple[str, ...]]:
    observed_tags = _project_tag_names(project)
    requested = set(step.project_tags)
    previous = set(previous_tags)
    observed = set(observed_tags)
    query_tags = tuple(sorted(requested | previous))
    queries: dict[str, dict[str, Any]] = {}
    observation_count = 0
    for index, tag in enumerate(query_tags, start=1):
        projects = read_client.observe_projects_by_tag(tag)
        _write_json(
            step_directory / f"tag-projects-{index:02d}.json",
            _observation_dict(projects),
        )
        payload = _payload_list(projects)
        matching_count = sum(
            1
            for candidate in payload
            if isinstance(candidate, dict)
            and str(candidate.get("uuid")) == project_uuid
        )
        membership = matching_count == 1
        expected_membership = tag in observed
        queries[tag] = {
            "current_project_present": membership,
            "expected_from_project_projection": expected_membership,
            "matching_project_count": matching_count,
            "returned_project_count": len(payload),
            "total_count": _response_total_count(projects),
        }
        if matching_count > 1 or membership != expected_membership:
            raise LabManifestError(
                f"scenario step {step.id!r} tag query disagrees with Project "
                f"projection for {tag!r}"
            )
        observation_count += 1

    property_projection: dict[str, Any] | None = None
    if step.probe_project_properties:
        properties = read_client.attempt_observe_project_properties(project_uuid)
        _write_json(
            step_directory / "project-properties.json",
            _observation_dict(properties),
        )
        if properties.status not in {200, 403}:
            raise LabManifestError(
                f"scenario step {step.id!r} Project property probe returned "
                f"unexpected HTTP {properties.status}"
            )
        property_count: int | None = None
        if properties.status == 200:
            property_count = len(_payload_list(properties))
        property_projection = {
            "status": properties.status,
            "readable_with_orchestrator_key": properties.status == 200,
            "property_count": property_count,
        }
        observation_count += 1

    summary = {
        "requested_tags": sorted(requested),
        "observed_tags": list(observed_tags),
        "previous_observed_tags": sorted(previous),
        "missing_requested_tags": sorted(requested - observed),
        "stale_previous_tags": sorted((previous - requested) & observed),
        "added_observed_tags": sorted(observed - previous),
        "removed_observed_tags": sorted(previous - observed),
        "request_exactly_reconciled": requested == observed,
        "upload_key_permissions": list(upload_key_permissions),
        "tag_queries": queries,
        "project_properties": property_projection,
    }
    _write_json(step_directory / "routing-metadata.json", summary)
    return observation_count, observed_tags


def _run_scenario_steps(
    *,
    selected: tuple[LabScenario, ...],
    manifest_root: Path,
    run_directory: Path,
    run_id: str,
    upload_client: DependencyTrackLabApi,
    read_client: DependencyTrackLabApi,
    analysis_client: DependencyTrackLabApi | None,
    upload_key_permissions: tuple[str, ...],
    processing_timeout: float,
    poll_interval: float,
    results: list[LabStepResult],
    project_records: list[LabProjectRecord],
) -> None:
    for scenario in selected:
        previous_summary: dict[str, Any] | None = None
        previous_project_key: tuple[str, str] | None = None
        summaries_by_step: dict[str, dict[str, Any]] = {}
        observations_by_step: dict[
            str, dict[Observation, DependencyTrackObservation]
        ] = {}
        project_uuids_by_step: dict[str, str] = {}
        project_tags_by_key: dict[tuple[str, str], tuple[str, ...]] = {}
        for index, step in enumerate(scenario.steps, start=1):
            project_name = step.project_name or scenario.project_name
            declared_version = step.project_version or scenario.project_version
            project_version = f"{declared_version}-lab-{run_id[:8]}"
            parent_project_uuid = (
                project_uuids_by_step[step.parent_step]
                if step.parent_step is not None
                else None
            )
            record_index = len(project_records)
            project_records.append(
                LabProjectRecord(
                    scenario_id=scenario.id,
                    step_id=step.id,
                    project_name=project_name,
                    project_version=project_version,
                )
            )
            _write_project_ledger(run_directory, run_id, project_records)
            step_directory = run_directory / scenario.id / f"{index:02d}-{step.id}"
            step_directory.mkdir(parents=True, exist_ok=False)
            project_uuid: str | None = None
            base_observation_count = 1
            if step.expected_bom_rejection is not None:
                expected = step.expected_bom_rejection
                attempt = upload_client.attempt_bom_upload_by_project_coordinates(
                    project_name,
                    project_version,
                    manifest_root / step.bom,
                    parent_project_uuid=parent_project_uuid,
                    project_tags=step.project_tags,
                )
                _write_json(
                    step_directory / "upload-rejection.json",
                    _observation_dict(attempt.observation),
                )
                if attempt.upload is not None:
                    raise LabManifestError(
                        f"scenario {scenario.id!r} expected BOM rejection but "
                        "Dependency-Track accepted the upload"
                    )
                actual_media_type = _base_media_type(attempt.observation)
                if (
                    attempt.observation.status != expected.status
                    or actual_media_type != expected.media_type.lower()
                ):
                    raise LabManifestError(
                        f"scenario {scenario.id!r} BOM rejection contract mismatch: "
                        f"expected HTTP {expected.status} {expected.media_type}, "
                        f"observed HTTP {attempt.observation.status} "
                        f"{actual_media_type or 'without Content-Type'}"
                    )
                lookup = read_client.observe_project_lookup_if_present(
                    project_name, project_version
                )
                project_created = lookup.status != 404
                if project_created != expected.project_created:
                    raise LabManifestError(
                        f"scenario {scenario.id!r} rejected BOM Project side effect "
                        "mismatch: expected project_created="
                        f"{expected.project_created}, "
                        f"observed project_created={project_created}"
                    )
                if project_created:
                    project_uuid = _project_uuid_from_lookup(
                        lookup,
                        scenario_id=scenario.id,
                        project_name=project_name,
                        project_version=project_version,
                    )
                base_observation_count = 2
            else:
                attempt = upload_client.attempt_bom_upload_by_project_coordinates(
                    project_name,
                    project_version,
                    manifest_root / step.bom,
                    parent_project_uuid=parent_project_uuid,
                    project_tags=step.project_tags,
                )
                _write_json(
                    step_directory / "bom-upload.json",
                    _observation_dict(attempt.observation),
                )
                if attempt.upload is None:
                    actual_media_type = _base_media_type(attempt.observation)
                    raise LabManifestError(
                        f"scenario {scenario.id!r} BOM upload was rejected: "
                        f"HTTP {attempt.observation.status} "
                        f"{actual_media_type or 'without Content-Type'}"
                    )
                upload = attempt.upload
                upload_client.wait_for_bom_processing(
                    upload.token,
                    timeout=processing_timeout,
                    poll_interval=poll_interval,
                )
                lookup = read_client.observe_project_lookup(
                    project_name, project_version
                )
                project_uuid = _project_uuid_from_lookup(
                    lookup,
                    scenario_id=scenario.id,
                    project_name=project_name,
                    project_version=project_version,
                )
            if project_uuid is not None:
                project_records[record_index] = LabProjectRecord(
                    scenario_id=scenario.id,
                    step_id=step.id,
                    project_name=project_name,
                    project_version=project_version,
                    project_uuid=project_uuid,
                )
                _write_project_ledger(run_directory, run_id, project_records)
                project_uuids_by_step[step.id] = project_uuid
            if step.observations and project_uuid is None:
                raise LabManifestError(
                    f"scenario {scenario.id!r} cannot capture Project observations "
                    "because no Project was created"
                )
            _write_json(
                step_directory / "project-lookup.json", _observation_dict(lookup)
            )
            captured: dict[Observation, DependencyTrackObservation] = {}
            for observation in step.observations:
                if project_uuid is None:  # guarded above; narrows for type checkers
                    raise LabManifestError("Project UUID is required for observations")
                result = _capture_observation(read_client, observation, project_uuid)
                captured[observation] = result
                _write_json(
                    step_directory / f"{observation.value}.json",
                    _observation_dict(result),
                )
            hierarchy_observation_count = 0
            if step.parent_step is not None:
                if project_uuid is None or parent_project_uuid is None:
                    raise LabManifestError(
                        f"scenario step {step.id!r} requires parent and child UUIDs"
                    )
                child_project = captured[Observation.PROJECT]
                child_metrics = captured[Observation.METRICS]
                hierarchy_observation_count = _capture_parent_relationship(
                    step=step,
                    step_directory=step_directory,
                    child_uuid=project_uuid,
                    parent_uuid=parent_project_uuid,
                    child_project=child_project,
                    child_metrics=child_metrics,
                    read_client=read_client,
                )
            routing_observation_count = 0
            project_key = (project_name, project_version)
            if step.project_tags or step.probe_project_properties:
                if Observation.PROJECT not in captured:
                    raise LabManifestError(
                        f"scenario step {step.id!r} routing metadata requires a "
                        "Project observation"
                    )
                routing_observation_count, observed_tags = _capture_routing_metadata(
                    step=step,
                    step_directory=step_directory,
                    project_uuid=project_uuid,
                    project=captured[Observation.PROJECT],
                    previous_tags=project_tags_by_key.get(project_key, ()),
                    upload_key_permissions=upload_key_permissions,
                    read_client=read_client,
                )
                project_tags_by_key[project_key] = observed_tags
            summary = _step_summary(captured)
            _write_json(step_directory / "summary.json", summary)
            delta = (
                _step_delta(previous_summary, summary)
                if previous_project_key == project_key
                else None
            )
            if delta is not None:
                _write_json(step_directory / "delta.json", delta)
            if step.equivalent_to_step is not None:
                comparison = _step_equivalence(
                    reference_step_id=step.equivalent_to_step,
                    reference_summary=summaries_by_step[step.equivalent_to_step],
                    reference_observations=observations_by_step[
                        step.equivalent_to_step
                    ],
                    candidate_summary=summary,
                    candidate_observations=captured,
                )
                _write_json(step_directory / "equivalence.json", comparison)
                if comparison["equivalent"] is not True:
                    failed_checks = sorted(
                        key
                        for key, value in comparison["checks"].items()
                        if value is not True
                    )
                    raise LabManifestError(
                        f"scenario {scenario.id!r} step {step.id!r} is not "
                        f"equivalent to {step.equivalent_to_step!r}: "
                        + ", ".join(failed_checks)
                    )
            summaries_by_step[step.id] = summary
            observations_by_step[step.id] = captured
            previous_summary = summary
            previous_project_key = project_key
            mutation_observation_count = 0
            if step.analysis_actions:
                if analysis_client is None:
                    raise LabManifestError(
                        f"scenario {scenario.id!r} requires an analysis client"
                    )
                mutation_observation_count = _run_analysis_actions(
                    step=step,
                    step_directory=step_directory,
                    project_uuid=project_uuid,
                    read_client=read_client,
                    analysis_client=analysis_client,
                    timeout=processing_timeout,
                    poll_interval=poll_interval,
                )
            if step.vex_round_trip is not None:
                if analysis_client is None:
                    raise LabManifestError(
                        f"scenario {scenario.id!r} requires an analysis client"
                    )
                mutation_observation_count = _run_vex_round_trip(
                    round_trip=step.vex_round_trip,
                    step_directory=step_directory,
                    project_uuid=project_uuid,
                    read_client=read_client,
                    analysis_client=analysis_client,
                    timeout=processing_timeout,
                    poll_interval=poll_interval,
                )
            if step.vex_targeting_probe is not None:
                if analysis_client is None:
                    raise LabManifestError(
                        f"scenario {scenario.id!r} requires an analysis client"
                    )
                mutation_observation_count = _run_vex_targeting_probe(
                    probe=step.vex_targeting_probe,
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
                    observation_count=(
                        len(captured)
                        + base_observation_count
                        + hierarchy_observation_count
                        + routing_observation_count
                        + mutation_observation_count
                    ),
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
    routing_scenarios = [
        scenario.id
        for scenario in selected
        if any(
            step.project_tags or step.probe_project_properties
            for step in scenario.steps
        )
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
    upload_key_permissions: tuple[str, ...] = ()
    try:
        if routing_scenarios:
            upload_team = upload_client.observe_current_team()
            upload_key_permissions = _team_permission_names(upload_team)
            _write_json(
                run_directory / "upload-key-team.json",
                _observation_dict(upload_team),
            )
        _run_scenario_steps(
            selected=selected,
            manifest_root=manifest_root,
            run_directory=run_directory,
            run_id=run_id,
            upload_client=upload_client,
            read_client=read_client,
            analysis_client=analysis_client,
            upload_key_permissions=upload_key_permissions,
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
