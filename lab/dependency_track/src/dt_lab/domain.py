from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class LabManifestError(ValueError):
    """Raised when a Dependency-Track lab manifest is invalid."""


class LabCleanupError(RuntimeError):
    """Raised when a Dependency-Track lab cleanup cannot complete safely."""


class ScenarioCategory(StrEnum):
    IDENTITY = "identity"
    LIFECYCLE = "lifecycle"
    PORTFOLIO = "portfolio"
    TRIAGE = "triage"
    ROBUSTNESS = "robustness"
    CORPUS = "corpus"


class ScenarioStatus(StrEnum):
    IMPLEMENTED = "implemented"
    PLANNED = "planned"


class CorpusSourceKind(StrEnum):
    RELEASE_ASSET = "release-asset"
    VERIFIED_OCI_ATTESTATION = "verified-oci-attestation"
    DERIVED = "derived"


class Observation(StrEnum):
    PROJECT = "project"
    COMPONENTS = "components"
    DIRECT_COMPONENTS = "direct-components"
    SERVICES = "services"
    DEPENDENCY_GRAPH = "dependency-graph"
    FINDINGS = "findings"
    VULNERABILITIES = "vulnerabilities"
    METRICS = "metrics"
    VIOLATIONS = "violations"
    BOM_EXPORT = "bom-export"
    VEX_EXPORT = "vex-export"


class AnalysisState(StrEnum):
    EXPLOITABLE = "EXPLOITABLE"
    IN_TRIAGE = "IN_TRIAGE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NOT_AFFECTED = "NOT_AFFECTED"
    RESOLVED = "RESOLVED"
    NOT_SET = "NOT_SET"


class AnalysisJustification(StrEnum):
    CODE_NOT_PRESENT = "CODE_NOT_PRESENT"
    CODE_NOT_REACHABLE = "CODE_NOT_REACHABLE"
    REQUIRES_CONFIGURATION = "REQUIRES_CONFIGURATION"
    REQUIRES_DEPENDENCY = "REQUIRES_DEPENDENCY"
    REQUIRES_ENVIRONMENT = "REQUIRES_ENVIRONMENT"
    PROTECTED_BY_COMPILER = "PROTECTED_BY_COMPILER"
    PROTECTED_AT_RUNTIME = "PROTECTED_AT_RUNTIME"
    PROTECTED_AT_PERIMETER = "PROTECTED_AT_PERIMETER"
    PROTECTED_BY_MITIGATING_CONTROL = "PROTECTED_BY_MITIGATING_CONTROL"
    NOT_SET = "NOT_SET"


class AnalysisResponse(StrEnum):
    CAN_NOT_FIX = "CAN_NOT_FIX"
    WILL_NOT_FIX = "WILL_NOT_FIX"
    UPDATE = "UPDATE"
    ROLLBACK = "ROLLBACK"
    WORKAROUND_AVAILABLE = "WORKAROUND_AVAILABLE"
    NOT_SET = "NOT_SET"


@dataclass(frozen=True)
class BomUpload:
    token: str


@dataclass(frozen=True)
class DependencyTrackObservation:
    method: str
    path: str
    query: tuple[tuple[str, str], ...]
    status: int
    headers: tuple[tuple[str, str], ...]
    duration_seconds: float
    payload: Any
    request_payload: Any | None = None


_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _require_slug(value: str, field_name: str) -> None:
    if not _SLUG_PATTERN.fullmatch(value):
        raise LabManifestError(
            f"{field_name} must be a lowercase hyphenated identifier: {value!r}"
        )


@dataclass(frozen=True)
class LabTarget:
    dependency_track_version: str
    cyclonedx_versions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.dependency_track_version.strip():
            raise LabManifestError("target.dependency_track_version is required")
        if not self.cyclonedx_versions:
            raise LabManifestError("target.cyclonedx_versions must not be empty")


@dataclass(frozen=True)
class CorpusArtifact:
    id: str
    ecosystem: str
    source_kind: CorpusSourceKind
    source: str
    release: str
    license: str
    integrity: str
    sha256: str
    local_path: str
    cyclonedx_version: str
    project_name: str
    project_version: str
    purpose: str
    hypotheses: tuple[str, ...]
    decision_questions: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_slug(self.id, "corpus artifact id")
        required_values = {
            "ecosystem": self.ecosystem,
            "source": self.source,
            "release": self.release,
            "license": self.license,
            "integrity": self.integrity,
            "local_path": self.local_path,
            "cyclonedx_version": self.cyclonedx_version,
            "project_name": self.project_name,
            "project_version": self.project_version,
            "purpose": self.purpose,
        }
        for field_name, value in required_values.items():
            if not value.strip():
                raise LabManifestError(
                    f"corpus artifact {self.id!r} requires {field_name}"
                )
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise LabManifestError(
                f"corpus artifact {self.id!r} requires a lowercase SHA-256"
            )
        local_path_parts = self.local_path.replace("\\", "/").split("/")
        if self.local_path.startswith(("/", "\\")) or ".." in local_path_parts:
            raise LabManifestError(
                f"corpus artifact {self.id!r} local_path must stay below the "
                "artifact directory"
            )
        if not self.project_name.startswith("dt-lab-"):
            raise LabManifestError(
                f"corpus artifact {self.id!r} Project name must start with 'dt-lab-'"
            )
        if not self.hypotheses or any(
            not hypothesis.strip() for hypothesis in self.hypotheses
        ):
            raise LabManifestError(f"corpus artifact {self.id!r} requires hypotheses")
        if not self.decision_questions or any(
            not question.strip() for question in self.decision_questions
        ):
            raise LabManifestError(
                f"corpus artifact {self.id!r} requires decision questions"
            )


@dataclass(frozen=True)
class CorpusCatalog:
    schema_version: int
    target: LabTarget
    artifacts: tuple[CorpusArtifact, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise LabManifestError(
                f"unsupported corpus catalog schema version: {self.schema_version}"
            )
        if not self.artifacts:
            raise LabManifestError("corpus catalog requires at least one artifact")
        artifact_ids = [artifact.id for artifact in self.artifacts]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise LabManifestError("corpus catalog has duplicate artifact ids")


@dataclass(frozen=True)
class CorpusArtifactInspection:
    artifact_id: str
    path: str
    byte_count: int
    component_count: int
    dependency_count: int
    service_count: int
    vulnerability_count: int


@dataclass(frozen=True)
class AnalysisAction:
    id: str
    component_purl: str
    vulnerability_id: str
    vulnerability_source: str
    state: AnalysisState
    justification: AnalysisJustification
    response: AnalysisResponse
    detail: str
    comment: str
    suppressed: bool

    def __post_init__(self) -> None:
        _require_slug(self.id, "analysis action id")
        required_values = {
            "component_purl": self.component_purl,
            "vulnerability_id": self.vulnerability_id,
            "vulnerability_source": self.vulnerability_source,
            "detail": self.detail,
            "comment": self.comment,
        }
        for field_name, value in required_values.items():
            if not value.strip():
                raise LabManifestError(
                    f"analysis action {self.id!r} requires {field_name}"
                )
        if not isinstance(self.suppressed, bool):
            raise LabManifestError(
                f"analysis action {self.id!r} suppressed must be a boolean"
            )


@dataclass(frozen=True)
class ScenarioStep:
    id: str
    bom: str
    observations: tuple[Observation, ...]
    project_version: str | None = None
    analysis_actions: tuple[AnalysisAction, ...] = ()

    def __post_init__(self) -> None:
        _require_slug(self.id, "scenario step id")
        if not self.bom.strip():
            raise LabManifestError(f"scenario step {self.id!r} requires a BOM path")
        if not self.observations:
            raise LabManifestError(
                f"scenario step {self.id!r} requires at least one observation"
            )
        if self.project_version is not None and not self.project_version.strip():
            raise LabManifestError(
                f"scenario step {self.id!r} project_version must not be empty"
            )
        action_ids = [action.id for action in self.analysis_actions]
        if len(action_ids) != len(set(action_ids)):
            raise LabManifestError(
                f"scenario step {self.id!r} has duplicate analysis action ids"
            )


@dataclass(frozen=True)
class LabScenario:
    id: str
    category: ScenarioCategory
    status: ScenarioStatus
    purpose: str
    project_name: str
    project_version: str
    hypotheses: tuple[str, ...]
    decision_questions: tuple[str, ...]
    steps: tuple[ScenarioStep, ...] = ()

    def __post_init__(self) -> None:
        _require_slug(self.id, "scenario id")
        if not self.purpose.strip():
            raise LabManifestError(f"scenario {self.id!r} requires a purpose")
        if not self.project_name.strip() or not self.project_version.strip():
            raise LabManifestError(
                f"scenario {self.id!r} requires project name and version"
            )
        if not self.project_name.startswith("dt-lab-"):
            raise LabManifestError(
                f"scenario {self.id!r} Project name must start with 'dt-lab-'"
            )
        if not self.hypotheses:
            raise LabManifestError(
                f"scenario {self.id!r} requires at least one hypothesis"
            )
        if any(not hypothesis.strip() for hypothesis in self.hypotheses):
            raise LabManifestError(
                f"scenario {self.id!r} hypotheses must not contain empty values"
            )
        if not self.decision_questions:
            raise LabManifestError(
                f"scenario {self.id!r} requires at least one decision question"
            )
        if any(not question.strip() for question in self.decision_questions):
            raise LabManifestError(
                f"scenario {self.id!r} decision questions must not contain empty values"
            )
        if self.status is ScenarioStatus.IMPLEMENTED and not self.steps:
            raise LabManifestError(
                f"implemented scenario {self.id!r} requires at least one step"
            )
        step_ids = [step.id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise LabManifestError(f"scenario {self.id!r} has duplicate step ids")
        if self.category is not ScenarioCategory.TRIAGE and any(
            step.analysis_actions for step in self.steps
        ):
            raise LabManifestError(
                f"scenario {self.id!r} analysis actions require triage category"
            )


@dataclass(frozen=True)
class LabManifest:
    schema_version: int
    target: LabTarget
    scenarios: tuple[LabScenario, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 3:
            raise LabManifestError(
                f"unsupported lab manifest schema version: {self.schema_version}"
            )
        if not self.scenarios:
            raise LabManifestError("lab manifest requires at least one scenario")
        scenario_ids = [scenario.id for scenario in self.scenarios]
        if len(scenario_ids) != len(set(scenario_ids)):
            raise LabManifestError("lab manifest has duplicate scenario ids")


@dataclass(frozen=True)
class OpenApiOperation:
    method: str
    path: str
    operation_id: str | None
    tags: tuple[str, ...]
    summary: str | None
    permissions: tuple[str, ...]
    query_parameters: tuple[str, ...]
    response_statuses: tuple[str, ...]
    response_headers: tuple[str, ...]
    response_media_types: tuple[str, ...]
    deprecated: bool


@dataclass(frozen=True)
class OpenApiInventory:
    title: str | None
    api_version: str | None
    openapi_version: str | None
    contract_sha256: str
    path_count: int
    operation_count: int
    tag_count: int
    selected_tags: tuple[str, ...]
    operations: tuple[OpenApiOperation, ...]


@dataclass(frozen=True)
class LabStepResult:
    scenario_id: str
    step_id: str
    project_uuid: str
    snapshot_directory: str
    observation_count: int


@dataclass(frozen=True)
class LabProjectRecord:
    scenario_id: str
    step_id: str
    project_name: str
    project_version: str
    project_uuid: str | None = None


@dataclass(frozen=True)
class LabCleanupTarget:
    project_name: str
    project_version: str
    project_uuid: str | None


@dataclass(frozen=True)
class LabCleanupResult:
    run_id: str
    cleanup_id: str
    executed: bool
    audit_path: str
    targets: tuple[LabCleanupTarget, ...]
    deleted_project_uuids: tuple[str, ...]
    already_absent_projects: tuple[str, ...]


@dataclass(frozen=True)
class LabRunResult:
    run_id: str
    output_directory: str
    steps: tuple[LabStepResult, ...]
