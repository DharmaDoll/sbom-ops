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


class ScenarioStatus(StrEnum):
    IMPLEMENTED = "implemented"
    PLANNED = "planned"


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
class ScenarioStep:
    id: str
    bom: str
    observations: tuple[Observation, ...]
    project_version: str | None = None

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


@dataclass(frozen=True)
class LabManifest:
    schema_version: int
    target: LabTarget
    scenarios: tuple[LabScenario, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 2:
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
