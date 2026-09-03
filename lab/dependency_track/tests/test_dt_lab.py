from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from dt_lab.cli import main
from dt_lab.domain import (
    AnalysisAction,
    AnalysisJustification,
    AnalysisResponse,
    AnalysisState,
    BomUpload,
    BomUploadAttempt,
    DependencyTrackObservation,
    LabManifestError,
    Observation,
    ScenarioStatus,
    ScenarioStep,
    VexUpload,
)
from dt_lab.service import (
    build_corpus_lab_manifest,
    build_openapi_inventory,
    inspect_corpus_catalog,
    load_corpus_catalog,
    load_lab_manifest,
    openapi_inventory_dict,
    run_lab_scenarios,
)

LAB_ROOT = Path(__file__).parents[1]
MANIFEST_PATH = LAB_ROOT / "scenarios" / "scenarios.yaml"
OPENAPI_FIXTURE = LAB_ROOT / "fixtures" / "dependency-track-openapi.json"
CORPUS_CATALOG = LAB_ROOT / "corpus" / "corpus.yaml"


def _write_test_corpus(tmp_path: Path) -> tuple[Path, Path]:
    artifact_directory = tmp_path / "artifacts"
    artifact_directory.mkdir()
    artifact = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:b41242d9-27d4-4e4f-ac6f-9de83039f3c2",
        "version": 1,
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:pypi/example@1.0.0",
                "name": "example",
                "version": "1.0.0",
                "purl": "pkg:pypi/example@1.0.0",
            }
        ],
        "dependencies": [{"ref": "pkg:pypi/example@1.0.0", "dependsOn": []}],
    }
    artifact_bytes = json.dumps(artifact).encode()
    artifact_path = artifact_directory / "python" / "sbom.cdx.json"
    artifact_path.parent.mkdir()
    artifact_path.write_bytes(artifact_bytes)
    catalog_path = tmp_path / "corpus.yaml"
    catalog_path.write_text(
        f"""
schema_version: 1
target:
  dependency_track_version: 4.14.3
  cyclonedx_versions: ["1.6"]
artifacts:
  - id: python-example-1-0-0
    ecosystem: Python
    source_kind: release-asset
    source: https://example.invalid/sbom.cdx.json
    release: 1.0.0
    license: Apache-2.0
    integrity: Test fixture hash.
    sha256: {hashlib.sha256(artifact_bytes).hexdigest()}
    local_path: python/sbom.cdx.json
    cyclonedx_version: "1.6"
    project:
      name: dt-lab-corpus-python-example
      version: 1.0.0-cdx-1.6
    purpose: Exercise a real-world-shaped Python input.
    hypotheses: [Dependency-Track retains its PURL.]
    decision_questions: ["Which inventory fields survive ingestion?"]
""".strip(),
        encoding="utf-8",
    )
    return catalog_path, artifact_directory


def test_repository_lab_manifest_is_valid() -> None:
    manifest = load_lab_manifest(MANIFEST_PATH)

    assert manifest.target.dependency_track_version == "4.14.3"
    assert len(manifest.scenarios) == 18
    assert all(scenario.hypotheses for scenario in manifest.scenarios)
    assert all(scenario.decision_questions for scenario in manifest.scenarios)
    implemented = [
        scenario
        for scenario in manifest.scenarios
        if scenario.status is ScenarioStatus.IMPLEMENTED
    ]
    assert [scenario.id for scenario in implemented] == [
        "lifecycle-vulnerable-to-updated",
        "identity-same-name-different-purl",
        "identity-missing-purl",
        "identity-duplicate-dependency-paths",
        "lifecycle-add-remove-components",
        "lifecycle-project-versions",
        "portfolio-parent-child",
        "portfolio-tags-properties",
        "portfolio-direct-transitive-graph",
        "triage-multiple-sources-aliases",
        "triage-analysis-states",
        "triage-delegation-boundary",
        "triage-vex-round-trip",
        "triage-vex-targeting",
        "robustness-invalid-cyclonedx",
        "robustness-json-xml-equivalence",
    ]
    assert sum(len(scenario.steps) for scenario in implemented) == 22
    format_scenario = implemented[-1]
    assert format_scenario.steps[1].equivalent_to_step == "json"


def test_analysis_action_sequence_requires_a_safe_final_state() -> None:
    unsafe_action = AnalysisAction(
        id="leave-in-triage",
        component_purl="pkg:maven/example/component@1.0.0",
        vulnerability_id="CVE-2099-0001",
        vulnerability_source="NVD",
        state=AnalysisState.IN_TRIAGE,
        justification=AnalysisJustification.NOT_SET,
        response=AnalysisResponse.NOT_SET,
        detail="Synthetic unsafe final state.",
        comment="Synthetic unsafe final action.",
        suppressed=False,
    )

    with pytest.raises(LabManifestError, match="unsuppressed NOT_SET"):
        ScenarioStep(
            id="unsafe-sequence",
            bom="sboms/example.cdx.json",
            observations=(Observation.FINDINGS,),
            analysis_actions=(unsafe_action,),
        )


def test_repository_real_world_corpus_catalog_is_valid() -> None:
    catalog = load_corpus_catalog(CORPUS_CATALOG)

    assert catalog.target.dependency_track_version == "4.14.3"
    assert catalog.target.cyclonedx_versions == ("1.6", "1.7")
    assert [artifact.id for artifact in catalog.artifacts] == [
        "go-otel-obi-0-12-2",
        "typescript-n8n-2-36-8",
        "rails-openproject-17-7-2",
        "rails-openproject-17-7-2-schema-valid",
        "python-airflow-3-3-0-cdx-1-7",
        "python-airflow-3-3-0-cdx-1-6",
    ]


def test_real_world_corpus_inspection_and_manifest_are_hash_bound(
    tmp_path: Path,
) -> None:
    catalog_path, artifact_directory = _write_test_corpus(tmp_path)
    catalog = load_corpus_catalog(catalog_path)

    inspections = inspect_corpus_catalog(catalog, artifact_directory)
    manifest = build_corpus_lab_manifest(
        catalog, artifact_directory, ("python-example-1-0-0",)
    )

    assert inspections[0].component_count == 1
    assert inspections[0].dependency_count == 1
    assert manifest.scenarios[0].category.value == "corpus"
    assert manifest.scenarios[0].steps[0].bom == inspections[0].path
    assert manifest.scenarios[0].steps[0].observations[-1].value == "bom-export"

    artifact_path = artifact_directory / "python" / "sbom.cdx.json"
    artifact_path.write_text("{}", encoding="utf-8")
    with pytest.raises(LabManifestError, match="SHA-256 mismatch"):
        inspect_corpus_catalog(catalog, artifact_directory)


def test_real_world_corpus_requires_explicit_known_artifacts(tmp_path: Path) -> None:
    catalog_path, artifact_directory = _write_test_corpus(tmp_path)
    catalog = load_corpus_catalog(catalog_path)

    with pytest.raises(LabManifestError, match="require explicit artifact IDs"):
        build_corpus_lab_manifest(catalog, artifact_directory, ())
    with pytest.raises(LabManifestError, match="unknown corpus artifacts"):
        build_corpus_lab_manifest(catalog, artifact_directory, ("unknown",))


def test_lab_cli_validates_local_real_world_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    catalog_path, artifact_directory = _write_test_corpus(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "dt-lab",
            "validate-corpus",
            "--catalog",
            str(catalog_path),
            "--artifact-dir",
            str(artifact_directory),
            "--require-local",
        ],
    )

    assert main() == 0
    output = capsys.readouterr().out
    assert "artifacts=1" in output
    assert "components=1" in output


def test_lab_manifest_rejects_missing_implemented_bom(tmp_path: Path) -> None:
    manifest_path = tmp_path / "scenarios.yaml"
    manifest_path.write_text(
        """
schema_version: 3
target:
  dependency_track_version: 4.14.3
  cyclonedx_versions: ["1.5"]
scenarios:
  - id: missing-bom
    category: robustness
    status: implemented
    purpose: Reject missing scenario files.
    hypotheses: [A referenced BOM must exist.]
    decision_questions: ["Does manifest validation fail before execution?"]
    project: {name: dt-lab-missing, version: 1.0.0}
    steps:
      - id: upload
        bom: absent.cdx.json
        observe: [project]
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(LabManifestError, match="BOM does not exist"):
        load_lab_manifest(manifest_path)


def test_lab_manifest_rejects_unknown_dependency_reference(tmp_path: Path) -> None:
    (tmp_path / "invalid.cdx.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "serialNumber": "urn:uuid:5ada1c0d-5249-40f0-aeea-20ebc9ba6a75",
                "version": 1,
                "metadata": {
                    "component": {
                        "type": "application",
                        "bom-ref": "root",
                        "name": "root",
                        "version": "1",
                    }
                },
                "components": [],
                "dependencies": [{"ref": "root", "dependsOn": ["missing"]}],
            }
        ),
        encoding="utf-8",
    )
    manifest_path = tmp_path / "scenarios.yaml"
    manifest_path.write_text(
        """
schema_version: 3
target:
  dependency_track_version: 4.14.3
  cyclonedx_versions: ["1.5"]
scenarios:
  - id: invalid-graph
    category: robustness
    status: implemented
    purpose: Reject an invalid dependency graph.
    hypotheses: [Unknown dependency references are invalid.]
    decision_questions: ["Does validation reject the invalid graph?"]
    project: {name: dt-lab-invalid, version: 1.0.0}
    steps:
      - id: upload
        bom: invalid.cdx.json
        observe: [project]
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(LabManifestError, match="unknown dependency references"):
        load_lab_manifest(manifest_path)


def test_lab_manifest_validates_xml_dependency_references(tmp_path: Path) -> None:
    (tmp_path / "invalid.cdx.xml").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5"
     serialNumber="urn:uuid:8791a04b-d3b2-4bc4-9215-72570cce0686"
     version="1">
  <metadata>
    <component type="application" bom-ref="root">
      <name>root</name>
      <version>1</version>
    </component>
  </metadata>
  <dependencies>
    <dependency ref="root"><dependency ref="missing"/></dependency>
  </dependencies>
</bom>
""",
        encoding="utf-8",
    )
    manifest_path = tmp_path / "scenarios.yaml"
    manifest_path.write_text(
        """
schema_version: 3
target:
  dependency_track_version: 4.14.3
  cyclonedx_versions: ["1.5"]
scenarios:
  - id: invalid-xml-graph
    category: robustness
    status: implemented
    purpose: Reject an invalid XML dependency graph.
    hypotheses: [Unknown XML dependency references are invalid.]
    decision_questions: ["Does validation reject the invalid XML graph?"]
    project: {name: dt-lab-invalid-xml, version: 1.0.0}
    steps:
      - id: upload
        bom: invalid.cdx.xml
        observe: [project]
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(LabManifestError, match="unknown dependency references"):
        load_lab_manifest(manifest_path)


def test_openapi_inventory_extracts_contract_details() -> None:
    payload = json.loads(OPENAPI_FIXTURE.read_text(encoding="utf-8"))

    inventory = build_openapi_inventory(payload)
    rendered = openapi_inventory_dict(inventory)

    assert inventory.path_count == 13
    assert inventory.operation_count == 14
    assert inventory.tag_count == 9
    assert len(inventory.operations) == 13
    finding = next(
        operation
        for operation in inventory.operations
        if operation.tags == ("finding",)
    )
    assert finding.method == "GET"
    assert finding.path == "/v1/finding/project/{uuid}"
    assert finding.permissions == ("VIEW_VULNERABILITY",)
    assert finding.query_parameters == ("source", "suppressed")
    assert finding.response_statuses == ("200", "403")
    assert finding.response_headers == ("X-Total-Count",)
    assert finding.response_media_types == (
        "application/json",
        "application/sarif+json",
    )
    components = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "getAllComponents"
    )
    assert components.permissions == ("VIEW_PORTFOLIO",)
    assert components.query_parameters == (
        "limit",
        "offset",
        "onlyDirect",
        "onlyOutdated",
        "pageNumber",
        "pageSize",
        "sortName",
        "sortOrder",
    )
    assert components.response_headers == ("X-Total-Count",)
    assert components.response_statuses == ("200", "401", "403", "404")
    deletion = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "deleteProject"
    )
    assert deletion.method == "DELETE"
    assert deletion.path == "/v1/project/{uuid}"
    assert deletion.permissions == ("PORTFOLIO_MANAGEMENT",)
    assert deletion.response_statuses == ("204", "401", "403", "404")
    lookup = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "lookupProject"
    )
    assert lookup.permissions == ("VIEW_PORTFOLIO",)
    assert lookup.query_parameters == ("name", "version")
    children = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "getChildrenProjects"
    )
    assert children.permissions == ("VIEW_PORTFOLIO",)
    assert children.query_parameters == (
        "excludeInactive",
        "limit",
        "offset",
        "pageNumber",
        "pageSize",
        "sortName",
        "sortOrder",
    )
    assert children.response_headers == ("X-Total-Count",)
    assert children.response_statuses == ("200", "401", "403", "404")
    tagged_projects = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "getProjectsByTag"
    )
    assert tagged_projects.permissions == ("VIEW_PORTFOLIO",)
    assert tagged_projects.query_parameters == (
        "excludeInactive",
        "limit",
        "offset",
        "onlyRoot",
        "pageNumber",
        "pageSize",
        "sortName",
        "sortOrder",
    )
    assert tagged_projects.response_headers == ("X-Total-Count",)
    project_properties = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "getProperties_1"
    )
    assert project_properties.permissions == ("PORTFOLIO_MANAGEMENT",)
    assert project_properties.response_statuses == ("200", "401", "403", "404")
    bom_upload = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "UploadBom"
    )
    assert bom_upload.permissions == ("BOM_UPLOAD",)
    assert bom_upload.response_media_types == (
        "application/json",
        "application/problem+json",
    )
    retrieve_analysis = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "retrieveAnalysis"
    )
    assert retrieve_analysis.permissions == ("VIEW_VULNERABILITY",)
    assert retrieve_analysis.query_parameters == (
        "component",
        "project",
        "vulnerability",
    )
    update_analysis = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "updateAnalysis"
    )
    assert update_analysis.permissions == ("VULNERABILITY_ANALYSIS",)
    assert update_analysis.response_statuses == ("200", "401", "404")
    team_self = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "getSelf"
    )
    assert team_self.path == "/v1/team/self"
    assert team_self.response_statuses == ("200", "400", "401", "404")
    vex_upload = next(
        operation
        for operation in inventory.operations
        if operation.operation_id == "uploadVex_1"
    )
    assert vex_upload.method == "POST"
    assert vex_upload.path == "/v1/vex"
    assert vex_upload.permissions == ("VULNERABILITY_ANALYSIS",)
    assert vex_upload.response_statuses == ("200", "400", "401", "403", "404")
    assert rendered["summary"]["selected_operation_count"] == 13
    assert len(rendered["source"]["contract_sha256"]) == 64


def test_lab_manifest_requires_cleanup_safe_project_prefix(tmp_path: Path) -> None:
    manifest_path = tmp_path / "scenarios.yaml"
    manifest_path.write_text(
        """
schema_version: 3
target:
  dependency_track_version: 4.14.3
  cyclonedx_versions: ["1.5"]
scenarios:
  - id: unsafe-project
    category: robustness
    status: planned
    purpose: Reject a Project outside the lab namespace.
    hypotheses: [Every scenario must use the lab Project namespace.]
    decision_questions: ["Does validation reject an unsafe Project name?"]
    project: {name: production-service, version: 1.0.0}
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(LabManifestError, match="must start with 'dt-lab-'"):
        load_lab_manifest(manifest_path)


def test_lab_manifest_requires_hypotheses_and_decision_questions(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "scenarios.yaml"
    manifest_path.write_text(
        """
schema_version: 3
target:
  dependency_track_version: 4.14.3
  cyclonedx_versions: ["1.5"]
scenarios:
  - id: missing-decision-context
    category: triage
    status: planned
    purpose: Reject an experiment without decision context.
    project: {name: dt-lab-missing-context, version: 1.0.0}
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(LabManifestError, match="hypotheses must be a list"):
        load_lab_manifest(manifest_path)


def test_openapi_inventory_can_include_all_tags() -> None:
    payload = json.loads(OPENAPI_FIXTURE.read_text(encoding="utf-8"))

    inventory = build_openapi_inventory(payload, selected_tags=None)

    assert len(inventory.operations) == 14
    assert inventory.selected_tags == (
        "analysis",
        "bom",
        "component",
        "finding",
        "project",
        "projectProperty",
        "team",
        "user",
        "vex",
    )


def test_lab_cli_validates_repository_manifest(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "dt-lab",
            "validate-manifest",
            "--manifest",
            str(MANIFEST_PATH),
        ],
    )

    assert main() == 0
    assert "scenarios=18 implemented=16 planned=2 steps=22" in capsys.readouterr().out


def test_lab_cli_writes_openapi_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_path = tmp_path / "inventory.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "dt-lab",
            "openapi-inventory",
            str(OPENAPI_FIXTURE),
            "--output",
            str(output_path),
        ],
    )

    assert main() == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["summary"] == {
        "operation_count": 14,
        "path_count": 13,
        "selected_operation_count": 13,
        "selected_tags": [
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
        ],
        "tag_count": 9,
    }
    assert "OpenAPI inventory: paths=13 operations=14 selected=13 tags=9" in (
        capsys.readouterr().out
    )


def test_lab_cli_reuses_read_key_for_analysis_mutation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example")
    monkeypatch.setenv("SBOM_OPS_SBOM_UPLOAD_API_KEY", "upload-key")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "read-key")
    monkeypatch.delenv("SBOM_OPS_DT_ANALYSIS_API_KEY", raising=False)
    client_keys: list[str] = []

    def fake_client(api_key: str) -> object:
        client_keys.append(api_key)
        return object()

    monkeypatch.setattr("dt_lab.cli._dependency_track_client", fake_client)
    monkeypatch.setattr(
        "dt_lab.cli.run_lab_scenarios",
        lambda *args, **kwargs: SimpleNamespace(
            run_id="run-1", steps=(), output_directory="runs/run-1"
        ),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "dt-lab",
            "run-scenarios",
            "--manifest",
            str(MANIFEST_PATH),
            "--scenario",
            "triage-analysis-states",
            "--allow-analysis-mutation",
        ],
    )

    assert main() == 0
    assert client_keys == ["upload-key", "read-key", "read-key"]
    assert "DT lab run completed" in capsys.readouterr().out


def test_lab_cli_prefers_dedicated_analysis_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SBOM_OPS_DT_BASE_URL", "https://dtrack.example")
    monkeypatch.setenv("SBOM_OPS_SBOM_UPLOAD_API_KEY", "upload-key")
    monkeypatch.setenv("SBOM_OPS_DT_API_KEY", "read-key")
    monkeypatch.setenv("SBOM_OPS_DT_ANALYSIS_API_KEY", "analysis-key")
    client_keys: list[str] = []

    def fake_client(api_key: str) -> object:
        client_keys.append(api_key)
        return object()

    monkeypatch.setattr("dt_lab.cli._dependency_track_client", fake_client)
    monkeypatch.setattr(
        "dt_lab.cli.run_lab_scenarios",
        lambda *args, **kwargs: SimpleNamespace(
            run_id="run-1", steps=(), output_directory="runs/run-1"
        ),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "dt-lab",
            "run-scenarios",
            "--manifest",
            str(MANIFEST_PATH),
            "--scenario",
            "triage-analysis-states",
            "--allow-analysis-mutation",
        ],
    )

    assert main() == 0
    assert client_keys == ["upload-key", "read-key", "analysis-key"]


def test_lab_cli_cleanup_defaults_to_a_local_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_id = "25dfd88e-2673-462b-9f40-818279ecd8b5"
    run_directory = tmp_path / run_id
    run_directory.mkdir()
    (run_directory / "run.json").write_text(
        json.dumps({"run_id": run_id, "status": "completed"}), encoding="utf-8"
    )
    (run_directory / "projects.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": run_id,
                "projects": [
                    {
                        "scenario_id": "identity",
                        "step_id": "initial",
                        "project_name": "dt-lab-example",
                        "project_version": "1.0.0-lab-25dfd88e",
                        "project_uuid": "4c40cf70-57cf-4eee-8043-1f246fef3f7b",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "dt-lab",
            "cleanup-run",
            "--run-id",
            run_id,
            "--output-dir",
            str(tmp_path),
        ],
    )

    assert main() == 0
    assert "DT lab cleanup plan" in capsys.readouterr().out

    monkeypatch.delenv("SBOM_OPS_DT_CLEANUP_API_KEY", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        [
            "dt-lab",
            "cleanup-run",
            "--run-id",
            run_id,
            "--output-dir",
            str(tmp_path),
            "--execute",
        ],
    )

    assert main() == 2
    assert "--execute requires SBOM_OPS_DT_CLEANUP_API_KEY" in (capsys.readouterr().err)


class FakeLabClient:
    def __init__(self) -> None:
        self.last_bom = ""
        self.project_versions: list[str] = []
        self.analysis_state = "NOT_SET"
        self.analysis_suppressed = False
        self.analysis_justification = "NOT_SET"
        self.analysis_response = "NOT_SET"
        self.analysis_detail = ""
        self.analysis_comments: list[dict[str, object]] = []
        self.project_uuids: dict[tuple[str, str], str] = {}
        self.project_parents: dict[str, str] = {}
        self.project_tags: dict[str, tuple[str, ...]] = {}
        self.last_project_name = ""
        self.last_project_version = ""

    def upload_bom_by_project_coordinates(
        self,
        project_name: str,
        project_version: str,
        bom_path: str | Path,
        *,
        parent_project_uuid: str | None = None,
        project_tags: tuple[str, ...] = (),
    ) -> BomUpload:
        self.last_bom = Path(bom_path).name
        self.project_versions.append(project_version)
        self.last_project_name = project_name
        self.last_project_version = project_version
        project_key = (project_name, project_version)
        project_created = project_key not in self.project_uuids
        if project_created:
            self.project_uuids[project_key] = f"project-{len(self.project_uuids) + 1}"
            self.project_tags[self.project_uuids[project_key]] = project_tags
        if parent_project_uuid is not None:
            self.project_parents[self.project_uuids[project_key]] = parent_project_uuid
        return BomUpload(token=f"token-{self.last_bom}")

    def attempt_bom_upload_by_project_coordinates(
        self,
        project_name: str,
        project_version: str,
        bom_path: str | Path,
        *,
        parent_project_uuid: str | None = None,
        project_tags: tuple[str, ...] = (),
    ) -> BomUploadAttempt:
        upload = self.upload_bom_by_project_coordinates(
            project_name,
            project_version,
            bom_path,
            parent_project_uuid=parent_project_uuid,
            project_tags=project_tags,
        )
        return BomUploadAttempt(
            upload=upload,
            observation=DependencyTrackObservation(
                method="POST",
                path="/api/v1/bom",
                query=(),
                status=200,
                headers=(("Content-Type", "application/json"),),
                duration_seconds=0.01,
                payload={"token": upload.token},
                request_payload={
                    "autoCreate": True,
                    "projectName": project_name,
                    "projectVersion": project_version,
                    "projectTags": list(project_tags),
                },
            ),
        )

    def upload_vex_for_project(
        self, project_uuid: str, vex_path: str | Path
    ) -> VexUpload:
        payload = json.loads(Path(vex_path).read_text(encoding="utf-8"))
        vulnerability = next(
            item
            for item in payload["vulnerabilities"]
            if item["id"] == "CVE-2021-44228"
        )
        analysis = vulnerability["analysis"]
        imported_state = str(analysis["state"]).upper()
        imported_justification = str(analysis.get("justification", "not_set")).upper()
        responses = analysis.get("response", [])
        imported_response = str(responses[0]).upper() if responses else "NOT_SET"
        imported_detail = str(analysis.get("detail", ""))
        changes = (
            self.analysis_state != imported_state,
            self.analysis_justification != imported_justification,
            self.analysis_detail != imported_detail,
        )
        self.analysis_state = imported_state
        self.analysis_justification = imported_justification
        self.analysis_response = imported_response
        self.analysis_detail = imported_detail
        self.analysis_suppressed = self.analysis_state == "NOT_AFFECTED"
        comments = (
            f"Analysis imported as {self.analysis_state}",
            f"Justification imported as {self.analysis_justification}",
            f"Details imported as {self.analysis_detail}",
        )
        for changed, comment in zip(changes, comments, strict=True):
            if changed:
                self.analysis_comments.append(
                    {
                        "timestamp": len(self.analysis_comments) + 1,
                        "comment": comment,
                        "commenter": "CycloneDX VEX",
                    }
                )
        return VexUpload(token="vex-token-1")

    def wait_for_bom_processing(
        self,
        token: str,
        *,
        timeout: float = 120.0,
        poll_interval: float = 5.0,
    ) -> None:
        return None

    def _observation(self, path: str, payload: object) -> DependencyTrackObservation:
        return DependencyTrackObservation(
            method="GET",
            path=path,
            query=(),
            status=200,
            headers=(("Content-Type", "application/json"),),
            duration_seconds=0.01,
            payload=payload,
        )

    def observe_project_lookup(
        self, project_name: str, project_version: str
    ) -> DependencyTrackObservation:
        project_key = (project_name, project_version)
        if project_key not in self.project_uuids:
            self.project_uuids[project_key] = f"project-{len(self.project_uuids) + 1}"
        project_uuid = self.project_uuids[project_key]
        payload: dict[str, object] = {
            "uuid": project_uuid,
            "name": project_name,
            "version": project_version,
        }
        if project_uuid in self.project_parents:
            payload["parent"] = {"uuid": self.project_parents[project_uuid]}
        return self._observation(
            "/api/v1/project/lookup",
            payload,
        )

    def observe_project_lookup_if_present(
        self, project_name: str, project_version: str
    ) -> DependencyTrackObservation:
        return self.observe_project_lookup(project_name, project_version)

    def observe_current_team(self) -> DependencyTrackObservation:
        return self._observation(
            "/api/v1/team/self",
            {
                "uuid": "analysis-team-1",
                "name": "dt-lab-analysis",
                "permissions": [
                    {"name": "VIEW_BADGES"},
                    {"name": "VIEW_POLICY_VIOLATION"},
                    {"name": "VIEW_PORTFOLIO"},
                    {"name": "VIEW_VULNERABILITY"},
                    {"name": "VULNERABILITY_ANALYSIS"},
                ],
            },
        )

    def observe_project(self, project_uuid: str) -> DependencyTrackObservation:
        coordinates = next(
            (
                key
                for key, observed_uuid in self.project_uuids.items()
                if observed_uuid == project_uuid
            ),
            None,
        )
        payload: dict[str, object] = {
            "uuid": project_uuid,
            "collectionLogic": "NONE",
            "lastInheritedRiskScore": 0.0,
        }
        if coordinates is not None:
            payload["name"], payload["version"] = coordinates
        if project_uuid in self.project_parents:
            payload["parent"] = {"uuid": self.project_parents[project_uuid]}
        payload["tags"] = [
            {"name": tag} for tag in self.project_tags.get(project_uuid, ())
        ]
        return self._observation(f"/api/v1/project/{project_uuid}", payload)

    def observe_project_children(self, project_uuid: str) -> DependencyTrackObservation:
        children = [
            self.observe_project(child_uuid).payload
            for child_uuid, parent_uuid in self.project_parents.items()
            if parent_uuid == project_uuid
        ]
        return self._observation(f"/api/v1/project/{project_uuid}/children", children)

    def observe_projects_by_tag(self, tag: str) -> DependencyTrackObservation:
        projects = [
            self.observe_project(project_uuid).payload
            for project_uuid, tags in self.project_tags.items()
            if tag in tags
        ]
        return self._observation(f"/api/v1/project/tag/{tag}", projects)

    def attempt_observe_project_properties(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return DependencyTrackObservation(
            method="GET",
            path=f"/api/v1/project/{project_uuid}/property",
            query=(),
            status=403,
            headers=(("Content-Type", "application/json"),),
            duration_seconds=0.01,
            payload={"status": 403},
        )

    def observe_project_components(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        retained = {
            "uuid": "component-retained",
            "name": "log4j-core",
            "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        }
        if self.last_bom.endswith("initial.cdx.json"):
            changed = {
                "uuid": "component-removed",
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20",
            }
        else:
            changed = {
                "uuid": "component-added",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            }
        return self._observation(
            f"/api/v1/component/project/{project_uuid}", [retained, changed]
        )

    def observe_project_direct_components(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return self._observation(
            f"/api/v1/component/project/{project_uuid}",
            [{"uuid": "direct-1", "name": "direct"}],
        )

    def observe_project_services(self, project_uuid: str) -> DependencyTrackObservation:
        return self._observation(
            f"/api/v1/service/project/{project_uuid}",
            [{"uuid": "service-1", "name": "service"}],
        )

    def observe_project_dependency_graph(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return self._observation(
            f"/api/v1/dependencyGraph/project/{project_uuid}/directDependencies", []
        )

    def observe_project_findings(
        self, project_uuid: str, *, suppressed: bool = False
    ) -> DependencyTrackObservation:
        findings = []
        if self.last_bom == "triage-multiple-sources-aliases.cdx.json":
            findings = [
                {
                    "uuid": "finding-1",
                    "component": {
                        "uuid": "component-1",
                        "name": "lodash",
                        "version": "4.17.20",
                        "purl": "pkg:npm/lodash@4.17.20",
                    },
                    "vulnerability": {
                        "uuid": "vulnerability-1",
                        "vulnId": "GHSA-35jh-r3h4-6jhm",
                        "source": "GITHUB",
                        "aliases": [
                            {
                                "uuid": "alias-1",
                                "cveId": "CVE-2021-23337",
                                "ghsaId": "GHSA-35jh-r3h4-6jhm",
                            }
                        ],
                        "severity": "HIGH",
                        "epssScore": 0.42,
                        "epssPercentile": 0.91,
                        "cvssV3BaseScore": 7.2,
                    },
                    "analysis": {"state": "NOT_SET", "isSuppressed": False},
                }
            ]
        elif self.last_bom in {
            "triage-analysis-states.cdx.json",
            "triage-delegation-boundary.cdx.json",
            "triage-vex-round-trip.cdx.json",
        } and (suppressed or not self.analysis_suppressed):
            findings = [
                {
                    "uuid": "finding-analysis-1",
                    "component": {
                        "uuid": "component-analysis-1",
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": (
                            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
                        ),
                    },
                    "vulnerability": {
                        "uuid": "vulnerability-analysis-1",
                        "vulnId": "CVE-2021-44228",
                        "source": "NVD",
                        "severity": "CRITICAL",
                    },
                    "analysis": {
                        "state": self.analysis_state,
                        "isSuppressed": self.analysis_suppressed,
                    },
                }
            ]
        return self._observation(f"/api/v1/finding/project/{project_uuid}", findings)

    def record_analysis_decision(
        self,
        *,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        action: AnalysisAction,
    ) -> DependencyTrackObservation:
        self.analysis_state = action.state.value
        self.analysis_suppressed = action.suppressed
        self.analysis_justification = action.justification.value
        self.analysis_response = action.response.value
        self.analysis_detail = action.detail
        self.analysis_comments.append(
            {
                "timestamp": len(self.analysis_comments) + 1,
                "comment": action.comment,
                "commenter": "dt-lab",
            }
        )
        return DependencyTrackObservation(
            method="PUT",
            path="/api/v1/analysis",
            query=(),
            status=200,
            headers=(),
            duration_seconds=0.01,
            payload={
                "analysisState": self.analysis_state,
                "isSuppressed": self.analysis_suppressed,
                "analysisComments": list(self.analysis_comments),
            },
        )

    def observe_analysis_trail(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> DependencyTrackObservation:
        return self._observation(
            "/api/v1/analysis",
            {
                "analysisState": self.analysis_state,
                "isSuppressed": self.analysis_suppressed,
                "analysisComments": list(self.analysis_comments),
            },
        )

    def observe_analysis_trail_if_present(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> DependencyTrackObservation:
        return self.observe_analysis_trail(
            project_uuid, component_uuid, vulnerability_uuid
        )

    def observe_project_vulnerabilities(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        vulnerabilities = []
        if self.last_bom == "triage-multiple-sources-aliases.cdx.json":
            vulnerabilities = [
                {
                    "uuid": "vulnerability-1",
                    "vulnId": "GHSA-35jh-r3h4-6jhm",
                    "source": "GITHUB",
                    "aliases": [{"cveId": "CVE-2021-23337"}],
                    "epssScore": 0.42,
                }
            ]
        return self._observation(
            f"/api/v1/vulnerability/project/{project_uuid}", vulnerabilities
        )

    def observe_project_metrics(self, project_uuid: str) -> DependencyTrackObservation:
        return self._observation(f"/api/v1/metrics/project/{project_uuid}/current", {})

    def observe_project_bom_export(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        return self._observation(f"/api/v1/bom/cyclonedx/project/{project_uuid}", {})

    def observe_project_vex_export(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        analysis: dict[str, object] = {"detail": self.analysis_detail}
        if self.analysis_state != "NOT_SET":
            analysis["state"] = self.analysis_state.lower()
        if self.analysis_justification != "NOT_SET":
            analysis["justification"] = self.analysis_justification.lower()
        if self.analysis_response != "NOT_SET":
            analysis["response"] = [self.analysis_response.lower()]
        return self._observation(
            f"/api/v1/vex/cyclonedx/project/{project_uuid}",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-44228",
                        "source": {"name": "NVD"},
                        "affects": [{"ref": project_uuid}],
                        "analysis": analysis,
                    }
                ],
            },
        )


class FakeRejectedBomClient(FakeLabClient):
    def attempt_bom_upload_by_project_coordinates(
        self,
        project_name: str,
        project_version: str,
        bom_path: str | Path,
        *,
        parent_project_uuid: str | None = None,
        project_tags: tuple[str, ...] = (),
    ) -> BomUploadAttempt:
        self.last_bom = Path(bom_path).name
        self.project_versions.append(project_version)
        return BomUploadAttempt(
            upload=None,
            observation=DependencyTrackObservation(
                method="POST",
                path="/api/v1/bom",
                query=(),
                status=400,
                headers=(("Content-Type", "application/problem+json; charset=utf-8"),),
                duration_seconds=0.02,
                payload={
                    "status": 400,
                    "title": "The uploaded BOM is invalid",
                    "detail": "component type is invalid",
                },
                request_payload={
                    "autoCreate": True,
                    "projectName": project_name,
                    "projectVersion": project_version,
                    "bom": {"filename": self.last_bom},
                },
            ),
        )


class FakeVexTargetingClient(FakeLabClient):
    PRIMARY_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    CONTROL_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.3"

    def __init__(self) -> None:
        super().__init__()
        self.scope_analysis: dict[str, dict[str, object]] = {
            self.PRIMARY_PURL: {
                "state": "NOT_SET",
                "suppressed": False,
                "justification": "NOT_SET",
                "detail": "",
                "comments": [],
            },
            self.CONTROL_PURL: {
                "state": "NOT_SET",
                "suppressed": False,
                "justification": "NOT_SET",
                "detail": "",
                "comments": [],
            },
        }
        self.component_uuids = {
            self.PRIMARY_PURL: "component-primary",
            self.CONTROL_PURL: "component-control",
        }

    def _scope_finding(self, purl: str) -> dict[str, object]:
        state = self.scope_analysis[purl]
        return {
            "uuid": f"finding-{self.component_uuids[purl]}",
            "component": {
                "uuid": self.component_uuids[purl],
                "name": "log4j-core",
                "version": purl.rsplit("@", 1)[-1],
                "purl": purl,
            },
            "vulnerability": {
                "uuid": "vulnerability-log4shell",
                "vulnId": "CVE-2021-44228",
                "source": "NVD",
                "severity": "CRITICAL",
            },
            "analysis": {
                "state": state["state"],
                "isSuppressed": state["suppressed"],
            },
        }

    def observe_project_findings(
        self, project_uuid: str, *, suppressed: bool = False
    ) -> DependencyTrackObservation:
        if self.last_bom != "triage-vex-targeting.cdx.json":
            return super().observe_project_findings(project_uuid, suppressed=suppressed)
        findings = [
            self._scope_finding(purl)
            for purl, state in self.scope_analysis.items()
            if suppressed or state["suppressed"] is False
        ]
        return self._observation(f"/api/v1/finding/project/{project_uuid}", findings)

    def observe_project_bom_export(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        if self.last_bom != "triage-vex-targeting.cdx.json":
            return super().observe_project_bom_export(project_uuid)
        return self._observation(
            f"/api/v1/bom/cyclonedx/project/{project_uuid}",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {
                    "component": {
                        "type": "application",
                        "name": "dt-lab-vex-targeting",
                        "bom-ref": project_uuid,
                    }
                },
                "components": [
                    {
                        "bom-ref": component_uuid,
                        "purl": purl,
                        "type": "library",
                        "name": "log4j-core",
                    }
                    for purl, component_uuid in self.component_uuids.items()
                ],
            },
        )

    def observe_project_vex_export(
        self, project_uuid: str
    ) -> DependencyTrackObservation:
        if self.last_bom != "triage-vex-targeting.cdx.json":
            return super().observe_project_vex_export(project_uuid)
        return self._observation(
            f"/api/v1/vex/cyclonedx/project/{project_uuid}",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {
                    "component": {
                        "type": "application",
                        "name": "dt-lab-vex-targeting",
                        "bom-ref": project_uuid,
                    }
                },
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-44228",
                        "source": {"name": "NVD"},
                        "affects": [{"ref": project_uuid}],
                    }
                ],
            },
        )

    def upload_vex_for_project(
        self, project_uuid: str, vex_path: str | Path
    ) -> VexUpload:
        if self.last_bom != "triage-vex-targeting.cdx.json":
            return super().upload_vex_for_project(project_uuid, vex_path)
        payload = json.loads(Path(vex_path).read_text(encoding="utf-8"))
        vulnerability = payload["vulnerabilities"][0]
        affects_ref = vulnerability["affects"][0]["ref"]
        analysis = vulnerability["analysis"]
        declared_components = {
            component.get("bom-ref"): component.get("purl")
            for component in payload.get("components", [])
            if isinstance(component, dict)
        }
        if affects_ref == project_uuid:
            targets = tuple(self.scope_analysis)
        elif declared_components.get(affects_ref) in self.scope_analysis:
            targets = (declared_components[affects_ref],)
        else:
            targets = ()
        for purl in targets:
            state = self.scope_analysis[purl]
            state["state"] = str(analysis["state"]).upper()
            state["suppressed"] = state["state"] == "NOT_AFFECTED"
            state["justification"] = str(
                analysis.get("justification", "not_set")
            ).upper()
            state["detail"] = str(analysis.get("detail", ""))
            comments = state["comments"]
            assert isinstance(comments, list)
            comments.append("CycloneDX VEX")
        return VexUpload(token="vex-targeting-token")

    def record_analysis_decision(
        self,
        *,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        action: AnalysisAction,
    ) -> DependencyTrackObservation:
        if self.last_bom != "triage-vex-targeting.cdx.json":
            return super().record_analysis_decision(
                project_uuid=project_uuid,
                component_uuid=component_uuid,
                vulnerability_uuid=vulnerability_uuid,
                action=action,
            )
        purl = next(
            purl
            for purl, observed_uuid in self.component_uuids.items()
            if observed_uuid == component_uuid
        )
        state = self.scope_analysis[purl]
        state["state"] = action.state.value
        state["suppressed"] = action.suppressed
        state["justification"] = action.justification.value
        state["detail"] = action.detail
        comments = state["comments"]
        assert isinstance(comments, list)
        comments.append(action.comment)
        return DependencyTrackObservation(
            method="PUT",
            path="/api/v1/analysis",
            query=(),
            status=200,
            headers=(),
            duration_seconds=0.01,
            payload={
                "analysisState": action.state.value,
                "isSuppressed": action.suppressed,
            },
        )

    def observe_analysis_trail(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> DependencyTrackObservation:
        if self.last_bom != "triage-vex-targeting.cdx.json":
            return super().observe_analysis_trail(
                project_uuid, component_uuid, vulnerability_uuid
            )
        purl = next(
            purl
            for purl, observed_uuid in self.component_uuids.items()
            if observed_uuid == component_uuid
        )
        state = self.scope_analysis[purl]
        return self._observation(
            "/api/v1/analysis",
            {
                "analysisState": state["state"],
                "analysisJustification": state["justification"],
                "analysisDetails": state["detail"],
                "isSuppressed": state["suppressed"],
                "analysisComments": state["comments"],
            },
        )


def test_default_lab_run_excludes_analysis_mutations(tmp_path: Path) -> None:
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(MANIFEST_PATH),
        manifest_path=MANIFEST_PATH,
        upload_client=client,
        read_client=client,
        output_directory=tmp_path,
        poll_interval=0,
    )

    run_metadata = json.loads(
        (Path(result.output_directory) / "run.json").read_text(encoding="utf-8")
    )
    assert "triage-analysis-states" not in run_metadata["scenarios"]
    assert "triage-delegation-boundary" not in run_metadata["scenarios"]
    assert "triage-vex-round-trip" not in run_metadata["scenarios"]
    assert "triage-vex-targeting" not in run_metadata["scenarios"]
    assert "robustness-invalid-cyclonedx" not in run_metadata["scenarios"]
    assert run_metadata["analysis_mutation_enabled"] is False
    assert client.analysis_comments == []


def test_lab_runner_verifies_parent_child_relationship_and_risk_projection(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(MANIFEST_PATH),
        manifest_path=MANIFEST_PATH,
        upload_client=client,
        read_client=client,
        output_directory=tmp_path,
        scenario_ids=("portfolio-parent-child",),
        poll_interval=0,
    )

    assert len(result.steps) == 2
    assert result.steps[0].project_uuid == "project-1"
    assert result.steps[1].project_uuid == "project-2"
    assert result.steps[1].observation_count == 9
    assert (Path(result.steps[0].snapshot_directory) / "bom-upload.json").is_file()
    assert (Path(result.steps[1].snapshot_directory) / "bom-upload.json").is_file()
    assert not (Path(result.steps[1].snapshot_directory) / "delta.json").exists()
    hierarchy = json.loads(
        (Path(result.steps[1].snapshot_directory) / "hierarchy.json").read_text(
            encoding="utf-8"
        )
    )
    assert hierarchy["relationship_verified"] is True
    assert hierarchy["parent_step"] == "parent"
    assert hierarchy["children_count"] == 1
    assert hierarchy["matching_child_count"] == 1
    assert hierarchy["parent"]["project"]["collection_logic"] == "NONE"
    project_ledger = json.loads(
        (Path(result.output_directory) / "projects.json").read_text(encoding="utf-8")
    )
    assert [project["project_name"] for project in project_ledger["projects"]] == [
        "dt-lab-portfolio-parent",
        "dt-lab-portfolio-child",
    ]


def test_lab_runner_records_least_privilege_routing_metadata(tmp_path: Path) -> None:
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(MANIFEST_PATH),
        manifest_path=MANIFEST_PATH,
        upload_client=client,
        read_client=client,
        output_directory=tmp_path,
        scenario_ids=("portfolio-tags-properties",),
        poll_interval=0,
    )

    assert len(result.steps) == 2
    assert result.steps[0].observation_count == 5
    assert result.steps[1].observation_count == 8
    assert (Path(result.output_directory) / "upload-key-team.json").is_file()
    initial = json.loads(
        (Path(result.steps[0].snapshot_directory) / "routing-metadata.json").read_text(
            encoding="utf-8"
        )
    )
    changed = json.loads(
        (Path(result.steps[1].snapshot_directory) / "routing-metadata.json").read_text(
            encoding="utf-8"
        )
    )
    assert initial["request_exactly_reconciled"] is True
    assert initial["observed_tags"] == [
        "dt-lab-owner-alpha",
        "dt-lab-repository-alpha",
    ]
    assert changed["request_exactly_reconciled"] is False
    assert changed["missing_requested_tags"] == [
        "dt-lab-owner-beta",
        "dt-lab-repository-beta",
    ]
    assert changed["stale_previous_tags"] == [
        "dt-lab-owner-alpha",
        "dt-lab-repository-alpha",
    ]
    assert changed["project_properties"] == {
        "property_count": None,
        "readable_with_orchestrator_key": False,
        "status": 403,
    }
    assert "PORTFOLIO_MANAGEMENT" not in changed["upload_key_permissions"]


def test_lab_runner_records_expected_bom_rejection_and_project_side_effect(
    tmp_path: Path,
) -> None:
    client = FakeRejectedBomClient()

    result = run_lab_scenarios(
        load_lab_manifest(MANIFEST_PATH),
        manifest_path=MANIFEST_PATH,
        upload_client=client,
        read_client=client,
        output_directory=tmp_path,
        scenario_ids=("robustness-invalid-cyclonedx",),
        poll_interval=0,
    )

    assert len(result.steps) == 1
    assert result.steps[0].project_uuid == "project-1"
    assert result.steps[0].observation_count == 5
    step_directory = Path(result.steps[0].snapshot_directory)
    rejection = json.loads(
        (step_directory / "upload-rejection.json").read_text(encoding="utf-8")
    )
    assert rejection["request"]["payload"]["autoCreate"] is True
    assert rejection["response"]["status"] == 400
    assert rejection["response"]["headers"]["Content-Type"].startswith(
        "application/problem+json"
    )
    assert rejection["response"]["payload"]["title"] == ("The uploaded BOM is invalid")
    project_ledger = json.loads(
        (Path(result.output_directory) / "projects.json").read_text(encoding="utf-8")
    )
    assert project_ledger["projects"][0]["project_uuid"] == "project-1"


def test_lab_runner_fails_when_bom_rejection_contract_changes(tmp_path: Path) -> None:
    client = FakeRejectedBomClient()
    original_attempt = client.attempt_bom_upload_by_project_coordinates

    def wrong_media_type(
        project_name: str,
        project_version: str,
        bom_path: str | Path,
        *,
        parent_project_uuid: str | None = None,
        project_tags: tuple[str, ...] = (),
    ) -> BomUploadAttempt:
        attempt = original_attempt(
            project_name,
            project_version,
            bom_path,
            parent_project_uuid=parent_project_uuid,
            project_tags=project_tags,
        )
        return BomUploadAttempt(
            upload=None,
            observation=DependencyTrackObservation(
                method=attempt.observation.method,
                path=attempt.observation.path,
                query=attempt.observation.query,
                status=attempt.observation.status,
                headers=(("Content-Type", "application/json"),),
                duration_seconds=attempt.observation.duration_seconds,
                payload=attempt.observation.payload,
                request_payload=attempt.observation.request_payload,
            ),
        )

    client.attempt_bom_upload_by_project_coordinates = wrong_media_type  # type: ignore[method-assign]

    with pytest.raises(LabManifestError, match="rejection contract mismatch"):
        run_lab_scenarios(
            load_lab_manifest(MANIFEST_PATH),
            manifest_path=MANIFEST_PATH,
            upload_client=client,
            read_client=client,
            output_directory=tmp_path,
            scenario_ids=("robustness-invalid-cyclonedx",),
            poll_interval=0,
        )

    run_directory = next(tmp_path.iterdir())
    rejection_path = next(run_directory.glob("*/**/upload-rejection.json"))
    assert rejection_path.is_file()


def test_lab_runner_verifies_json_xml_semantic_and_uuid_equivalence(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(MANIFEST_PATH),
        manifest_path=MANIFEST_PATH,
        upload_client=client,
        read_client=client,
        output_directory=tmp_path,
        scenario_ids=("robustness-json-xml-equivalence",),
        poll_interval=0,
    )

    assert len(result.steps) == 2
    comparison = json.loads(
        (Path(result.steps[1].snapshot_directory) / "equivalence.json").read_text(
            encoding="utf-8"
        )
    )
    assert comparison["reference_step"] == "json"
    assert comparison["equivalent"] is True
    assert comparison["checks"] == {
        "bom_export": True,
        "dependency_graph": True,
        "identity_uuids": True,
        "summary_semantics": True,
    }


def test_lab_runner_retains_json_xml_equivalence_failure_evidence(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()
    original_components = client.observe_project_components

    def format_sensitive_components(
        project_uuid: str,
    ) -> DependencyTrackObservation:
        observation = original_components(project_uuid)
        if client.last_bom.endswith(".xml"):
            return client._observation(
                observation.path,
                [
                    {
                        "uuid": "format-only-component",
                        "name": "format-only",
                        "version": "1.0.0",
                        "purl": "pkg:generic/format-only@1.0.0",
                    }
                ],
            )
        return observation

    client.observe_project_components = format_sensitive_components  # type: ignore[method-assign]

    with pytest.raises(LabManifestError, match="is not equivalent"):
        run_lab_scenarios(
            load_lab_manifest(MANIFEST_PATH),
            manifest_path=MANIFEST_PATH,
            upload_client=client,
            read_client=client,
            output_directory=tmp_path,
            scenario_ids=("robustness-json-xml-equivalence",),
            poll_interval=0,
        )

    run_directory = next(tmp_path.iterdir())
    comparison_path = next(run_directory.glob("*/02-xml/equivalence.json"))
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    assert comparison["equivalent"] is False
    assert comparison["checks"]["summary_semantics"] is False


def test_lab_runner_captures_step_delta(tmp_path: Path) -> None:
    manifest_path = MANIFEST_PATH
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(manifest_path),
        manifest_path=manifest_path,
        upload_client=client,
        read_client=client,
        output_directory=tmp_path,
        scenario_ids=("lifecycle-add-remove-components",),
        poll_interval=0,
        openapi_contract_sha256="abc123",
    )

    assert len(result.steps) == 2
    run_metadata = json.loads(
        (Path(result.output_directory) / "run.json").read_text(encoding="utf-8")
    )
    assert run_metadata["status"] == "completed"
    assert run_metadata["step_count"] == 2
    assert run_metadata["project_ledger"] == "projects.json"
    assert run_metadata["project_count"] == 1
    project_ledger = json.loads(
        (Path(result.output_directory) / "projects.json").read_text(encoding="utf-8")
    )
    assert project_ledger["run_id"] == result.run_id
    assert len(project_ledger["projects"]) == 2
    assert all(
        project["project_version"].endswith(f"-lab-{result.run_id[:8]}")
        for project in project_ledger["projects"]
    )
    updated_directory = Path(result.steps[1].snapshot_directory)
    assert (updated_directory / "bom-upload.json").is_file()
    delta = json.loads((updated_directory / "delta.json").read_text(encoding="utf-8"))
    assert delta["components_added"] == ["pkg:pypi/requests@2.31.0"]
    assert delta["components_removed"] == ["pkg:npm/lodash@4.17.20"]
    assert delta["retained_uuid_changes"] == []


def test_lab_runner_supports_step_project_versions(tmp_path: Path) -> None:
    manifest_path = MANIFEST_PATH
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(manifest_path),
        manifest_path=manifest_path,
        upload_client=client,
        read_client=client,
        output_directory=tmp_path,
        scenario_ids=("lifecycle-project-versions",),
        poll_interval=0,
    )

    assert len(result.steps) == 2
    assert client.project_versions[0].startswith("1.0.0-lab-")
    assert client.project_versions[1].startswith("2.0.0-lab-")


def test_lab_runner_summarizes_direct_components_and_services(
    tmp_path: Path,
) -> None:
    manifest_path = MANIFEST_PATH
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(manifest_path),
        manifest_path=manifest_path,
        upload_client=client,
        read_client=client,
        output_directory=tmp_path,
        scenario_ids=("portfolio-direct-transitive-graph",),
        poll_interval=0,
    )

    summary = json.loads(
        (Path(result.steps[0].snapshot_directory) / "summary.json").read_text(
            encoding="utf-8"
        )
    )
    assert summary["direct_component_count"] == 1
    assert summary["service_count"] == 1


def test_lab_runner_summarizes_finding_sources_aliases_and_scores(
    tmp_path: Path,
) -> None:
    manifest_path = MANIFEST_PATH
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(manifest_path),
        manifest_path=manifest_path,
        upload_client=client,
        read_client=client,
        output_directory=tmp_path,
        scenario_ids=("triage-multiple-sources-aliases",),
        poll_interval=0,
    )

    summary = json.loads(
        (Path(result.steps[0].snapshot_directory) / "summary.json").read_text(
            encoding="utf-8"
        )
    )
    assert summary["finding_sources"] == {"GITHUB": 1}
    assert summary["unique_vulnerability_count"] == 1
    assert summary["triage_field_coverage"] == {
        "analysis_state": 1,
        "analysis_suppressed": 1,
        "cvss_v3": 1,
        "epss_percentile": 1,
        "epss_score": 1,
        "severity": 1,
        "vulnerability_aliases": 1,
    }
    assert summary["findings"][0] == {
        "aliases": ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"],
        "analysis_state": "NOT_SET",
        "analysis_suppressed": False,
        "component_identity": "pkg:npm/lodash@4.17.20",
        "component_uuid": "component-1",
        "cvss_v2_base_score": None,
        "cvss_v3_base_score": 7.2,
        "cvss_v4_score": None,
        "epss_percentile": 0.91,
        "epss_score": 0.42,
        "finding_uuid": "finding-1",
        "severity": "HIGH",
        "vulnerability_id": "GHSA-35jh-r3h4-6jhm",
        "vulnerability_source": "GITHUB",
        "vulnerability_uuid": "vulnerability-1",
    }
    assert summary["vulnerabilities"][0]["aliases"] == ["CVE-2021-23337"]


def test_lab_runner_requires_explicit_analysis_mutation_opt_in(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()

    with pytest.raises(LabManifestError, match="explicit opt-in"):
        run_lab_scenarios(
            load_lab_manifest(MANIFEST_PATH),
            manifest_path=MANIFEST_PATH,
            upload_client=client,
            read_client=client,
            analysis_client=client,
            output_directory=tmp_path,
            scenario_ids=("triage-analysis-states",),
            poll_interval=0,
        )

    assert list(tmp_path.iterdir()) == []


def test_lab_runner_rejects_disallowed_analysis_key_permissions(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()

    def overprivileged_team() -> DependencyTrackObservation:
        return client._observation(
            "/api/v1/team/self",
            {
                "permissions": [
                    {"name": "VULNERABILITY_ANALYSIS"},
                    {"name": "PORTFOLIO_MANAGEMENT"},
                ]
            },
        )

    client.observe_current_team = overprivileged_team  # type: ignore[method-assign]

    with pytest.raises(LabManifestError, match="outside the lab analysis allowlist"):
        run_lab_scenarios(
            load_lab_manifest(MANIFEST_PATH),
            manifest_path=MANIFEST_PATH,
            upload_client=client,
            read_client=client,
            analysis_client=client,
            output_directory=tmp_path,
            scenario_ids=("triage-analysis-states",),
            poll_interval=0,
            allow_analysis_mutation=True,
        )

    assert list(tmp_path.iterdir()) == []


def test_lab_runner_requires_vulnerability_analysis_permission(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()

    def read_only_team() -> DependencyTrackObservation:
        return client._observation(
            "/api/v1/team/self",
            {
                "permissions": [
                    {"name": "VIEW_PORTFOLIO"},
                    {"name": "VIEW_VULNERABILITY"},
                ]
            },
        )

    client.observe_current_team = read_only_team  # type: ignore[method-assign]

    with pytest.raises(LabManifestError, match="must include VULNERABILITY_ANALYSIS"):
        run_lab_scenarios(
            load_lab_manifest(MANIFEST_PATH),
            manifest_path=MANIFEST_PATH,
            upload_client=client,
            read_client=client,
            analysis_client=client,
            output_directory=tmp_path,
            scenario_ids=("triage-analysis-states",),
            poll_interval=0,
            allow_analysis_mutation=True,
        )

    assert list(tmp_path.iterdir()) == []


def test_lab_runner_records_analysis_decisions_and_verification(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(MANIFEST_PATH),
        manifest_path=MANIFEST_PATH,
        upload_client=client,
        read_client=client,
        analysis_client=client,
        output_directory=tmp_path,
        scenario_ids=("triage-analysis-states",),
        poll_interval=0,
        allow_analysis_mutation=True,
    )

    assert len(result.steps) == 1
    assert result.steps[0].observation_count == 41
    step_directory = Path(result.steps[0].snapshot_directory)
    action_directories = sorted(
        path
        for path in (step_directory / "analysis-actions").iterdir()
        if path.is_dir()
    )
    assert [path.name for path in action_directories] == [
        "01-begin-triage",
        "02-mark-exploitable",
        "03-mark-not-affected",
        "04-mark-false-positive",
        "05-mark-resolved",
        "06-restore-not-set",
    ]
    final_verification = json.loads(
        (action_directories[-1] / "verification.json").read_text(encoding="utf-8")
    )
    assert final_verification["expected"] == {
        "state": "NOT_SET",
        "suppressed": False,
    }
    assert final_verification["observed"]["finding_state"] == "NOT_SET"
    assert final_verification["observed"]["trail_comment_count"] == 6
    run_metadata = json.loads(
        (Path(result.output_directory) / "run.json").read_text(encoding="utf-8")
    )
    assert run_metadata["analysis_mutation_enabled"] is True
    assert (Path(result.output_directory) / "analysis-key-team.json").is_file()


def test_lab_runner_captures_analysis_reconciliation_boundaries(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(MANIFEST_PATH),
        manifest_path=MANIFEST_PATH,
        upload_client=client,
        read_client=client,
        analysis_client=client,
        output_directory=tmp_path,
        scenario_ids=("triage-delegation-boundary",),
        poll_interval=0,
        allow_analysis_mutation=True,
    )

    assert len(result.steps) == 1
    assert result.steps[0].observation_count == 41
    reconciliation = json.loads(
        (
            Path(result.steps[0].snapshot_directory)
            / "analysis-actions"
            / "reconciliation.json"
        ).read_text(encoding="utf-8")
    )
    assert {
        key: reconciliation[key]
        for key in (
            "finding_etag_observed",
            "finding_last_modified_observed",
            "trail_etag_observed",
            "trail_last_modified_observed",
        )
    } == {
        "finding_etag_observed": False,
        "finding_last_modified_observed": False,
        "trail_etag_observed": False,
        "trail_last_modified_observed": False,
    }
    actions = {action["action_id"]: action for action in reconciliation["actions"]}
    comment_only_delta = actions["append-comment-only"]["delta_from_previous"]
    assert comment_only_delta == {
        "audit_changed": True,
        "audit_comment_count_delta": 1,
        "finding_decision_changed": False,
        "last_comment_timestamp_advanced": True,
        "request_decision_changed": False,
        "trail_decision_changed": False,
    }
    replay_delta = actions["replay-identical-request"]["delta_from_previous"]
    assert replay_delta == comment_only_delta
    assert actions["suppress-only"]["default_finding_present"] is False
    assert actions["suppress-only"]["including_suppressed_finding_present"] is True
    assert actions["unsuppress-only"]["default_finding_present"] is True
    suppress_delta = actions["suppress-only"]["delta_from_previous"]
    assert suppress_delta["request_decision_changed"] is True
    assert suppress_delta["trail_decision_changed"] is True
    assert suppress_delta["finding_decision_changed"] is True
    assert actions["restore-not-set"]["trail_decision"]["state"] == "NOT_SET"
    assert actions["restore-not-set"]["trail_decision"]["suppressed"] is False


def test_lab_runner_emergency_restores_failed_analysis_action_sequence(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()
    original_record = client.record_analysis_decision
    call_count = 0

    def fail_second_update(**kwargs) -> DependencyTrackObservation:
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise RuntimeError("synthetic analysis update failure")
        return original_record(**kwargs)

    client.record_analysis_decision = fail_second_update  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="synthetic analysis update failure"):
        run_lab_scenarios(
            load_lab_manifest(MANIFEST_PATH),
            manifest_path=MANIFEST_PATH,
            upload_client=client,
            read_client=client,
            analysis_client=client,
            output_directory=tmp_path,
            scenario_ids=("triage-delegation-boundary",),
            poll_interval=0,
            allow_analysis_mutation=True,
        )

    assert client.analysis_state == "NOT_SET"
    assert client.analysis_suppressed is False
    emergency_verifications = list(
        tmp_path.glob(
            "*/triage-delegation-boundary/*/analysis-actions/"
            "emergency-restore/*-verification.json"
        )
    )
    assert len(emergency_verifications) == 1
    assert json.loads(emergency_verifications[0].read_text(encoding="utf-8")) == {
        "state": "NOT_SET",
        "suppressed": False,
    }


def test_lab_runner_records_vex_round_trip_and_restores_analysis(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()

    result = run_lab_scenarios(
        load_lab_manifest(MANIFEST_PATH),
        manifest_path=MANIFEST_PATH,
        upload_client=client,
        read_client=client,
        analysis_client=client,
        output_directory=tmp_path,
        scenario_ids=("triage-vex-round-trip",),
        poll_interval=0,
        allow_analysis_mutation=True,
    )

    assert len(result.steps) == 1
    assert result.steps[0].observation_count == 22
    directory = (
        Path(result.steps[0].snapshot_directory)
        / "vex-round-trip"
        / "not-affected-round-trip"
    )
    verification = json.loads(
        (directory / "verification.json").read_text(encoding="utf-8")
    )
    assert verification["seed"]["finding_state"] == "NOT_AFFECTED"
    assert verification["reset"]["finding_state"] == "NOT_SET"
    assert verification["imported"]["finding_state"] == "NOT_AFFECTED"
    assert verification["replayed"]["finding_state"] == "NOT_AFFECTED"
    assert verification["comparison"] == {
        "finding_state_preserved": True,
        "replay_audit_comment_delta": 0,
        "replay_state_idempotent": True,
        "replay_vex_analysis_idempotent": True,
        "source_affects_component_purl": False,
        "suppression_projection_matches_seed": True,
        "vex_affects_preserved": True,
        "vex_analysis_preserved": True,
    }
    assert (directory / "source-vex.cdx.json").is_file()
    final_verification = json.loads(
        (directory / "final-verification.json").read_text(encoding="utf-8")
    )
    assert final_verification == {
        "expected": {"state": "NOT_SET", "suppressed": False},
        "observed": {"state": "NOT_SET", "suppressed": False},
    }
    assert client.analysis_state == "NOT_SET"
    assert client.analysis_suppressed is False


def test_lab_runner_emergency_restores_analysis_when_vex_upload_fails(
    tmp_path: Path,
) -> None:
    client = FakeLabClient()

    def fail_vex_upload(project_uuid: str, vex_path: str | Path) -> VexUpload:
        raise RuntimeError("VEX upload failed")

    client.upload_vex_for_project = fail_vex_upload  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="VEX upload failed"):
        run_lab_scenarios(
            load_lab_manifest(MANIFEST_PATH),
            manifest_path=MANIFEST_PATH,
            upload_client=client,
            read_client=client,
            analysis_client=client,
            output_directory=tmp_path,
            scenario_ids=("triage-vex-round-trip",),
            poll_interval=0,
            allow_analysis_mutation=True,
        )

    assert client.analysis_state == "NOT_SET"
    assert client.analysis_suppressed is False
    run_directory = next(tmp_path.iterdir())
    verification_path = (
        run_directory
        / "triage-vex-round-trip"
        / "01-not-affected-round-trip"
        / "vex-round-trip"
        / "not-affected-round-trip"
        / "emergency-restore"
        / "verification.json"
    )
    assert json.loads(verification_path.read_text(encoding="utf-8"))["observed"] == {
        "state": "NOT_SET",
        "suppressed": False,
    }


def test_lab_runner_compares_component_and_project_vex_targeting(
    tmp_path: Path,
) -> None:
    client = FakeVexTargetingClient()

    result = run_lab_scenarios(
        load_lab_manifest(MANIFEST_PATH),
        manifest_path=MANIFEST_PATH,
        upload_client=client,
        read_client=client,
        analysis_client=client,
        output_directory=tmp_path,
        scenario_ids=("triage-vex-targeting",),
        poll_interval=0,
        allow_analysis_mutation=True,
    )

    assert len(result.steps) == 1
    assert result.steps[0].observation_count == 45
    directory = (
        Path(result.steps[0].snapshot_directory)
        / "vex-targeting"
        / "project-and-component-scope"
    )
    verification = json.loads(
        (directory / "verification.json").read_text(encoding="utf-8")
    )
    assert verification["exported_component_scope"]["primary"]["state"] == "NOT_SET"
    assert verification["exported_component_scope"]["control"]["state"] == "NOT_SET"
    assert verification["input_component_scope"]["primary"]["state"] == "NOT_SET"
    assert verification["input_component_scope"]["control"]["state"] == "NOT_SET"
    assert verification["declared_component_scope"]["primary"]["state"] == (
        "NOT_AFFECTED"
    )
    assert verification["declared_component_scope"]["control"]["state"] == "NOT_SET"
    assert verification["project_scope"]["primary"]["state"] == "NOT_AFFECTED"
    assert verification["project_scope"]["control"]["state"] == "NOT_AFFECTED"
    assert verification["comparison"] == {
        "declared_component_scope_control_unchanged": True,
        "declared_component_scope_primary_changed": True,
        "exported_component_scope_control_unchanged": True,
        "exported_component_scope_primary_changed": False,
        "input_component_scope_control_unchanged": True,
        "input_component_scope_primary_changed": False,
        "project_scope_control_changed": True,
        "project_scope_primary_changed": True,
    }
    final_verification = json.loads(
        (directory / "final-restore" / "verification.json").read_text(encoding="utf-8")
    )
    assert final_verification == {
        "control": {"state": "NOT_SET", "suppressed": False},
        "primary": {"state": "NOT_SET", "suppressed": False},
    }


def test_lab_runner_records_failed_run_metadata(tmp_path: Path) -> None:
    manifest_path = MANIFEST_PATH
    client = FakeLabClient()

    def fail_export(project_uuid: str) -> DependencyTrackObservation:
        raise RuntimeError("export failed")

    client.observe_project_bom_export = fail_export  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="export failed"):
        run_lab_scenarios(
            load_lab_manifest(manifest_path),
            manifest_path=manifest_path,
            upload_client=client,
            read_client=client,
            output_directory=tmp_path,
            scenario_ids=("triage-multiple-sources-aliases",),
            poll_interval=0,
        )

    run_directories = list(tmp_path.iterdir())
    assert len(run_directories) == 1
    metadata = json.loads((run_directories[0] / "run.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "failed"
    assert metadata["completed_step_count"] == 0
    assert metadata["error"] == {
        "type": "RuntimeError",
        "message": "export failed",
    }
