from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from dt_lab.cli import main
from dt_lab.domain import (
    AnalysisAction,
    BomUpload,
    DependencyTrackObservation,
    LabManifestError,
    ScenarioStatus,
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
    assert len(manifest.scenarios) == 17
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
        "portfolio-direct-transitive-graph",
        "triage-multiple-sources-aliases",
        "triage-analysis-states",
        "triage-vex-round-trip",
    ]
    assert sum(len(scenario.steps) for scenario in implemented) == 13
    assert any(
        scenario.id == "triage-delegation-boundary"
        and scenario.status is ScenarioStatus.PLANNED
        for scenario in manifest.scenarios
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


def test_openapi_inventory_extracts_contract_details() -> None:
    payload = json.loads(OPENAPI_FIXTURE.read_text(encoding="utf-8"))

    inventory = build_openapi_inventory(payload)
    rendered = openapi_inventory_dict(inventory)

    assert inventory.path_count == 9
    assert inventory.operation_count == 10
    assert inventory.tag_count == 7
    assert len(inventory.operations) == 9
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
    assert rendered["summary"]["selected_operation_count"] == 9
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

    assert len(inventory.operations) == 10
    assert inventory.selected_tags == (
        "analysis",
        "component",
        "finding",
        "project",
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
    assert "scenarios=17 implemented=10 planned=7 steps=13" in capsys.readouterr().out


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
        "operation_count": 10,
        "path_count": 9,
        "selected_operation_count": 9,
        "selected_tags": [
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
        ],
        "tag_count": 7,
    }
    assert "OpenAPI inventory: paths=9 operations=10 selected=9 tags=7" in (
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

    def upload_bom_by_project_coordinates(
        self, project_name: str, project_version: str, bom_path: str | Path
    ) -> BomUpload:
        self.last_bom = Path(bom_path).name
        self.project_versions.append(project_version)
        return BomUpload(token=f"token-{self.last_bom}")

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
        return self._observation(
            "/api/v1/project/lookup",
            {"uuid": "project-1", "name": project_name, "version": project_version},
        )

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
        return self._observation(
            f"/api/v1/project/{project_uuid}", {"uuid": project_uuid}
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
        elif (
            self.last_bom
            in {
                "triage-analysis-states.cdx.json",
                "triage-vex-round-trip.cdx.json",
            }
            and suppressed == self.analysis_suppressed
        ):
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
    assert "triage-vex-round-trip" not in run_metadata["scenarios"]
    assert run_metadata["analysis_mutation_enabled"] is False
    assert client.analysis_comments == []


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
    assert result.steps[0].observation_count == 35
    step_directory = Path(result.steps[0].snapshot_directory)
    action_directories = sorted((step_directory / "analysis-actions").iterdir())
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
