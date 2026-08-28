from __future__ import annotations

import json
from pathlib import Path

import pytest
from dt_lab.cli import main
from dt_lab.domain import (
    BomUpload,
    DependencyTrackObservation,
    LabManifestError,
    ScenarioStatus,
)
from dt_lab.service import (
    build_openapi_inventory,
    load_lab_manifest,
    openapi_inventory_dict,
    run_lab_scenarios,
)

LAB_ROOT = Path(__file__).parents[1]
MANIFEST_PATH = LAB_ROOT / "scenarios" / "scenarios.yaml"
OPENAPI_FIXTURE = LAB_ROOT / "fixtures" / "dependency-track-openapi.json"


def test_repository_lab_manifest_is_valid() -> None:
    manifest = load_lab_manifest(MANIFEST_PATH)

    assert manifest.target.dependency_track_version == "4.14.3"
    assert len(manifest.scenarios) == 16
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
    ]
    assert sum(len(scenario.steps) for scenario in implemented) == 11


def test_lab_manifest_rejects_missing_implemented_bom(tmp_path: Path) -> None:
    manifest_path = tmp_path / "scenarios.yaml"
    manifest_path.write_text(
        """
schema_version: 1
target:
  dependency_track_version: 4.14.3
  cyclonedx_versions: ["1.5"]
scenarios:
  - id: missing-bom
    category: robustness
    status: implemented
    purpose: Reject missing scenario files.
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
schema_version: 1
target:
  dependency_track_version: 4.14.3
  cyclonedx_versions: ["1.5"]
scenarios:
  - id: invalid-graph
    category: robustness
    status: implemented
    purpose: Reject an invalid dependency graph.
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

    assert inventory.path_count == 5
    assert inventory.operation_count == 5
    assert inventory.tag_count == 4
    assert len(inventory.operations) == 4
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
    assert rendered["summary"]["selected_operation_count"] == 4
    assert len(rendered["source"]["contract_sha256"]) == 64


def test_lab_manifest_requires_cleanup_safe_project_prefix(tmp_path: Path) -> None:
    manifest_path = tmp_path / "scenarios.yaml"
    manifest_path.write_text(
        """
schema_version: 1
target:
  dependency_track_version: 4.14.3
  cyclonedx_versions: ["1.5"]
scenarios:
  - id: unsafe-project
    category: robustness
    status: planned
    purpose: Reject a Project outside the lab namespace.
    project: {name: production-service, version: 1.0.0}
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(LabManifestError, match="must start with 'dt-lab-'"):
        load_lab_manifest(manifest_path)


def test_openapi_inventory_can_include_all_tags() -> None:
    payload = json.loads(OPENAPI_FIXTURE.read_text(encoding="utf-8"))

    inventory = build_openapi_inventory(payload, selected_tags=None)

    assert len(inventory.operations) == 5
    assert inventory.selected_tags == ("analysis", "finding", "project", "user")


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
    assert "scenarios=16 implemented=8 planned=8 steps=11" in capsys.readouterr().out


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
        "operation_count": 5,
        "path_count": 5,
        "selected_operation_count": 4,
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
            "vex",
            "violation",
            "violationanalysis",
            "vulnerability",
        ],
        "tag_count": 4,
    }
    assert "OpenAPI inventory: paths=5 operations=5 selected=4 tags=4" in (
        capsys.readouterr().out
    )


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

    def upload_bom_by_project_coordinates(
        self, project_name: str, project_version: str, bom_path: str | Path
    ) -> BomUpload:
        self.last_bom = Path(bom_path).name
        self.project_versions.append(project_version)
        return BomUpload(token=f"token-{self.last_bom}")

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

    def observe_project_findings(self, project_uuid: str) -> DependencyTrackObservation:
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
        return self._observation(f"/api/v1/finding/project/{project_uuid}", findings)

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
