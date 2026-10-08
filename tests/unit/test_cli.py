from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from sbom_ops import cli
from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.asset_registry import (
    RegisteredDeployable,
    RegisteredService,
    RegistryDeploymentObservation,
    RegistryDeploymentStatus,
    RegistryProjectObservation,
    RegistryProjectStatus,
    RegistrySnapshotStatus,
    ReportedDeployment,
)
from sbom_ops.domain.assets import BusinessCriticality, DeploymentStatus
from sbom_ops.domain.models import (
    AnalysisSnapshotStatus,
    AnalysisState,
    FindingAssessment,
    Priority,
    Severity,
)
from sbom_ops.services.orchestrator import RunResult
from sbom_ops.storage.asset_registry import AssetRegistry


class FakeOrchestrator:
    def __init__(
        self,
        config,
        *,
        force_refresh_kev=False,
        advisory_snapshot=None,
        asset_inventory=None,
    ):
        self.config = config
        self.force_refresh_kev = force_refresh_kev
        self.advisory_snapshot = advisory_snapshot
        self.asset_inventory = asset_inventory

    def run(self) -> RunResult:
        return RunResult(
            run_id="run-1",
            duration_seconds=0.1,
            kev_used_stale_cache=False,
            projects_processed=1,
            findings_processed=2,
            issues_created=0,
            issues_updated=0,
            issues_closed=0,
            dry_run=True,
            analysis_snapshot_status=AnalysisSnapshotStatus.NOT_REQUESTED,
            assessments=(
                FindingAssessment(
                    project_uuid="project-1",
                    finding_key="v2:project-1:digest",
                    vulnerability_id="GHSA-ABCD-1234-5678",
                    vulnerability_source="GITHUB",
                    severity=Severity.HIGH,
                    cvss_score=None,
                    epss_score=None,
                    priority=Priority.P3,
                    analysis_state=AnalysisState.NOT_SET,
                    is_suppressed=False,
                    rationale=("Default monitoring priority",),
                    analysis_detail="analyst note",
                    in_kev=False,
                    component_uuid="component-1",
                    component_purl="pkg:pypi/example@1.2.3",
                    component_name="example",
                    component_version="1.2.3",
                    vulnerability_aliases=("CVE-2026-1001",),
                ),
            ),
        )


def test_sync_log_failure_is_visible_without_breaking_json_result(
    monkeypatch, capsys
) -> None:
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file="missing/log.jsonl"))
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    monkeypatch.setattr(cli, "append_sync_event", lambda path, payload: False)

    assert cli.run_sync(config, "json") == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["run_id"] == "run-1"
    assert payload["assessments"][0]["component_purl"] == ("pkg:pypi/example@1.2.3")
    assert payload["assessments"][0]["in_kev"] is False
    assert payload["assessments"][0]["analysis_detail"] == "analyst note"
    assert payload["assessments"][0]["vulnerability_aliases"] == ["CVE-2026-1001"]
    assert payload["analysis_snapshot_status"] == "not_requested"
    assert captured.err == (
        "warning: sync log could not be written; primary sync result is unchanged\n"
    )


def test_sync_log_success_does_not_emit_warning(monkeypatch, capsys) -> None:
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file="sync.jsonl"))
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    monkeypatch.setattr(cli, "append_sync_event", lambda path, payload: True)

    assert cli.run_sync(config, "json") == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "succeeded"
    assert captured.err == ""


def test_sync_passes_force_kev_refresh_to_orchestrator(monkeypatch, capsys) -> None:
    captured = {}

    class CapturingOrchestrator(FakeOrchestrator):
        def __init__(self, config, *, force_refresh_kev=False):
            super().__init__(config, force_refresh_kev=force_refresh_kev)
            captured["force_refresh_kev"] = self.force_refresh_kev

    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    monkeypatch.setattr(cli, "Orchestrator", CapturingOrchestrator)

    assert cli.run_sync(config, "json", force_refresh_kev=True) == 0

    assert captured["force_refresh_kev"] is True
    assert json.loads(capsys.readouterr().out)["status"] == "succeeded"


def test_sync_parser_exposes_force_kev_refresh_flag() -> None:
    args = cli.build_parser().parse_args(["sync", "--refresh-kev"])

    assert args.refresh_kev is True


def test_sync_parser_exposes_advisory_snapshot_input() -> None:
    args = cli.build_parser().parse_args(
        ["sync", "--advisory-snapshot", "snapshot.json"]
    )

    assert args.advisory_snapshot == "snapshot.json"


def test_sync_parser_exposes_asset_inventory_input() -> None:
    args = cli.build_parser().parse_args(["sync", "--asset-inventory", "assets.json"])

    assert args.asset_inventory == "assets.json"


def test_sync_parser_exposes_asset_db_input() -> None:
    args = cli.build_parser().parse_args(["sync", "--asset-db", "assets.sqlite3"])

    assert args.asset_db == "assets.sqlite3"


def test_sync_reads_asset_db_before_running_orchestrator(
    tmp_path, monkeypatch, capsys
) -> None:
    path = tmp_path / "assets.sqlite3"
    with AssetRegistry(path, create_if_missing=True) as registry:
        registry.register_service(
            RegisteredService(
                "checkout-api", "team-checkout", BusinessCriticality.HIGH, "payments"
            )
        )
        registry.register_deployable(RegisteredDeployable("checkout-api", "web"))
        registry.register_deployment(
            ReportedDeployment(
                "checkout-api",
                "web",
                "production",
                "build-123",
                DeploymentStatus.DEPLOYED,
                ExposureStatus.UNKNOWN,
                "alice",
                "deployment record 123",
                "2026-10-07T00:00:00Z",
                "2099-10-07T00:00:00Z",
            )
        )
    captured = {}

    class CapturingOrchestrator(FakeOrchestrator):
        def __init__(self, config, *, force_refresh_kev=False, asset_registry=None):
            super().__init__(config, force_refresh_kev=force_refresh_kev)
            captured["registry"] = asset_registry

    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    monkeypatch.setattr(cli, "Orchestrator", CapturingOrchestrator)

    assert cli.run_sync(config, "json", asset_db_path=str(path)) == 0
    assert captured["registry"].services[0].owner == "team-checkout"
    assert captured["registry"].links == ()
    assert captured["registry"].deployment_reports[0].artifact_id == "build-123"
    assert json.loads(capsys.readouterr().out)["status"] == "succeeded"


def test_sync_rejects_missing_asset_db_before_running_orchestrator(
    tmp_path, monkeypatch
) -> None:
    def unexpected_orchestrator(*args, **kwargs):
        raise AssertionError("sync must not begin after asset DB read failure")

    monkeypatch.setattr(cli, "Orchestrator", unexpected_orchestrator)
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))

    with pytest.raises(ValueError, match="does not exist"):
        cli.run_sync(config, "json", asset_db_path=str(tmp_path / "missing.sqlite3"))


def test_sync_passes_asset_inventory_to_orchestrator(monkeypatch, capsys) -> None:
    captured = {}

    class CapturingOrchestrator(FakeOrchestrator):
        def __init__(self, config, *, force_refresh_kev=False, asset_inventory=None):
            super().__init__(
                config,
                force_refresh_kev=force_refresh_kev,
                asset_inventory=asset_inventory,
            )
            captured["inventory"] = asset_inventory

    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    path = Path(__file__).parents[2] / "examples" / "asset-inventory.example.json"
    monkeypatch.setattr(cli, "Orchestrator", CapturingOrchestrator)

    assert cli.run_sync(config, "json", asset_inventory_path=str(path)) == 0

    assert captured["inventory"].snapshot_id == "synthetic-asset-scenario-v1"
    assert json.loads(capsys.readouterr().out)["status"] == "succeeded"


def test_invalid_asset_inventory_does_not_block_sync(tmp_path, monkeypatch, capsys):
    path = tmp_path / "invalid.json"
    path.write_text("not-json", encoding="utf-8")
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)

    assert cli.run_sync(config, "json", asset_inventory_path=str(path)) == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "succeeded"
    assert payload["asset_inventory_status"] == "invalid"
    assert "invalid asset inventory JSON" in payload["asset_inventory_error"]
    assert "warning: asset inventory ignored" in captured.err


def test_invalid_advisory_snapshot_does_not_block_sync(tmp_path, monkeypatch, capsys):
    path = tmp_path / "invalid.json"
    path.write_text("not-json", encoding="utf-8")
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)

    assert cli.run_sync(config, "json", advisory_snapshot_path=str(path)) == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "succeeded"
    assert payload["advisory_snapshot_status"] == "invalid"
    assert "invalid advisory snapshot JSON" in payload["advisory_snapshot_error"]
    assert "warning: advisory snapshot ignored" in captured.err


def test_text_result_makes_missing_scores_explicit(monkeypatch, capsys) -> None:
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)

    assert cli.run_sync(config, "text") == 0

    captured = capsys.readouterr()
    assert "analysis_snapshot_status=not_requested" in captured.out.splitlines()[0]
    assert (
        "component=example@1.2.3 purl=pkg:pypi/example@1.2.3 "
        "vulnerability=GHSA-ABCD-1234-5678 "
        "source=GITHUB dt_aliases=CVE-2026-1001 severity=HIGH "
        "cvss=unavailable cvss_version=unavailable epss=unavailable "
        "in_kev=false poc_reported=unknown poc_sources=none advisory=none "
        "analysis=NOT_SET suppressed=false "
        "rationale=Default monitoring priority" in captured.out
    )


def test_text_result_shows_reviewed_registry_link(monkeypatch, capsys) -> None:
    class RegistryOrchestrator(FakeOrchestrator):
        def run(self) -> RunResult:
            return replace(
                super().run(),
                registry_snapshot_status=RegistrySnapshotStatus.LOADED,
                registry_projects=(
                    RegistryProjectObservation(
                        project_uuid="project-1",
                        dt_name="checkout-api/web",
                        dt_version="v1",
                        status=RegistryProjectStatus.MATCHED,
                        reviewed_name="checkout-api/web",
                        reviewed_version="v1",
                        service_id="checkout-api",
                        deployable_id="web",
                        owner="team-checkout",
                        criticality=BusinessCriticality.HIGH,
                        reviewer="alice",
                    ),
                ),
                registry_deployments=(
                    RegistryDeploymentObservation(
                        project_uuid="project-1",
                        environment="production",
                        artifact_id="v1",
                        status=RegistryDeploymentStatus.REPORTED,
                        report_ids=(1,),
                        deployment_status=DeploymentStatus.DEPLOYED,
                        exposure_status=ExposureStatus.UNKNOWN,
                    ),
                ),
            )

    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    monkeypatch.setattr(cli, "Orchestrator", RegistryOrchestrator)

    assert cli.run_sync(config, "text") == 0

    output = capsys.readouterr().out
    assert "registry_snapshot_status=loaded" in output
    assert (
        "registry-project project=project-1 status=matched "
        "dt_name=checkout-api/web dt_version=v1 "
        "reviewed_name=checkout-api/web reviewed_version=v1 "
        "service=checkout-api/web owner=team-checkout criticality=high reviewer=alice"
    ) in output
    assert (
        "registry-deployment project=project-1 environment=production "
        "artifact=v1 status=reported deployment=deployed exposure=unknown "
        "report_ids=1 other_artifacts=none"
    ) in output


def test_text_result_discloses_stale_kev_cache(monkeypatch, capsys) -> None:
    class StaleKevOrchestrator(FakeOrchestrator):
        def run(self) -> RunResult:
            return replace(super().run(), kev_used_stale_cache=True)

    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    monkeypatch.setattr(cli, "Orchestrator", StaleKevOrchestrator)

    assert cli.run_sync(config, "text") == 0

    captured = capsys.readouterr()
    assert "kev_used_stale_cache=true" in captured.out.splitlines()[0]
