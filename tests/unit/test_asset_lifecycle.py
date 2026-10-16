from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from sbom_ops import cli
from sbom_ops.clients.dependency_track import DependencyTrackProject
from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    LifecycleAction,
    RegisteredDeployable,
    RegisteredService,
    ReportedDeployment,
)
from sbom_ops.domain.assets import BusinessCriticality, DeploymentStatus
from sbom_ops.services.asset_registry import (
    approve_project_link,
    discover_project_candidates,
    observe_registry_deployments,
    observe_registry_projects,
)
from sbom_ops.services.asset_updates import plan_lifecycle_change, plan_service_update
from sbom_ops.storage.asset_registry import AssetRegistry


def populate(path: Path) -> None:
    with AssetRegistry(path, create_if_missing=True) as registry:
        registry.register_service(
            RegisteredService(
                "checkout", "team-a", BusinessCriticality.HIGH, "payments"
            )
        )
        for name in ("web", "worker"):
            deployable = RegisteredDeployable("checkout", name)
            registry.register_deployable(deployable)
            registry.link_project(
                deployable=deployable,
                project_uuid=name,
                project_version="v1",
                reviewer="alice",
            )
        registry.register_deployment(
            ReportedDeployment(
                "checkout",
                "web",
                "production",
                "v1",
                DeploymentStatus.DEPLOYED,
                ExposureStatus.CONFIRMED,
                "alice",
                "fictional claim",
                "2026-01-01T00:00:00Z",
                "2099-01-01T00:00:00Z",
            )
        )


def plan(registry: AssetRegistry, action: LifecycleAction, **kwargs):
    return plan_lifecycle_change(
        registry, action=action, actor="alice", reason="correction", **kwargs
    )


def snapshot(registry: AssetRegistry) -> AssetRegistrySnapshot:
    return AssetRegistrySnapshot(
        registry.list_services(),
        registry.list_links(),
        registry.list_deployment_reports(),
        **registry.lifecycle_state(),
    )


@pytest.mark.parametrize(
    "action,deployable,expected",
    [
        (LifecycleAction.RETIRE_SERVICE, None, ["retired", "retired"]),
        (LifecycleAction.RETIRE_DEPLOYABLE, "web", ["retired", "matched"]),
    ],
)
def test_retirement_preserves_records_and_excludes_context(
    tmp_path, action, deployable, expected
):
    path = tmp_path / "assets.sqlite3"
    populate(path)
    projects = [
        DependencyTrackProject(name, f"checkout/{name}", "v1")
        for name in ("web", "worker")
    ]
    with AssetRegistry(path) as registry:
        links = registry.list_links()
        reports = registry.list_deployment_reports()
        proposal = plan(
            registry, action, service_id="checkout", deployable_id=deployable
        )
        before = path.read_bytes()
        assert proposal.as_dict()["after"]["status"] == "retired"
        assert path.read_bytes() == before
        event = registry.apply_lifecycle_change(proposal)
        assert event["actor"] == "alice"
        assert registry.list_links() == links
        assert registry.list_deployment_reports() == reports
        assert len(registry.list_deployables()) == 2
        assert len(registry.list_services()) == 1
        observed = observe_registry_projects(snapshot(registry), projects, projects)
        assert [item.status.value for item in observed] == expected
        assert observed[0].owner is None
        assert (
            observe_registry_deployments(snapshot(registry), observed)[0].status.value
            == "unverified_link"
        )
        assert len(discover_project_candidates(registry, projects)) == (
            0 if deployable is None else 1
        )
        with pytest.raises(ValueError, match="retired"):
            registry.link_project(
                deployable=RegisteredDeployable("checkout", "web"),
                project_uuid="new",
                project_version="v2",
                reviewer="alice",
            )
        with pytest.raises(ValueError, match="retired"):
            registry.apply_lifecycle_change(proposal)
        if deployable is None:
            with pytest.raises(ValueError, match="retired"):
                registry.register_deployable(RegisteredDeployable("checkout", "new"))
    with AssetRegistry(path, read_only=True) as registry:
        assert registry.is_retired("checkout", "web")
        assert registry.list_lifecycle_events("checkout") == (event,)


def test_link_removal_failure_rolls_back_archive(tmp_path):
    path = tmp_path / "assets.sqlite3"
    populate(path)
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TRIGGER fail_delete BEFORE DELETE ON reviewed_project_links "
            "BEGIN SELECT RAISE(ABORT, 'remove failure'); END"
        )
    with AssetRegistry(path) as registry:
        request = plan(registry, LifecycleAction.REVOKE_LINK, project_uuid="web")
        with pytest.raises(sqlite3.IntegrityError, match="remove failure"):
            registry.apply_lifecycle_change(request)
        assert registry.list_lifecycle_events() == ()
        assert registry.linked_coordinates("web") == ("checkout/web", "v1")


def test_failed_v4_migration_preserves_old_schema(tmp_path, monkeypatch):
    path = tmp_path / "assets.sqlite3"
    populate(path)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE identifier_reviews")
        db.execute("DROP TABLE identifier_observations")
        db.execute("DROP TABLE poc_source_state")
        db.execute("DROP TABLE poc_observations")
        db.execute("DROP TABLE asset_lifecycle_events")
        db.execute("PRAGMA user_version = 4")
    with AssetRegistry(path) as registry:
        checks = 0

        def fail_after_creation():
            nonlocal checks
            checks += 1
            if checks == 2:
                raise ValueError("simulated post-migration failure")

        monkeypatch.setattr(registry, "check_integrity", fail_after_creation)
        with pytest.raises(ValueError, match="simulated"):
            registry.migrate()
        assert registry.schema_version == 4
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4
        assert (
            db.execute(
                "SELECT name FROM sqlite_master WHERE name='asset_lifecycle_events'"
            ).fetchall()
            == []
        )


def test_retired_asset_allows_later_stop_claim_without_reactivating_link(tmp_path):
    path = tmp_path / "assets.sqlite3"
    populate(path)
    with AssetRegistry(path) as registry:
        registry.apply_lifecycle_change(
            plan(registry, LifecycleAction.RETIRE_SERVICE, service_id="checkout")
        )
        old = registry.list_deployment_reports()[0]
        correction = registry.register_deployment(
            replace(
                old,
                report_id=None,
                deployment_status=DeploymentStatus.NOT_DEPLOYED,
                exposure_status=ExposureStatus.UNKNOWN,
                observed_at="2026-01-02T00:00:00Z",
                supersedes_report_id=old.report_id,
            )
        )
        assert correction.supersedes_report_id == old.report_id
        assert registry.is_retired("checkout") is True
        assert len(registry.list_deployment_reports()) == 2


def test_revoke_archive_reapprove_and_revoke_again(tmp_path):
    path = tmp_path / "assets.sqlite3"
    populate(path)
    with AssetRegistry(path) as registry:
        old = next(link for link in registry.list_links() if link.project_uuid == "web")
        request = plan(registry, LifecycleAction.REVOKE_LINK, project_uuid="web")
        event = registry.apply_lifecycle_change(request)
        assert registry.linked_uuid("checkout/web", "v1") is None
        assert registry.linked_coordinates("web") is None
        assert event["before"]["links"][0]["reviewed_at"] == old.reviewed_at
        projects = [DependencyTrackProject("web", "checkout/web", "v2")]
        assert (
            observe_registry_projects(snapshot(registry), projects, projects)[
                0
            ].status.value
            == "revoked"
        )
        with pytest.raises(ValueError, match="currently approved"):
            plan(registry, LifecycleAction.REVOKE_LINK, project_uuid="web")
        approved = approve_project_link(
            registry,
            projects,
            service_id="checkout",
            deployable_id="web",
            project_uuid="web",
            reviewer="bob",
        )
        assert approved.project_version == "v2"
        assert (
            observe_registry_projects(snapshot(registry), projects, projects)[
                0
            ].status.value
            == "matched"
        )
        assert registry.list_lifecycle_events("checkout") == (event,)
        registry.apply_lifecycle_change(
            plan(registry, LifecycleAction.REVOKE_LINK, project_uuid="web")
        )
        assert len(registry.list_lifecycle_events("checkout")) == 2


def test_stale_change_and_audit_failure_leave_current_link_intact(tmp_path):
    path = tmp_path / "assets.sqlite3"
    populate(path)
    with AssetRegistry(path) as registry:
        request = plan(registry, LifecycleAction.REVOKE_LINK, project_uuid="web")
        with pytest.raises(ValueError, match="changed since review"):
            registry.apply_lifecycle_change(
                replace(request, links=(replace(request.links[0], reviewer="stale"),))
            )
        with sqlite3.connect(path) as db:
            db.execute(
                "CREATE TRIGGER fail_audit BEFORE INSERT ON asset_lifecycle_events "
                "BEGIN SELECT RAISE(ABORT, 'audit failure'); END"
            )
        with pytest.raises(sqlite3.IntegrityError, match="audit failure"):
            registry.apply_lifecycle_change(request)
        assert registry.linked_coordinates("web") == ("checkout/web", "v1")
        assert registry.list_lifecycle_events() == ()


def test_v4_migration_preserves_update_history_and_backup(tmp_path):
    path = tmp_path / "assets.sqlite3"
    populate(path)
    with AssetRegistry(path) as registry:
        registry.update_service(
            plan_service_update(
                registry,
                service_id="checkout",
                owner="team-b",
                actor="bob",
                reason="transfer",
            )
        )
        history = registry.list_service_changes("checkout")
        links = registry.list_links()
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE identifier_reviews")
        db.execute("DROP TABLE identifier_observations")
        db.execute("DROP TABLE poc_source_state")
        db.execute("DROP TABLE poc_observations")
        db.execute("DROP TABLE asset_lifecycle_events")
        db.execute("PRAGMA user_version = 4")
    before = path.read_bytes()
    with AssetRegistry(path, read_only=True) as registry:
        assert registry.list_lifecycle_events() == ()
        assert registry.is_retired("checkout") is False
        plan(registry, LifecycleAction.RETIRE_SERVICE, service_id="checkout")
    assert path.read_bytes() == before
    with AssetRegistry(path) as registry:
        with pytest.raises(ValueError, match="migration"):
            registry.apply_lifecycle_change(
                plan(registry, LifecycleAction.RETIRE_SERVICE, service_id="checkout")
            )
        backup = registry.backup_to(tmp_path / "v4-backup.sqlite3")
        assert registry.migrate()
        assert registry.schema_version == 9
        assert registry.list_service_changes("checkout") == history
        assert registry.list_links() == links
    with AssetRegistry(backup, read_only=True) as registry:
        assert registry.schema_version == 4
        assert registry.list_service_changes("checkout") == history


def test_cli_preview_apply_and_history_never_contacts_dt(tmp_path, capsys, monkeypatch):
    path = tmp_path / "assets.sqlite3"
    populate(path)
    monkeypatch.setattr(
        cli, "_asset_dt_client", lambda: pytest.fail("unexpected DT access")
    )
    parser = cli.build_parser()
    args = [
        "assets",
        "--db",
        str(path),
        "revoke-link",
        "--project",
        "web",
        "--actor",
        "alice",
        "--reason",
        "wrong link",
    ]
    before = path.read_bytes()
    assert cli.run_assets(parser.parse_args(args)) == 0
    assert '"status": "preview"' in capsys.readouterr().out
    assert path.read_bytes() == before
    assert cli.run_assets(parser.parse_args([*args, "--apply"])) == 0
    assert json.loads(capsys.readouterr().out)["after"]["status"] == "revoked"
    assert (
        cli.run_assets(
            parser.parse_args(
                ["assets", "--db", str(path), "history", "--service", "checkout"]
            )
        )
        == 0
    )
    assert len(json.loads(capsys.readouterr().out)["lifecycle_events"]) == 1
