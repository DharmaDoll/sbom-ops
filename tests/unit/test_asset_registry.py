from __future__ import annotations

import sqlite3
import stat
from pathlib import Path

import pytest

from sbom_ops.clients.dependency_track import DependencyTrackProject
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    ProjectLinkAuditStatus,
    RegisteredDeployable,
    RegisteredService,
    RegistryProjectStatus,
)
from sbom_ops.domain.assets import BusinessCriticality
from sbom_ops.services.asset_registry import (
    approve_project_link,
    audit_reviewed_project_links,
    discover_project_candidates,
    observe_registry_projects,
)
from sbom_ops.storage.asset_registry import AssetRegistry


def _register(registry: AssetRegistry) -> RegisteredDeployable:
    registry.register_service(
        RegisteredService(
            "checkout-api", "team-checkout", BusinessCriticality.HIGH, "payments"
        )
    )
    deployable = RegisteredDeployable("checkout-api", "web")
    registry.register_deployable(deployable)
    return deployable


def test_registration_and_explicit_review(tmp_path) -> None:
    db_path = tmp_path / "assets.sqlite3"
    with AssetRegistry(db_path, create_if_missing=True) as registry:
        deployable = _register(registry)
        projects = [DependencyTrackProject("uuid-1", deployable.project_name, "v1")]
        assert discover_project_candidates(registry, projects)[0].status == "candidate"
        link = approve_project_link(
            registry,
            projects,
            service_id=deployable.service_id,
            deployable_id=deployable.deployable_id,
            project_uuid="uuid-1",
            reviewer="alice",
        )
        assert link.project_version == "v1"
        assert link.reviewer == "alice"
        assert discover_project_candidates(registry, projects)[0].status == "reviewed"
    with AssetRegistry(db_path) as reopened:
        assert reopened.linked_uuid("checkout-api/web", "v1") == "uuid-1"
        assert reopened.list_services()[0].owner == "team-checkout"
        assert reopened.list_links()[0].reviewer == "alice"
        replacement = [DependencyTrackProject("uuid-2", "checkout-api/web", "v1")]
        assert (
            discover_project_candidates(reopened, replacement)[0].status == "conflict"
        )
        repurposed = [DependencyTrackProject("uuid-1", "checkout-api/web", "v2")]
        assert discover_project_candidates(reopened, repurposed)[0].status == "conflict"
        with pytest.raises(ValueError, match="already reviewed"):
            approve_project_link(
                reopened,
                replacement,
                service_id="checkout-api",
                deployable_id="web",
                project_uuid="uuid-2",
                reviewer="bob",
            )


def test_missing_or_ambiguous_project_cannot_be_approved(tmp_path) -> None:
    with AssetRegistry(tmp_path / "assets.sqlite3", create_if_missing=True) as registry:
        _register(registry)
        for projects in (
            [DependencyTrackProject("uuid-1", "other/web", "v1")],
            [DependencyTrackProject("uuid-1", "checkout-api/web", None)],
            [DependencyTrackProject("uuid-1", "checkout-api/web", " ")],
            [
                DependencyTrackProject("uuid-1", "checkout-api/web", "v1"),
                DependencyTrackProject("uuid-2", "checkout-api/web", "v1"),
            ],
        ):
            with pytest.raises(ValueError):
                approve_project_link(
                    registry,
                    projects,
                    service_id="checkout-api",
                    deployable_id="web",
                    project_uuid="uuid-1",
                    reviewer="alice",
                )
        assert all(
            item.status == "conflict"
            for item in discover_project_candidates(registry, projects)
        )


def test_duplicate_registration_does_not_overwrite(tmp_path) -> None:
    with AssetRegistry(tmp_path / "assets.sqlite3", create_if_missing=True) as registry:
        deployable = _register(registry)
        with pytest.raises(ValueError, match="already registered"):
            registry.register_service(
                RegisteredService(
                    "checkout-api", "other-team", BusinessCriticality.STANDARD, "test"
                )
            )
        with pytest.raises(ValueError, match="already registered"):
            registry.register_deployable(deployable)
        assert registry.list_services()[0].owner == "team-checkout"


def test_unknown_schema_is_rejected(tmp_path) -> None:
    db_path = tmp_path / "assets.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.execute("PRAGMA user_version = 2")
    with pytest.raises(ValueError, match="unsupported"):
        AssetRegistry(db_path)


def test_invalid_identifier_is_rejected() -> None:
    with pytest.raises(ValueError, match="lowercase"):
        RegisteredDeployable("Checkout API", "web")


def test_read_does_not_create_missing_asset_db(tmp_path) -> None:
    path = tmp_path / "typo.sqlite3"
    with pytest.raises(ValueError, match="does not exist"):
        AssetRegistry(path)
    assert not path.exists()


def test_new_asset_db_is_private(tmp_path) -> None:
    path = tmp_path / "assets.sqlite3"
    with AssetRegistry(path, create_if_missing=True):
        pass
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_registry_can_be_opened_read_only_without_creating_a_db(tmp_path) -> None:
    path = tmp_path / "assets.sqlite3"
    with AssetRegistry(path, create_if_missing=True) as registry:
        _register(registry)
    with AssetRegistry(path, read_only=True) as registry:
        registry.check_integrity()
        assert registry.list_services()[0].owner == "team-checkout"
        with pytest.raises(sqlite3.OperationalError, match="readonly database"):
            registry.register_service(
                RegisteredService(
                    "other-service", "other-team", BusinessCriticality.STANDARD, "test"
                )
            )
    with pytest.raises(ValueError, match="does not exist"):
        AssetRegistry(tmp_path / "missing.sqlite3", read_only=True)


def test_registry_observation_only_trusts_matching_reviewed_identity(tmp_path) -> None:
    with AssetRegistry(tmp_path / "assets.sqlite3", create_if_missing=True) as registry:
        deployable = _register(registry)
        approved = DependencyTrackProject("uuid-1", deployable.project_name, "v1")
        approve_project_link(
            registry,
            [approved],
            service_id=deployable.service_id,
            deployable_id=deployable.deployable_id,
            project_uuid=approved.uuid,
            reviewer="alice",
        )
        snapshot = AssetRegistrySnapshot(
            services=registry.list_services(), links=registry.list_links()
        )

    unlinked = DependencyTrackProject("uuid-2", "other/web", "v1")
    observations = observe_registry_projects(
        snapshot, [approved, unlinked], [approved, unlinked]
    )
    assert [item.status for item in observations] == [
        RegistryProjectStatus.MATCHED,
        RegistryProjectStatus.UNLINKED,
    ]
    assert observations[0].as_dict()["service_id"] == "checkout-api"
    assert observations[0].as_dict()["owner"] == "team-checkout"
    assert observations[0].as_dict()["criticality"] == "high"
    assert observations[1].service_id is None

    changed = DependencyTrackProject("uuid-1", "checkout-api/web", "v2")
    result = observe_registry_projects(snapshot, [changed], [changed])[0]
    assert result.status is RegistryProjectStatus.IDENTITY_CHANGED
    assert result.reviewed_version == "v1"
    assert result.service_id is None
    assert result.owner is None
    assert result.criticality is None

    duplicate = DependencyTrackProject("uuid-2", "checkout-api/web", "v1")
    result = observe_registry_projects(snapshot, [approved, duplicate], [approved])[0]
    assert result.status is RegistryProjectStatus.AMBIGUOUS
    assert result.service_id is None


def test_backup_is_checked_and_does_not_overwrite(tmp_path) -> None:
    db_path = tmp_path / "assets.sqlite3"
    backup_path = tmp_path / "backup.sqlite3"
    with AssetRegistry(db_path, create_if_missing=True) as registry:
        _register(registry)
        registry.check_integrity()
        assert registry.backup_to(backup_path) == backup_path
        with pytest.raises(ValueError, match="already exists"):
            registry.backup_to(backup_path)
        registry.register_service(
            RegisteredService(
                "later-service", "later-team", BusinessCriticality.STANDARD, "later"
            )
        )
    with AssetRegistry(backup_path) as backup:
        backup.check_integrity()
        assert [item.service_id for item in backup.list_services()] == ["checkout-api"]


@pytest.mark.parametrize(
    ("current_projects", "expected_status"),
    [
        (
            [DependencyTrackProject("uuid-1", "checkout-api/web", "v1")],
            ProjectLinkAuditStatus.MATCHED,
        ),
        ([], ProjectLinkAuditStatus.NOT_VISIBLE),
        (
            [DependencyTrackProject("uuid-1", "checkout-api/web", "v2")],
            ProjectLinkAuditStatus.IDENTITY_CHANGED,
        ),
        (
            [DependencyTrackProject("uuid-1", "renamed/web", "v1")],
            ProjectLinkAuditStatus.IDENTITY_CHANGED,
        ),
        (
            [
                DependencyTrackProject("uuid-1", "checkout-api/web", "v1"),
                DependencyTrackProject("uuid-2", "checkout-api/web", "v1"),
            ],
            ProjectLinkAuditStatus.AMBIGUOUS,
        ),
        (
            [
                DependencyTrackProject("uuid-1", "checkout-api/web", "v1"),
                DependencyTrackProject("uuid-1", "checkout-api/web", "v1"),
            ],
            ProjectLinkAuditStatus.AMBIGUOUS,
        ),
    ],
)
def test_audit_reviewed_link_detects_visibility_and_identity_changes(
    tmp_path: Path,
    current_projects: list[DependencyTrackProject],
    expected_status: ProjectLinkAuditStatus,
) -> None:
    with AssetRegistry(tmp_path / "assets.sqlite3", create_if_missing=True) as registry:
        _register(registry)
        approved = [DependencyTrackProject("uuid-1", "checkout-api/web", "v1")]
        approve_project_link(
            registry,
            approved,
            service_id="checkout-api",
            deployable_id="web",
            project_uuid="uuid-1",
            reviewer="alice",
        )
        result = audit_reviewed_project_links(registry, current_projects)
        assert len(result) == 1
        assert result[0].status is expected_status
        assert result[0].link.reviewer == "alice"
        assert len(registry.list_links()) == 1
