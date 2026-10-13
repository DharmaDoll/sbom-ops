from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

from sbom_ops import cli
from sbom_ops.domain.asset_registry import RegisteredService, ServiceUpdate
from sbom_ops.domain.assets import BusinessCriticality
from sbom_ops.services.asset_updates import plan_service_update
from sbom_ops.storage.asset_registry import AssetRegistry


def register(path: Path) -> RegisteredService:
    service = RegisteredService(
        "checkout", "team-a", BusinessCriticality.HIGH, "payments"
    )
    with AssetRegistry(path, create_if_missing=True) as registry:
        registry.register_service(service)
    return service


def plan(registry: AssetRegistry, **kwargs) -> ServiceUpdate:
    return plan_service_update(
        registry,
        service_id="checkout",
        actor="alice",
        reason="team transfer",
        **kwargs,
    )


def test_update_is_durable_and_keeps_before_after_without_replacing_history(tmp_path):
    path = tmp_path / "assets.sqlite3"
    original = register(path)
    with AssetRegistry(path) as registry:
        first = registry.update_service(plan(registry, owner="team-b"))
        second = registry.update_service(
            plan(
                registry,
                criticality=BusinessCriticality.CRITICAL,
                impact_reason="checkout outage",
            )
        )
        assert (first.change_id, second.change_id) == (1, 2)
        assert (
            datetime.fromisoformat(first.changed_at.replace("Z", "+00:00")).utcoffset()
            is not None
        )
        assert first.update.before == original
        assert second.update.before == first.update.after
    with AssetRegistry(path, read_only=True) as registry:
        assert registry.list_service_changes("checkout") == (first, second)
        assert registry.get_service("checkout") == second.update.after
        assert second.as_dict()["after"]["criticality"] == "critical"
        assert first.update.reason == "team transfer"
        with pytest.raises(ValueError, match="read-only"):
            registry.update_service(plan(registry, owner="team-c"))


def test_stale_plan_cannot_overwrite_a_concurrent_update(tmp_path):
    path = tmp_path / "assets.sqlite3"
    register(path)
    with AssetRegistry(path) as registry:
        stale = plan(registry, owner="team-b")
        with AssetRegistry(path) as other:
            other.update_service(plan(other, owner="team-c"))
        with pytest.raises(ValueError, match="changed since review"):
            registry.update_service(stale)
        assert registry.get_service("checkout").owner == "team-c"
        assert len(registry.list_service_changes("checkout")) == 1


def test_history_write_failure_rolls_back_service_update(tmp_path):
    path = tmp_path / "assets.sqlite3"
    original = register(path)
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TRIGGER fail_audit BEFORE INSERT ON service_changes "
            "BEGIN SELECT RAISE(ABORT, 'simulated audit failure'); END"
        )
    with AssetRegistry(path) as registry:
        with pytest.raises(sqlite3.IntegrityError, match="simulated audit failure"):
            registry.update_service(plan(registry, owner="team-b"))
        assert registry.get_service("checkout") == original
        assert registry.list_service_changes("checkout") == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("actor", " "),
        ("reason", ""),
        ("actor", "x\ny"),
        ("reason", "x" * 1001),
    ],
)
def test_update_requires_usable_audit_context(field, value):
    before = RegisteredService(
        "checkout", "team-a", BusinessCriticality.HIGH, "payments"
    )
    data = {
        "before": before,
        "after": replace(before, owner="team-b"),
        "actor": "alice",
        "reason": "transfer",
    }
    data[field] = value
    with pytest.raises(ValueError, match="printable"):
        ServiceUpdate(**data)


def test_update_rejects_rename_noop_and_missing_service(tmp_path):
    path = tmp_path / "assets.sqlite3"
    original = register(path)
    with pytest.raises(ValueError, match="service_id"):
        ServiceUpdate(
            original, replace(original, service_id="other"), "alice", "rename"
        )
    with AssetRegistry(path, read_only=True) as registry:
        for kwargs in ({}, {"owner": " team-a "}):
            with pytest.raises(ValueError, match="no changes"):
                plan(registry, **kwargs)
        with pytest.raises(ValueError, match="not registered"):
            plan_service_update(
                registry, service_id="missing", actor="alice", reason="test"
            )
        with pytest.raises(ValueError, match="not registered"):
            registry.list_service_changes("missing")


def downgrade(path: Path, version: int) -> None:
    """Build a legacy fixture, never touch the operator's actual DB."""
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE poc_observations")
        db.execute("DROP TABLE asset_lifecycle_events")
        db.execute("DROP TABLE service_changes")
        if version < 3:
            db.execute("DROP TABLE deployment_report_supersessions")
        if version < 2:
            db.execute("DROP TABLE deployment_reports")
        db.execute(f"PRAGMA user_version = {version}")


@pytest.mark.parametrize("version", [1, 2, 3])
def test_legacy_read_preview_migration_backup_and_new_history(tmp_path, version):
    path = tmp_path / "assets.sqlite3"
    original = register(path)
    downgrade(path, version)
    before = path.read_bytes()
    with AssetRegistry(path, read_only=True) as registry:
        assert registry.schema_version == version
        assert registry.list_service_changes("checkout") == ()
        assert plan(registry, owner="team-b").before == original
    assert path.read_bytes() == before
    with AssetRegistry(path) as registry:
        with pytest.raises(ValueError, match="migration"):
            registry.update_service(plan(registry, owner="team-b"))
        backup = registry.backup_to(tmp_path / "before.sqlite3")
        assert registry.migrate() is True
        assert registry.migrate() is False
        assert registry.schema_version == 6
        registry.update_service(plan(registry, owner="team-b"))
    with AssetRegistry(backup, read_only=True) as registry:
        assert registry.schema_version == version
        assert registry.get_service("checkout") == original
    with AssetRegistry(path, read_only=True) as registry:
        assert registry.list_service_changes("checkout")[0].update.before == original


@pytest.mark.parametrize("version", [1, 2, 3])
def test_failed_migration_rolls_back_ddl_and_version(tmp_path, monkeypatch, version):
    path = tmp_path / "assets.sqlite3"
    register(path)
    downgrade(path, version)
    with AssetRegistry(path) as registry:
        check = registry.check_integrity
        calls = 0

        def fail_after_migration():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("simulated validation failure")
            check()

        monkeypatch.setattr(registry, "check_integrity", fail_after_migration)
        with pytest.raises(ValueError, match="simulated"):
            registry.migrate()
        assert registry.schema_version == version
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == version
        assert (
            db.execute(
                "SELECT name FROM sqlite_master WHERE name='service_changes'"
            ).fetchall()
            == []
        )
        if version == 1:
            assert (
                db.execute(
                    "SELECT name FROM sqlite_master WHERE name='deployment_reports'"
                ).fetchall()
                == []
            )


def test_cli_preview_apply_history_and_backup_failure(tmp_path, capsys):
    path = tmp_path / "assets.sqlite3"
    register(path)
    parser = cli.build_parser()

    def run(*tokens):
        return cli.run_assets(parser.parse_args(["assets", "--db", str(path), *tokens]))

    change = (
        "update-service",
        "--service",
        "checkout",
        "--owner",
        "team-b",
        "--actor",
        "alice",
        "--reason",
        "team transfer",
    )
    before = path.read_bytes()
    assert run(*change) == 0
    output = capsys.readouterr().out
    assert '"status": "preview"' in output and "--apply" in output
    assert path.read_bytes() == before
    assert run(*change, "--apply") == 0
    assert json.loads(capsys.readouterr().out)["status"] == "applied"
    assert run("history", "--service", "checkout") == 0
    history = json.loads(capsys.readouterr().out)
    assert history["changes"][0]["after"]["owner"] == "team-b"
    downgrade(path, 3)
    backup = tmp_path / "existing.sqlite3"
    with AssetRegistry(path) as registry:
        registry.backup_to(backup)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        run("migrate", "--backup", str(backup))
    assert path.read_bytes() == before
