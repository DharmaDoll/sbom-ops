from __future__ import annotations

import sqlite3

import pytest

from sbom_ops import cli
from sbom_ops.clients.dependency_track import DependencyTrackProject


class FakeClient:
    def list_projects(self) -> list[DependencyTrackProject]:
        return [DependencyTrackProject("uuid-1", "checkout-api/web", "build-123")]


class FakeChangedClient:
    def list_projects(self) -> list[DependencyTrackProject]:
        return [DependencyTrackProject("uuid-1", "checkout-api/web", "build-124")]


def test_asset_cli_registration_candidate_and_approval(tmp_path, monkeypatch, capsys):
    db_path = tmp_path / "assets.sqlite3"
    parser = cli.build_parser()
    monkeypatch.setattr(cli, "_asset_dt_client", FakeClient)

    def run(*tokens: str) -> str:
        args = parser.parse_args(["assets", "--db", str(db_path), *tokens])
        assert cli.run_assets(args) == 0
        return capsys.readouterr().out

    assert "registered service" in run(
        "register-service",
        "--service",
        "checkout-api",
        "--owner",
        "team-checkout",
        "--criticality",
        "high",
        "--reason",
        "handles checkout",
    )
    assert "checkout-api/web" in run(
        "register-deployable", "--service", "checkout-api", "--deployable", "web"
    )
    assert "status=candidate" in run("candidates")
    audit_args = parser.parse_args(["assets", "--db", str(db_path), "audit-links"])
    assert cli.run_assets(audit_args) == 1
    assert "no reviewed Project links" in capsys.readouterr().out
    assert "reviewed project=uuid-1" in run(
        "approve",
        "--service",
        "checkout-api",
        "--deployable",
        "web",
        "--project",
        "uuid-1",
        "--reviewer",
        "alice",
    )
    assert "status=reviewed" in run("candidates")
    assert "status=matched" in run("audit-links")
    monkeypatch.setattr(cli, "_asset_dt_client", FakeChangedClient)
    assert cli.run_assets(audit_args) == 1
    assert "status=identity_changed" in capsys.readouterr().out
    monkeypatch.setattr(cli, "_asset_dt_client", FakeClient)
    assert "link=uuid-1" in run("list")
    assert "deployment report=1" in run(
        "report-deployment",
        "--service",
        "checkout-api",
        "--deployable",
        "web",
        "--environment",
        "production",
        "--artifact",
        "build-123",
        "--status",
        "deployed",
        "--exposure",
        "confirmed",
        "--reviewer",
        "alice",
        "--evidence",
        "deployment record 123",
        "--observed-at",
        "2026-10-07T00:00:00Z",
        "--expires-at",
        "2026-10-08T00:00:00Z",
    )
    assert "deployment_report=1" in run("list")
    assert "integrity OK" in run("check")
    backup_path = tmp_path / "backup.sqlite3"
    assert "backup created" in run("backup", "--output", str(backup_path))
    assert backup_path.is_file()


def test_asset_cli_migrates_v1_after_backup(tmp_path, capsys) -> None:
    db_path = tmp_path / "assets.sqlite3"
    parser = cli.build_parser()
    service_args = parser.parse_args(
        [
            "assets",
            "--db",
            str(db_path),
            "register-service",
            "--service",
            "checkout-api",
            "--owner",
            "team-checkout",
            "--criticality",
            "high",
            "--reason",
            "payments",
        ]
    )
    cli.run_assets(service_args)
    with sqlite3.connect(db_path) as db:
        db.execute("DROP TABLE deployment_reports")
        db.execute("PRAGMA user_version = 1")
    backup_path = tmp_path / "backup-v1.sqlite3"
    migrate_args = parser.parse_args(
        ["assets", "--db", str(db_path), "migrate", "--backup", str(backup_path)]
    )
    assert cli.run_assets(migrate_args) == 0
    assert "upgraded to schema v2" in capsys.readouterr().out
    assert backup_path.is_file()
    with sqlite3.connect(backup_path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    with sqlite3.connect(db_path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2


def test_asset_cli_read_does_not_create_misspelled_db(tmp_path) -> None:
    db_path = tmp_path / "misspelled.sqlite3"
    args = cli.build_parser().parse_args(["assets", "--db", str(db_path), "list"])
    with pytest.raises(ValueError, match="does not exist"):
        cli.run_assets(args)
    assert not db_path.exists()
