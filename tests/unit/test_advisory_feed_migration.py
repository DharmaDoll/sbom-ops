"""Shared database migration must preserve prior data and roll back atomically."""

import sqlite3
from pathlib import Path

import pytest

from sbom_ops.storage.advisory_feed import AdvisoryFeedStore
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.identifier_candidates import IdentifierStore
from sbom_ops.storage.lifecycle_evidence import LifecycleEvidenceStore
from sbom_ops.storage.poc import PocStore
from sbom_ops.storage.vulnrichment import VulnrichmentStore


def v11(path: Path) -> None:
    with AssetRegistry(path, create_if_missing=True) as registry:
        version = registry.schema_version
    with sqlite3.connect(path) as db:
        if version == 12:
            db.execute("DROP TABLE advisory_feed_revisions")
            db.execute("DROP TABLE advisory_poll_state")
        db.execute("PRAGMA user_version=11")
        db.execute("INSERT INTO services VALUES ('example', 'team', 'high', 'test')")
        db.execute(
            "INSERT INTO poc_source_state VALUES "
            "('fixture', 1, NULL, 'http_error', 503)"
        )


def test_v11_backup_migration_and_all_stores(tmp_path: Path) -> None:
    path, backup = tmp_path / "assets.db", tmp_path / "backup.db"
    v11(path)
    with sqlite3.connect(path) as db:
        original = list(db.iterdump())
    with AssetRegistry(path) as registry:
        assert registry.schema_version == 11
        registry.backup_to(backup)
        assert registry.migrate() is True
        assert registry.schema_version == 12
        assert registry.migrate() is False
        registry.check_integrity()
        snapshot, evidence = registry.evidence_snapshot(())
        assert len(snapshot.services) == 1
        assert evidence == {}
    with sqlite3.connect(backup) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 11
        assert list(db.iterdump()) == original
    with sqlite3.connect(path) as db:
        current = list(db.iterdump())
        assert all(row in current for row in original if row.startswith("INSERT INTO"))
    with (
        PocStore(path),
        IdentifierStore(path),
        VulnrichmentStore(path),
        LifecycleEvidenceStore(path),
        AdvisoryFeedStore(path) as store,
    ):
        assert store.history("fixture", "key") == ()
        assert store.poll_state("fixture") is None


def test_migration_failure_preserves_v11(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "assets.db"
    v11(path)
    with sqlite3.connect(path) as db:
        original = list(db.iterdump())
    with AssetRegistry(path) as registry:
        original_check = registry.check_integrity
        calls = 0

        def fail_after_schema() -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("synthetic post-migration failure")
            original_check()

        monkeypatch.setattr(registry, "check_integrity", fail_after_schema)
        with pytest.raises(ValueError, match="synthetic"):
            registry.migrate()
        assert registry.schema_version == 11
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 11
        assert list(db.iterdump()) == original


def test_new_registry_supports_advisory_storage(tmp_path: Path) -> None:
    path = tmp_path / "assets.db"
    with AssetRegistry(path, create_if_missing=True) as registry:
        assert registry.schema_version == 12
    with AdvisoryFeedStore(path, read_only=True) as store:
        assert store.history("fixture", "key") == ()
