import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sbom_ops.domain.vulnrichment import VulnrichmentError
from sbom_ops.domain.vulnrichment_snapshot import VulnrichmentSnapshot
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.identifier_candidates import IdentifierStore
from sbom_ops.storage.poc import PocStore
from sbom_ops.storage.vulnrichment import VulnrichmentStore


def test_new_registry_has_cisa_storage_schema(tmp_path: Path) -> None:
    with AssetRegistry(tmp_path / "assets.db", create_if_missing=True) as registry:
        assert registry.schema_version == 11


def snapshot() -> VulnrichmentSnapshot:
    return VulnrichmentSnapshot.capture(
        json.loads(
            (
                Path(__file__).parents[1] / "fixtures/vulnrichment_synthetic.json"
            ).read_text()
        ),
        cve="CVE-2026-0001",
        revision="a" * 40,
        retrieved_at=datetime(2026, 10, 23, tzinfo=UTC),
        max_age=timedelta(hours=1),
    )


@pytest.fixture
def path(tmp_path: Path) -> Path:
    path = tmp_path / "assets.db"
    with AssetRegistry(path, create_if_missing=True):
        pass
    return path


def test_append_and_roundtrip_keep_original_evidence(path: Path) -> None:
    original = snapshot()
    updated = replace(original, revision="b" * 40)
    with VulnrichmentStore(path) as store:
        first = store.save(original)
        second = store.save(updated)
        third = store.save(original)
        assert first < second < third
    before = path.read_bytes()
    with VulnrichmentStore(path, read_only=True) as store:
        for key, expected in [(first, original), (second, updated), (third, original)]:
            actual = store.get(key, cve=expected.cve, revision=expected.revision)
            assert actual.report() == expected.report()
        assert store.get(999, cve=original.cve, revision=original.revision) is None
        with pytest.raises(sqlite3.OperationalError):
            store.save(original)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "field,value", [("cve", "CVE-2026-0002"), ("revision", "b" * 40)]
)
def test_wrong_target_is_rejected(path: Path, field: str, value: str) -> None:
    original = snapshot()
    target = {"cve": original.cve, "revision": original.revision}
    target[field] = value
    with VulnrichmentStore(path) as store:
        key = store.save(original)
        with pytest.raises(ValueError, match="target mismatch"):
            store.get(key, **target)


@pytest.mark.parametrize("key", [True, 0, -1, "1", 2**63])
def test_invalid_record_id_is_rejected(path: Path, key: object) -> None:
    with VulnrichmentStore(path) as store:
        with pytest.raises(ValueError, match="positive integer"):
            store.get(key, cve=snapshot().cve, revision=snapshot().revision)


def test_corrupted_payload_is_not_silently_missing(path: Path) -> None:
    original = snapshot()
    with VulnrichmentStore(path) as store:
        key = store.save(original)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE vulnrichment_snapshots SET snapshot_json='{}'")
    with VulnrichmentStore(path, read_only=True) as store:
        with pytest.raises(VulnrichmentError):
            store.get(key, cve=original.cve, revision=original.revision)


def test_index_payload_mismatch_is_rejected(path: Path) -> None:
    original = snapshot()
    with VulnrichmentStore(path) as store:
        key = store.save(original)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE vulnrichment_snapshots SET revision=?", ("b" * 40,))
    with VulnrichmentStore(path, read_only=True) as store:
        with pytest.raises(ValueError, match="index and payload mismatch"):
            store.get(key, cve=original.cve, revision="b" * 40)


def make_v9(path: Path) -> None:
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE lifecycle_evidence")
        db.execute("DROP TABLE vulnrichment_snapshots")
        db.execute("PRAGMA user_version=9")


def test_v9_requires_explicit_migration_and_backup(path: Path, tmp_path: Path) -> None:
    make_v9(path)
    # Seed existing independent tables and verify their rows survive migration.
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO services VALUES ('shop', 'team', 'high', 'sales')")
        db.execute(
            "INSERT INTO poc_source_state VALUES "
            "('fixture', 1, NULL, 'http_error', 503)"
        )
        db.execute(
            "INSERT INTO identifier_observations VALUES "
            "(1, 'GHSA-fixture', 'fixture', '2026-10-23T00:00:00Z', '{}')"
        )
        db.execute(
            "INSERT INTO identifier_reviews VALUES "
            "(1, 1, 'GHSA-fixture', 'GITHUB', 'CVE-2026-0001', 'revoke', "
            "'operator', 'fixture', '2026-10-23T00:00:00Z', NULL)"
        )
        before = list(db.iterdump())
    unchanged = path.read_bytes()
    with pytest.raises(ValueError, match="v10"):
        VulnrichmentStore(path)
    assert path.read_bytes() == unchanged
    backup = tmp_path / "v9.db"
    with AssetRegistry(path) as registry:
        registry.backup_to(backup)
        assert registry.migrate()
        assert not registry.migrate()
    with sqlite3.connect(backup) as db:
        assert list(db.iterdump()) == before
    with sqlite3.connect(path) as db:
        after = list(db.iterdump())
        assert all(line in after for line in before if line.startswith("INSERT INTO"))
    with AssetRegistry(backup, read_only=True) as registry:
        assert registry.schema_version == 9
    with PocStore(path) as store:
        assert store.source_state("fixture").failures == 1
    with IdentifierStore(path) as store:
        assert store.recent()[0]["observation_id"] == 1
        assert len(store.reviews()) == 1
    with VulnrichmentStore(path) as store:
        assert store.save(snapshot()) == 1


def test_v9_migration_failure_rolls_back(path: Path, monkeypatch) -> None:
    make_v9(path)
    with AssetRegistry(path) as registry:
        original = registry.check_integrity
        calls = 0

        def fail_after_ddl() -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("simulated failure")
            original()

        monkeypatch.setattr(registry, "check_integrity", fail_after_ddl)
        with pytest.raises(ValueError, match="simulated"):
            registry.migrate()
        assert registry.schema_version == 9
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 9
        assert (
            db.execute(
                "SELECT name FROM sqlite_master WHERE name='vulnrichment_snapshots'"
            ).fetchone()
            is None
        )


def test_backup_includes_cisa_evidence(path: Path, tmp_path: Path) -> None:
    original = snapshot()
    with VulnrichmentStore(path) as store:
        key = store.save(original)
    backup = tmp_path / "backup.db"
    with AssetRegistry(path) as registry:
        registry.backup_to(backup)
    with VulnrichmentStore(backup, read_only=True) as store:
        assert (
            store.get(key, cve=original.cve, revision=original.revision).report()
            == original.report()
        )


def test_missing_database_is_not_created(tmp_path: Path) -> None:
    path = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        VulnrichmentStore(path)
    assert not path.exists()
