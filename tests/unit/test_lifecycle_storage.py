import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sbom_ops.domain.lifecycle_evidence import LifecycleEvidence
from sbom_ops.storage import lifecycle_evidence
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.identifier_candidates import IdentifierStore
from sbom_ops.storage.poc import PocStore
from sbom_ops.storage.vulnrichment import VulnrichmentStore


@pytest.fixture
def evidence_db(tmp_path: Path) -> Path:
    path = tmp_path / "evidence.db"
    with AssetRegistry(path, create_if_missing=True):
        pass
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO services VALUES ('shop', 'team', 'high', 'sales')")
        db.execute("INSERT INTO deployables VALUES ('shop', 'api', 'shop-api')")
    return path


def evidence() -> LifecycleEvidence:
    return LifecycleEvidence(
        "shop", "api", "build", "boms/a.json", "operator", artifact_id="build-a"
    )


def test_append_read_and_correction_preserve_history(evidence_db: Path) -> None:
    with lifecycle_evidence.LifecycleEvidenceStore(evidence_db) as store:
        before = datetime.now(UTC)
        first = store.append(evidence())
        independent = store.append(evidence())
        corrected = store.append(
            replace(
                evidence(),
                supersedes_id=first.record_id,
                reason="SBOM訂正",
                sbom_ref="boms/b.json",
            )
        )
        assert before <= first.recorded_at <= datetime.now(UTC)
        assert first.evidence == evidence()
        assert corrected.evidence.supersedes_id == first.record_id
    with lifecycle_evidence.LifecycleEvidenceStore(
        evidence_db, read_only=True
    ) as store:
        assert store.list_records("shop", "api") == (first, independent, corrected)
        with pytest.raises(ValueError, match="read-only"):
            store.append(evidence())


@pytest.mark.parametrize("failure", ["missing", "fork", "target", "asset"])
def test_rejected_append_leaves_history_unchanged(
    evidence_db: Path, failure: str
) -> None:
    with lifecycle_evidence.LifecycleEvidenceStore(evidence_db) as store:
        first = store.append(evidence())
        item = replace(evidence(), supersedes_id=first.record_id, reason="correction")
        if failure == "missing":
            item = replace(item, supersedes_id=999)
        elif failure == "fork":
            store.append(item)
        elif failure == "target":
            item = replace(item, artifact_id="build-b")
        else:
            item = replace(evidence(), deployable_id="missing")
        original = store.list_records("shop", "api")
        with pytest.raises(ValueError):
            store.append(item)
        assert store.list_records("shop", "api") == original


def test_read_rejects_index_payload_mismatch(evidence_db: Path) -> None:
    with lifecycle_evidence.LifecycleEvidenceStore(evidence_db) as store:
        store.append(evidence())
    with sqlite3.connect(evidence_db) as db:
        db.execute("UPDATE lifecycle_evidence SET kind='unknown'")
    with lifecycle_evidence.LifecycleEvidenceStore(
        evidence_db, read_only=True
    ) as store:
        with pytest.raises(ValueError, match="inconsistent"):
            store.list_records("shop", "api")


@pytest.mark.parametrize("action", ["retire_service", "retire_deployable"])
def test_retired_asset_rejects_new_evidence(evidence_db: Path, action: str) -> None:
    with sqlite3.connect(evidence_db) as db:
        db.execute(
            "INSERT INTO asset_lifecycle_events "
            "(action,service_id,deployable_id,actor,reason,changed_at,"
            "before_json,after_json) VALUES (?,?,?,?,?,?,?,?)",
            (
                action,
                "shop",
                "api",
                "operator",
                "retired",
                "2026-10-25T00:00:00Z",
                "{}",
                "{}",
            ),
        )
    with lifecycle_evidence.LifecycleEvidenceStore(evidence_db) as store:
        with pytest.raises(ValueError, match="retired"):
            store.append(evidence())
        assert store.list_records("shop", "api") == ()


def test_insert_failure_rolls_back_correction(evidence_db: Path) -> None:
    with lifecycle_evidence.LifecycleEvidenceStore(evidence_db) as store:
        first = store.append(evidence())
        with sqlite3.connect(evidence_db) as db:
            db.execute(
                "CREATE TRIGGER fail_append AFTER INSERT ON lifecycle_evidence "
                "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"
            )
        with pytest.raises(sqlite3.IntegrityError, match="synthetic failure"):
            store.append(
                replace(evidence(), supersedes_id=first.record_id, reason="correction")
            )
        assert store.list_records("shop", "api") == (first,)


@pytest.mark.parametrize("version", [0, 10, 13])
def test_store_rejects_unsupported_schema(evidence_db: Path, version: int) -> None:
    with sqlite3.connect(evidence_db) as db:
        db.execute(f"PRAGMA user_version={version}")
    with pytest.raises(ValueError, match="schema v11"):
        lifecycle_evidence.LifecycleEvidenceStore(evidence_db)


def test_store_does_not_create_missing_db(tmp_path: Path) -> None:
    path = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        lifecycle_evidence.LifecycleEvidenceStore(path)
    assert not path.exists()


@pytest.mark.parametrize("corruption", ["missing", "target"])
def test_read_rejects_broken_correction_relationship(
    evidence_db: Path, corruption: str
) -> None:
    with lifecycle_evidence.LifecycleEvidenceStore(evidence_db) as store:
        first = store.append(evidence())
        correction = store.append(
            replace(evidence(), supersedes_id=first.record_id, reason="correction")
        )
    with sqlite3.connect(evidence_db) as db:
        if corruption == "missing":
            db.execute(
                "DELETE FROM lifecycle_evidence WHERE record_id=?", (first.record_id,)
            )
        else:
            raw = db.execute(
                "SELECT evidence_json FROM lifecycle_evidence " "WHERE record_id=?",
                (correction.record_id,),
            ).fetchone()[0]
            payload = json.loads(raw)
            payload["artifact_id"] = "different-build"
            db.execute(
                "UPDATE lifecycle_evidence SET evidence_json=? WHERE record_id=?",
                (json.dumps(payload), correction.record_id),
            )
    with lifecycle_evidence.LifecycleEvidenceStore(
        evidence_db, read_only=True
    ) as store:
        with pytest.raises(ValueError):
            store.list_records("shop", "api")


def test_concurrent_corrections_allow_only_one_successor(evidence_db: Path) -> None:
    with lifecycle_evidence.LifecycleEvidenceStore(evidence_db) as store:
        first = store.append(evidence())
    correction = replace(evidence(), supersedes_id=first.record_id, reason="correction")

    def attempt() -> bool:
        with lifecycle_evidence.LifecycleEvidenceStore(evidence_db) as store:
            try:
                store.append(correction)
            except ValueError as exc:
                assert "already superseded" in str(exc)
                return False
            return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt) for _ in range(2)]
        assert sorted(f.result() for f in futures) == [False, True]
    with lifecycle_evidence.LifecycleEvidenceStore(evidence_db) as store:
        history = store.list_records("shop", "api")
        assert len(history) == 2
        assert history[0] == first
        assert history[1].evidence == correction


def make_v10(path: Path) -> None:
    with AssetRegistry(path, create_if_missing=True) as registry:
        version = registry.schema_version
    with sqlite3.connect(path) as db:
        if version == 12:
            db.execute("DROP TABLE advisory_feed_revisions")
            db.execute("DROP TABLE advisory_poll_state")
        if version in (11, 12):
            db.execute("DROP TABLE lifecycle_evidence")
        db.execute("PRAGMA user_version=10")
        db.execute("INSERT INTO services VALUES ('shop', 'team', 'high', 'sales')")
        db.execute(
            "INSERT INTO poc_source_state "
            "VALUES ('fixture', 1, NULL, 'http_error', 503)"
        )


def test_v10_migration_keeps_rows_and_backup(tmp_path: Path) -> None:
    path, backup = tmp_path / "assets.db", tmp_path / "backup.db"
    make_v10(path)
    with sqlite3.connect(path) as db:
        original = list(db.iterdump())
    with AssetRegistry(path) as registry:
        assert registry.schema_version == 10
        registry.backup_to(backup)
        assert registry.migrate()
        assert registry.schema_version == 12
        assert not registry.migrate()
    with sqlite3.connect(backup) as db:
        assert list(db.iterdump()) == original
    with sqlite3.connect(path) as db:
        updated = list(db.iterdump())
        assert all(row in updated for row in original if row.startswith("INSERT INTO"))
        assert db.execute("SELECT count(*) FROM lifecycle_evidence").fetchone()[0] == 0
    with PocStore(path), IdentifierStore(path), VulnrichmentStore(path):
        pass


def test_failed_v10_migration_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "assets.db"
    make_v10(path)
    with AssetRegistry(path) as registry:
        original_check = registry.check_integrity
        calls = 0

        def fail_after_schema() -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("synthetic integrity failure")
            original_check()

        monkeypatch.setattr(registry, "check_integrity", fail_after_schema)
        with pytest.raises(ValueError, match="synthetic"):
            registry.migrate()
        assert registry.schema_version == 10
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 10
        assert (
            db.execute(
                "SELECT name FROM sqlite_master WHERE name='lifecycle_evidence'"
            ).fetchone()
            is None
        )


def test_fresh_database_has_empty_evidence_table(tmp_path: Path) -> None:
    path = tmp_path / "assets.db"
    with AssetRegistry(path, create_if_missing=True) as registry:
        assert registry.schema_version == 12
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM lifecycle_evidence").fetchone()[0] == 0


def test_snapshot_failure_releases_read_transaction(evidence_db: Path) -> None:
    with lifecycle_evidence.LifecycleEvidenceStore(evidence_db) as store:
        first = store.append(evidence())
    with sqlite3.connect(evidence_db) as db:
        original = db.execute(
            "SELECT evidence_json FROM lifecycle_evidence"
        ).fetchone()[0]
        db.execute("UPDATE lifecycle_evidence SET evidence_json='{}'")
    with AssetRegistry(evidence_db, read_only=True) as registry:
        with pytest.raises(ValueError):
            registry.evidence_snapshot((("shop", "api"),))
        with sqlite3.connect(evidence_db, timeout=0.1) as db:
            db.execute("UPDATE lifecycle_evidence SET evidence_json=?", (original,))
        _, histories = registry.evidence_snapshot((("shop", "api"),))
        assert histories[("shop", "api")] == (first,)
