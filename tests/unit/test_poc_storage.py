from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from sbom_ops import cli
from sbom_ops.domain.advisory import PocReportStatus, summarize_poc_reports
from sbom_ops.domain.asset_registry import RegisteredService
from sbom_ops.domain.assets import BusinessCriticality
from sbom_ops.domain.poc import PocFetchError, PocTargets
from sbom_ops.services.advisory_snapshot import load_advisory_snapshot
from sbom_ops.services.poc_refresh import collect_poc_snapshot
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.poc import PocStore
from sbom_ops.storage.poc_snapshot import save_poc_snapshot

NOW = datetime(2026, 10, 13, tzinfo=UTC)
CVE = "CVE-2026-10001"
TARGETS = PocTargets((CVE,), ())


class Source:
    source = "vulnerability-lookup:https://example.invalid"

    def __init__(self, count: int = 2, failure: Exception | None = None) -> None:
        self.count, self.failure = count, failure
        self.calls: list[str] = []

    def get_poc_sightings(self, cve: str) -> object:
        self.calls.append(cve)
        if self.failure:
            raise self.failure
        return {
            "metadata": {"count": self.count, "page": 1, "per_page": 1},
            "data": (
                [
                    {
                        "vulnerability": cve,
                        "type": "published-proof-of-concept",
                        "creation_timestamp": (NOW - timedelta(days=1)).isoformat(),
                    }
                ]
                if self.count
                else []
            ),
        }


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "assets.sqlite3"
    with AssetRegistry(path, create_if_missing=True) as registry:
        registry.register_service(
            RegisteredService("checkout", "payments", BusinessCriticality.HIGH, "sales")
        )
    return path


def collect(store, client, now=NOW, targets=TARGETS, **kwargs):
    return collect_poc_snapshot(
        targets,
        client,
        repository=store,
        clock=lambda: now,
        sleep=lambda _: None,
        **kwargs,
    )


def test_success_failure_recovery_retains_evidence_and_export(db_path, tmp_path):
    with PocStore(db_path) as store:
        collect(store, Source())
        success = store.get(CVE, Source.source).success
        later = NOW + timedelta(hours=1)
        result = collect(
            store, Source(failure=PocFetchError("http_error", status=429)), later
        )
        record = store.get(CVE, Source.source)
        assert record.success == success
        assert record.last_attempt_at == later.isoformat()
        assert record.error == "http_error" and record.http_status == 429
        assert result["collection"]["results"][0]["last_success_at"] == NOW.isoformat()
        observation = store.snapshot().vulnerability_observations[0]
        assert observation.record_count == 2
        assert observation.observed_at == NOW.isoformat()
        assert (
            summarize_poc_reports((observation,), now=later).status
            == PocReportStatus.UNKNOWN
        )
        output = tmp_path / "export.json"
        save_poc_snapshot(output, result)
        exported = load_advisory_snapshot(output).vulnerability_observations[0]
        assert exported.last_error == "http_error"
        assert exported.last_http_status == 429
        assert exported.record_count == 2
        assert (
            summarize_poc_reports((exported,), now=later).status
            == PocReportStatus.UNKNOWN
        )
        collect(store, Source(count=0), later + timedelta(minutes=1))
        record = store.get(CVE, Source.source)
        assert record.error is None
        assert record.success.record_count == 0
        assert (
            summarize_poc_reports(
                (record.observation(),), now=later + timedelta(minutes=1)
            ).status
            == PocReportStatus.NOT_OBSERVED
        )
    with AssetRegistry(db_path, read_only=True) as registry:
        assert registry.list_services()[0].owner == "payments"


def test_cache_interval_expiry_future_and_instance_isolation(db_path):
    with PocStore(db_path) as store:
        source = Source()
        collect(store, source)
        reused = collect(store, source, NOW + timedelta(minutes=59))
        assert reused["collection"]["results"][0]["cached"] is True
        assert len(source.calls) == 1
        collect(store, source, NOW + timedelta(hours=1))
        assert len(source.calls) == 2
        # TTL overrides a longer refresh interval.
        collect(store, source, NOW + timedelta(hours=7), refresh_seconds=86400)
        assert len(source.calls) == 3
        # Future cached observations must be rechecked, not accepted as fresh.
        collect(store, source, NOW + timedelta(hours=2))
        assert len(source.calls) == 4
        other = Source(count=0)
        other.source = "vulnerability-lookup:https://another.invalid"
        collect(store, other, NOW + timedelta(hours=2))
        assert len(other.calls) == 1
        assert len(store.snapshot().vulnerability_observations) == 2


def test_interruption_preserves_completed_cves_and_resume_skips_them(db_path):
    class Interrupted(Source):
        def get_poc_sightings(self, cve):
            if cve != CVE:
                raise KeyboardInterrupt
            return super().get_poc_sightings(cve)

    targets = PocTargets((CVE, "CVE-2026-10002"), ())
    with PocStore(db_path) as store:
        with pytest.raises(KeyboardInterrupt):
            collect(store, Interrupted(), targets=targets)
    with PocStore(db_path) as store:
        assert store.get(CVE, Source.source) is not None
        assert store.get("CVE-2026-10002", Source.source) is None
        resumed = Source()
        collect(store, resumed, targets=targets)
        assert resumed.calls == ["CVE-2026-10002"]


def test_first_failure_is_persistent_unknown_and_readonly_has_no_write(db_path):
    with PocStore(db_path) as store:
        collect(store, Source(failure=PocFetchError("transport_error")))
    before = db_path.read_bytes()
    with PocStore(db_path, read_only=True) as store:
        record = store.get(CVE, Source.source)
        assert record.success is None
        assert record.observation().record_count is None
        with pytest.raises(sqlite3.OperationalError):
            store.save(record)
    assert db_path.read_bytes() == before


def test_v5_requires_explicit_migration_and_backup_restores_old_schema(
    db_path, tmp_path
):
    with sqlite3.connect(db_path) as db:
        db.execute("DROP TABLE identifier_reviews")
        db.execute("DROP TABLE identifier_observations")
        db.execute("DROP TABLE poc_source_state")
        db.execute("DROP TABLE poc_observations")
        db.execute("PRAGMA user_version=5")
    before = db_path.read_bytes()
    with pytest.raises(ValueError, match="migrate"):
        PocStore(db_path)
    assert db_path.read_bytes() == before
    with AssetRegistry(db_path) as registry:
        original = registry.list_services()
        registry.backup_to(tmp_path / "v5.sqlite3")
        assert registry.migrate()
        assert registry.schema_version == 9
        assert registry.list_services() == original
    with AssetRegistry(tmp_path / "v5.sqlite3", read_only=True) as registry:
        assert registry.schema_version == 5
        assert registry.list_services() == original
    with PocStore(db_path) as store:
        assert store.snapshot().vulnerability_observations == ()


def test_poc_migration_failure_rolls_back_all_ddl(db_path, monkeypatch):
    with sqlite3.connect(db_path) as db:
        db.execute("DROP TABLE identifier_reviews")
        db.execute("DROP TABLE identifier_observations")
        db.execute("DROP TABLE poc_source_state")
        db.execute("DROP TABLE poc_observations")
        db.execute("PRAGMA user_version=5")
    with AssetRegistry(db_path) as registry:
        count = 0

        def fail():
            nonlocal count
            count += 1
            if count == 2:
                raise ValueError("simulated failure")

        monkeypatch.setattr(registry, "check_integrity", fail)
        with pytest.raises(ValueError, match="simulated"):
            registry.migrate()
    with sqlite3.connect(db_path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 5
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='poc_observations'"
        ).fetchall()


def test_shared_backup_contains_poc_and_assets(db_path, tmp_path):
    with PocStore(db_path) as store:
        collect(store, Source())
    backup = tmp_path / "backup.sqlite3"
    with AssetRegistry(db_path) as registry:
        registry.backup_to(backup)
    with PocStore(backup, read_only=True) as store:
        assert store.get(CVE, Source.source).success.record_count == 2
    with AssetRegistry(backup, read_only=True) as registry:
        assert registry.list_services()[0].owner == "payments"


def test_sync_automatically_reads_shared_poc_db_without_writes(
    db_path, monkeypatch, capsys
):
    with PocStore(db_path) as store:
        collect(store, Source())
    before = db_path.read_bytes()
    captured = {}

    def orchestrator(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            run=lambda: SimpleNamespace(as_dict=lambda: {"status": "succeeded"})
        )

    monkeypatch.setattr(cli, "Orchestrator", orchestrator)
    assert (
        cli.run_sync(
            SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None)),
            "json",
            asset_db_path=str(db_path),
        )
        == 0
    )
    observation = captured["advisory_snapshot"].observations_for(CVE)[0]
    assert observation.record_count == 2
    assert captured["asset_registry"].services[0].owner == "payments"
    assert db_path.read_bytes() == before
    assert json.loads(capsys.readouterr().out)["status"] == "succeeded"


def test_cli_stores_without_json_and_preview_does_not_create_db(
    tmp_path, monkeypatch, capsys
):
    source = Source()
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps({"status": "succeeded", "assessments": [{"vulnerability_id": CVE}]})
    )
    db = tmp_path / "state.sqlite3"
    args = ["sbom-ops", "poc-fetch", "--findings", str(findings), "--db", str(db)]
    monkeypatch.setattr("sys.argv", args)
    assert cli.main() == 0
    assert not db.exists()
    capsys.readouterr()
    monkeypatch.setattr(cli, "VulnerabilityLookupClient", lambda *a, **k: source)
    monkeypatch.setattr("sys.argv", args + ["--execute"])
    assert cli.main() == 0
    assert len(source.calls) == 1
    assert cli.main() == 0
    assert len(source.calls) == 1
    with PocStore(db, read_only=True) as store:
        assert store.get(CVE, source.source).success.record_count == 2
    assert {p.name for p in tmp_path.iterdir()} == {
        "findings.json",
        "state.sqlite3",
        "state.sqlite3.poc.lock",
    }


def test_sync_poc_db_failure_is_optional_not_a_dt_failure(
    tmp_path, monkeypatch, capsys
):
    from sbom_ops.domain.models import AnalysisSnapshotStatus
    from sbom_ops.services.orchestrator import RunResult

    class FakeOrchestrator:
        def __init__(self, **kwargs):
            assert "advisory_snapshot" not in kwargs

        def run(self):
            return RunResult(
                run_id="test",
                duration_seconds=0,
                kev_used_stale_cache=False,
                projects_processed=0,
                findings_processed=0,
                issues_created=0,
                issues_updated=0,
                issues_closed=0,
                dry_run=True,
                analysis_snapshot_status=AnalysisSnapshotStatus.NOT_REQUESTED,
            )

    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    assert (
        cli.run_sync(
            SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None)),
            "json",
            poc_db_path=str(tmp_path / "missing.sqlite3"),
        )
        == 0
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out)["advisory_snapshot_status"] == "invalid"
    assert "PoC DB ignored" in captured.err
    assert not (tmp_path / "missing.sqlite3").exists()
