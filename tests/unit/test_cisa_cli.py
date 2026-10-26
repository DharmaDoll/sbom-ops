import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sbom_ops import cisa_cli, cli
from sbom_ops.domain.vulnrichment import VulnrichmentError
from sbom_ops.storage.asset_registry import AssetRegistry


@pytest.fixture
def source(monkeypatch):
    calls = []

    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 23, tzinfo=UTC)

    monkeypatch.setattr(cisa_cli, "datetime", FixedClock)

    class Source:
        def get_record(self, cve: str, revision: str) -> object:
            calls.append((cve, revision))
            return json.loads(
                (
                    Path(__file__).parents[1] / "fixtures/vulnrichment_synthetic.json"
                ).read_text()
            )

    monkeypatch.setattr(cisa_cli, "VulnrichmentClient", Source)
    return calls


def invoke(monkeypatch, path: Path, action: str, *options: str) -> int:
    monkeypatch.setattr(
        "sys.argv",
        [
            "sbom-ops",
            "cisa",
            action,
            "--db",
            str(path),
            "--cve",
            "CVE-2026-0001",
            "--revision",
            "a" * 40,
            *options,
        ],
    )
    return cli.main()


def test_preview_does_not_create_database(
    tmp_path: Path, monkeypatch, capsys, source
) -> None:
    path = tmp_path / "missing" / "assets.db"
    monkeypatch.setattr(
        "sys.argv",
        [
            "sbom-ops",
            "cisa",
            "fetch",
            "--db",
            str(path),
            "--cve",
            "CVE-2026-0001",
            "--revision",
            "a" * 40,
            "--max-age-hours",
            "24",
        ],
    )
    assert cli.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "preview"
    assert output["revision"] == "a" * 40
    assert not path.parent.exists()
    assert source == []


def test_execute_and_read_only_show(
    tmp_path: Path, monkeypatch, capsys, source
) -> None:
    path = tmp_path / "assets.db"
    assert invoke(monkeypatch, path, "fetch", "--max-age-hours", "1", "--execute") == 0
    saved = json.loads(capsys.readouterr().out)
    assert saved["status"] == "saved"
    assert saved["snapshot_id"] == 1
    assert saved["latest_verified"] is False
    assert saved["exploitation"] == "poc"
    assert saved["assessed_at"] == "2026-10-21T12:00:00+00:00"
    assert all(
        o["expires_at"] == "2026-10-21T13:00:00+00:00" for o in saved["observations"]
    )
    before = path.read_bytes()
    assert invoke(monkeypatch, path, "show", "--snapshot", "1") == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["status"] == "stored"
    assert shown["observations"] == saved["observations"]
    assert shown["retrieved_at"] == saved["retrieved_at"]
    assert path.read_bytes() == before
    assert source == [("CVE-2026-0001", "a" * 40)]


@pytest.mark.parametrize("hours", ["0", "-1", "9999999999999999999999"])
def test_invalid_duration_has_no_effect(
    tmp_path: Path, monkeypatch, capsys, source, hours: str
) -> None:
    path = tmp_path / "assets.db"
    assert (
        invoke(monkeypatch, path, "fetch", "--max-age-hours", hours, "--execute") == 2
    )
    assert not path.exists()
    assert not capsys.readouterr().out
    assert source == []


def test_old_db_not_migrated_or_queried(
    tmp_path: Path, monkeypatch, capsys, source
) -> None:
    path = tmp_path / "assets.db"
    with AssetRegistry(path, create_if_missing=True):
        pass
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE lifecycle_evidence")
        db.execute("DROP TABLE vulnrichment_snapshots")
        db.execute("PRAGMA user_version=9")
    before = path.read_bytes()
    assert invoke(monkeypatch, path, "fetch", "--max-age-hours", "1", "--execute") == 2
    assert "back up and migrate" in capsys.readouterr().err
    assert source == []
    assert path.read_bytes() == before


def test_failed_refresh_does_not_report_old_success(
    tmp_path: Path, monkeypatch, capsys, source
) -> None:
    path = tmp_path / "assets.db"
    assert invoke(monkeypatch, path, "fetch", "--max-age-hours", "1", "--execute") == 0
    capsys.readouterr()
    before = path.read_bytes()

    class Failed:
        def get_record(self, cve: str, revision: str) -> object:
            raise VulnrichmentError("http_error", status=404)

    monkeypatch.setattr(cisa_cli, "VulnrichmentClient", Failed)
    assert invoke(monkeypatch, path, "fetch", "--max-age-hours", "1", "--execute") == 2
    output = capsys.readouterr()
    assert not output.out
    assert "http_error" in output.err
    assert path.read_bytes() == before


def test_missing_record_is_an_error(
    tmp_path: Path, monkeypatch, capsys, source
) -> None:
    path = tmp_path / "assets.db"
    with AssetRegistry(path, create_if_missing=True):
        pass
    assert invoke(monkeypatch, path, "show", "--snapshot", "123") == 2
    assert "not found" in capsys.readouterr().err
    assert source == []


def test_show_missing_db_never_creates_it(tmp_path: Path, monkeypatch, source) -> None:
    path = tmp_path / "assets.db"
    assert invoke(monkeypatch, path, "show", "--snapshot", "1") == 2
    assert not path.exists()
    assert source == []


def test_show_evaluates_freshness_without_changing_report(
    tmp_path: Path, monkeypatch, capsys, source
) -> None:
    path = tmp_path / "assets.db"
    assert invoke(monkeypatch, path, "fetch", "--max-age-hours", "1", "--execute") == 0
    capsys.readouterr()
    with cisa_cli.VulnrichmentStore(path, read_only=True) as store:
        snapshot = store.get(1, cve="CVE-2026-0001", revision="a" * 40)
    result = cisa_cli.describe_snapshot(
        1, snapshot, now=datetime(2090, 1, 1, tzinfo=UTC)
    )
    assert all(o["effective_status"] == "expired" for o in result["observations"])
    result = cisa_cli.describe_snapshot(
        1, snapshot, now=datetime(2020, 1, 1, tzinfo=UTC)
    )
    assert all(o["effective_status"] == "future" for o in result["observations"])


@pytest.mark.parametrize(
    "option,value", [("--revision", "main"), ("--cve", "GHSA-synthetic")]
)
def test_invalid_target_never_contacts_source(
    tmp_path: Path,
    monkeypatch,
    source,
    option: str,
    value: str,
) -> None:
    path = tmp_path / "assets.db"
    assert (
        invoke(
            monkeypatch,
            path,
            "fetch",
            "--max-age-hours",
            "1",
            "--execute",
            option,
            value,
        )
        == 2
    )
    assert source == []
    assert not path.exists()


def test_storage_failure_is_not_success(
    tmp_path: Path, monkeypatch, capsys, source
) -> None:
    path = tmp_path / "assets.db"

    def fail(self, snapshot):
        raise sqlite3.OperationalError("simulated write failure")

    monkeypatch.setattr(cisa_cli.VulnrichmentStore, "save", fail)
    assert invoke(monkeypatch, path, "fetch", "--max-age-hours", "1", "--execute") == 2
    assert not capsys.readouterr().out
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT COUNT(*) FROM vulnrichment_snapshots").fetchone()[0] == 0
        )


def test_load_explicit_sync_selection_is_read_only(
    tmp_path, monkeypatch, capsys, source
):
    path = tmp_path / "assets.db"
    assert invoke(monkeypatch, path, "fetch", "--max-age-hours", "1", "--execute") == 0
    capsys.readouterr()
    before = path.read_bytes()
    result = cisa_cli.load_triage_input(
        str(path), "production", [["CVE-2026-0001", "a" * 40, "1"]]
    )
    assert result.cisa[0].snapshot_id == 1
    assert result.cisa[0].snapshot.report().exploitation == "poc"
    assert path.read_bytes() == before
    assert len(source) == 1


@pytest.mark.parametrize(
    "environment, selections",
    [
        (None, [["CVE-2026-0001", "a" * 40, "1"]]),
        ("", []),
        ("production", [["CVE-2026-0001", "main", "1"]]),
        ("production", [["CVE-2026-0001", "a" * 40, "0"]]),
        ("production", [["CVE-2026-0001", "a" * 40, str(2**63)]]),
        ("production", [["CVE-2026-0001", "a" * 40, "1"]] * 2),
    ],
)
def test_invalid_sync_selections_fail_before_storage(tmp_path, environment, selections):
    path = tmp_path / "missing.db"
    with pytest.raises(ValueError):
        cisa_cli.load_triage_input(str(path), environment, selections)
    assert not path.exists()


def test_sync_selection_requires_registry_and_exact_record(tmp_path):
    with pytest.raises(ValueError, match="asset-db"):
        cisa_cli.load_triage_input(None, "production", [])
    path = tmp_path / "assets.db"
    with AssetRegistry(path, create_if_missing=True):
        pass
    with pytest.raises(ValueError, match="not found"):
        cisa_cli.load_triage_input(
            str(path), "production", [["CVE-2026-0001", "a" * 40, "1"]]
        )
