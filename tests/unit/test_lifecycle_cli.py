import json
import sqlite3
from pathlib import Path

import pytest

from sbom_ops import cli
from sbom_ops.storage.asset_registry import AssetRegistry


@pytest.fixture
def inputs(tmp_path: Path) -> tuple[Path, Path]:
    db, source = tmp_path / "assets.db", tmp_path / "evidence.json"
    with AssetRegistry(db, create_if_missing=True):
        pass
    with sqlite3.connect(db) as connection:
        connection.execute("INSERT INTO services VALUES ('shop','team','high','sales')")
        connection.execute("INSERT INTO deployables VALUES ('shop','api','shop-api')")
    source.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "service_id": "shop",
                "deployable_id": "api",
                "kind": "build",
                "artifact_id": "build-a",
                "sbom_ref": "boms/a.json",
                "actor": "operator",
            }
        )
    )
    return db, source


def run(db: Path, *args: str) -> int:
    return cli.run_assets(
        cli.build_parser().parse_args(["assets", "--db", str(db), *args])
    )


def test_preview_apply_history(inputs, capsys) -> None:
    db, source = inputs
    before = db.read_bytes()
    assert run(db, "evidence-register", "--file", str(source)) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["status"] == "preview"
    assert "record_id" not in preview
    assert db.read_bytes() == before
    assert run(db, "evidence-register", "--file", str(source), "--apply") == 0
    saved = json.loads(capsys.readouterr().out)
    assert saved["status"] == "applied"
    assert saved["record_id"] == 1
    assert saved["evidence"] == preview["evidence"]
    assert run(db, "evidence-history", "--service", "shop", "--deployable", "api") == 0
    history = json.loads(capsys.readouterr().out)
    assert history["records"][0]["record_id"] == saved["record_id"]
    assert history["records"][0]["recorded_at"] == saved["recorded_at"]


@pytest.mark.parametrize(
    "state,label",
    [
        ("matched", "成果物との対応が一致"),
        ("asset_link_unverified", "資産との紐付け未確認"),
        ("different_asset", "別の資産"),
        ("different_artifact", "別の成果物"),
        ("not_build", "Build根拠ではありません"),
        ("future", "未来日時・確認が必要"),
        ("observation_unknown", "観測日時不明・確認が必要"),
        ("superseded", "訂正前の履歴"),
    ],
)
def test_review_explains_each_record_state(capsys, state, label) -> None:
    from sbom_ops.lifecycle_cli import print_evidence_review

    print_evidence_review(
        "loaded",
        (
            {
                "project_uuid": "uuid",
                "project_status": "matched",
                "records": [
                    {
                        "record_id": 1,
                        "status": state,
                        "evidence": {"kind": "build", "sbom_ref": "boms/a.json"},
                    }
                ],
            },
        ),
    )
    assert label in capsys.readouterr().out


def test_empty_history_differs_from_missing_asset(inputs, capsys) -> None:
    db, _ = inputs
    assert run(db, "evidence-history", "--service", "shop", "--deployable", "api") == 0
    assert json.loads(capsys.readouterr().out)["records"] == []
    assert (
        run(db, "evidence-history", "--service", "shop", "--deployable", "missing") == 1
    )
    assert capsys.readouterr().err


@pytest.mark.parametrize(
    "content",
    [b"x" * 65537, b"\xff", b'{"secret": "synthetic-marker"}'],
    ids=["oversize", "invalid-utf8", "invalid-fields"],
)
def test_bad_input_does_not_write_or_echo_payload(
    inputs, capsys, content: bytes
) -> None:
    db, source = inputs
    source.write_bytes(content)
    before = db.read_bytes()
    assert run(db, "evidence-register", "--file", str(source), "--apply") == 1
    output = capsys.readouterr()
    assert "synthetic-marker" not in output.err + output.out
    assert db.read_bytes() == before


def test_correction_preview_and_history(inputs, capsys) -> None:
    db, source = inputs
    assert run(db, "evidence-register", "--file", str(source), "--apply") == 0
    first = json.loads(capsys.readouterr().out)
    payload = json.loads(source.read_text())
    payload.update(
        supersedes_id=first["record_id"], reason="訂正", sbom_ref="boms/b.json"
    )
    source.write_text(json.dumps(payload))
    before = db.read_bytes()
    assert run(db, "evidence-register", "--file", str(source)) == 0
    assert db.read_bytes() == before
    capsys.readouterr()
    assert run(db, "evidence-register", "--file", str(source), "--apply") == 0
    capsys.readouterr()
    assert run(db, "evidence-register", "--file", str(source)) == 1
    capsys.readouterr()
    assert run(db, "evidence-history", "--service", "shop", "--deployable", "api") == 0
    records = json.loads(capsys.readouterr().out)["records"]
    assert len(records) == 2
    assert records[0]["evidence"]["sbom_ref"] == "boms/a.json"
    assert records[1]["evidence"]["supersedes_id"] == first["record_id"]


def test_preview_does_not_create_or_migrate_db(inputs, tmp_path, capsys) -> None:
    db, source = inputs
    missing = tmp_path / "missing.db"
    assert run(missing, "evidence-register", "--file", str(source)) == 1
    assert not missing.exists()
    with sqlite3.connect(db) as connection:
        connection.execute("DROP TABLE advisory_feed_revisions")
        connection.execute("DROP TABLE advisory_poll_state")
        connection.execute("DROP TABLE lifecycle_evidence")
        connection.execute("PRAGMA user_version=10")
    before = db.read_bytes()
    assert run(db, "evidence-register", "--file", str(source)) == 1
    assert db.read_bytes() == before


def test_sync_result_carries_evidence_without_changing_actions() -> None:
    from sbom_ops.services.orchestrator import RunResult

    result = RunResult("run", 0.0, False, 0, 0, 0, 0, 0, True)
    assert result.as_dict()["lifecycle_evidence_status"] == "not_requested"
    assert result.as_dict()["lifecycle_evidence"] == []


def test_project_evidence_uses_one_read_snapshot(inputs, monkeypatch) -> None:
    from datetime import UTC, datetime

    from sbom_ops.domain.asset_registry import (
        RegistryProjectObservation,
        RegistryProjectStatus,
    )
    from sbom_ops.domain.lifecycle_evidence import LifecycleEvidence
    from sbom_ops.services.lifecycle_evidence import project_evidence_views
    from sbom_ops.storage.lifecycle_evidence import LifecycleEvidenceStore

    db, _ = inputs
    with sqlite3.connect(db) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            "INSERT INTO reviewed_project_links VALUES (?,?,?,?,?,?,?)",
            (
                "uuid",
                "shop-api",
                "build-a",
                "shop",
                "api",
                "reviewer",
                "2020-01-01T00:00:00Z",
            ),
        )
    item = LifecycleEvidence(
        "shop",
        "api",
        "build",
        "boms/a.json",
        "operator",
        artifact_id="build-a",
        observed_at=datetime(2020, 1, 1, tzinfo=UTC),
    )
    with LifecycleEvidenceStore(db) as store:
        store.append(item)
    original = AssetRegistry.list_links
    changed = False

    def update_after_links(registry):
        nonlocal changed
        links = original(registry)
        if not changed:
            changed = True
            with LifecycleEvidenceStore(db) as writer:
                writer.append(item)
        return links

    monkeypatch.setattr(AssetRegistry, "list_links", update_after_links)
    project = RegistryProjectObservation(
        "uuid",
        "shop-api",
        "build-a",
        RegistryProjectStatus.MATCHED,
        service_id="shop",
        deployable_id="api",
    )
    status, views = project_evidence_views(db, (project,), now=datetime.now(UTC))
    assert status == "loaded"
    assert len(views[0]["records"]) == 1
    assert views[0]["records"][0]["status"] == "matched"
    with LifecycleEvidenceStore(db) as store:
        assert len(store.list_records("shop", "api")) == 2
    status, next_views = project_evidence_views(db, (project,), now=datetime.now(UTC))
    assert status == "loaded"
    assert len(next_views[0]["records"]) == 2
    assert {row["status"] for row in next_views[0]["records"]} == {
        "multiple_candidates"
    }


@pytest.mark.parametrize(
    "status,label",
    [
        ("not_requested", "台帳未指定"),
        ("migration_required", "台帳の明示移行が必要"),
        ("invalid", "読取・整合性確認に失敗"),
        ("loaded", "読取済み"),
    ],
)
def test_review_explains_evidence_input_status(capsys, status, label) -> None:
    from sbom_ops.services.orchestrator import RunResult

    result = RunResult(
        "run", 0.0, False, 0, 0, 0, 0, 0, True, lifecycle_evidence_status=status
    )
    cli.print_review_queue(result)
    assert "SBOM根拠: " + label in capsys.readouterr().out


def test_review_displays_record_and_caveat(capsys) -> None:
    from sbom_ops.services.orchestrator import RunResult

    result = RunResult(
        "run",
        0.0,
        False,
        0,
        0,
        0,
        0,
        0,
        True,
        lifecycle_evidence_status="loaded",
        lifecycle_evidence=(
            {
                "project_uuid": "uuid",
                "project_status": "matched",
                "records": [
                    {
                        "record_id": 7,
                        "status": "multiple_candidates",
                        "evidence": {
                            "kind": "build",
                            "artifact_id": "build-a",
                            "sbom_ref": "boms/a.json",
                        },
                    }
                ],
            },
        ),
    )
    cli.print_review_queue(result)
    output = capsys.readouterr().out
    assert "根拠ID=7" in output
    assert "独立した候補が複数・自動選択しません" in output
    assert "boms/a.json" in output
    assert "実稼働・署名・完全性を保証しません" in output


@pytest.mark.parametrize(
    "case", ["valid", "broken", "old", "empty", "revoked", "future", "multiple"]
)
def test_sync_reads_evidence_and_distinguishes_invalid(
    inputs, capsys, monkeypatch, case
) -> None:
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from sbom_ops.domain.asset_registry import (
        RegistryProjectObservation,
        RegistryProjectStatus,
    )
    from sbom_ops.domain.lifecycle_evidence import LifecycleEvidence
    from sbom_ops.services.orchestrator import RunResult
    from sbom_ops.storage.lifecycle_evidence import LifecycleEvidenceStore

    db, _ = inputs
    with sqlite3.connect(db) as connection:
        connection.execute(
            "INSERT INTO reviewed_project_links VALUES (?,?,?,?,?,?,?)",
            (
                "uuid",
                "shop-api",
                "build-a",
                "shop",
                "api",
                "reviewer",
                "2020-01-01T00:00:00Z",
            ),
        )
    with LifecycleEvidenceStore(db) as store:
        store.append(
            LifecycleEvidence(
                "shop",
                "api",
                "build",
                "boms/a.json",
                "operator",
                artifact_id="build-a",
                observed_at=datetime(2020, 1, 1, tzinfo=UTC),
            )
        )
    if case == "multiple":
        with LifecycleEvidenceStore(db) as store:
            store.append(store.list_records("shop", "api")[0].evidence)
    if case != "valid":
        with sqlite3.connect(db) as connection:
            if case == "broken":
                connection.execute("UPDATE lifecycle_evidence SET evidence_json='{}'")
            elif case == "old":
                connection.execute("DROP TABLE advisory_feed_revisions")
                connection.execute("DROP TABLE advisory_poll_state")
                connection.execute("DROP TABLE lifecycle_evidence")
                connection.execute("PRAGMA user_version=10")
            elif case == "empty":
                connection.execute("DELETE FROM lifecycle_evidence")
            elif case == "revoked":
                connection.execute("DELETE FROM reviewed_project_links")
            elif case == "future":
                raw = connection.execute(
                    "SELECT evidence_json FROM lifecycle_evidence"
                ).fetchone()[0]
                payload = json.loads(raw)
                payload["observed_at"] = "2099-01-01T00:00:00+00:00"
                connection.execute(
                    "UPDATE lifecycle_evidence SET evidence_json=?",
                    (json.dumps(payload),),
                )
    project = RegistryProjectObservation(
        "uuid",
        "shop-api",
        "build-a",
        RegistryProjectStatus.MATCHED,
        service_id="shop",
        deployable_id="api",
    )

    class Fake:
        def __init__(self, **kwargs):
            pass

        def run(self):
            return RunResult(
                "run", 0.0, False, 1, 0, 0, 0, 0, True, registry_projects=(project,)
            )

    monkeypatch.setattr(cli, "Orchestrator", Fake)
    config = SimpleNamespace(runtime=SimpleNamespace(sync_log_file=None))
    before = db.read_bytes()
    assert cli.run_sync(config, "json", asset_db_path=str(db)) == 0
    result = json.loads(capsys.readouterr().out)
    expected = {"broken": "invalid", "old": "migration_required"}.get(case, "loaded")
    assert result["lifecycle_evidence_status"] == expected
    if case in ("broken", "old"):
        assert result["lifecycle_evidence"] == []
    elif case == "empty":
        assert result["lifecycle_evidence"][0]["records"] == []
    else:
        record = result["lifecycle_evidence"][0]["records"][0]
        assert record["status"] == {
            "revoked": "asset_link_unverified",
            "future": "future",
            "multiple": "multiple_candidates",
        }.get(case, "matched")
        assert record["record_id"] == 1
        assert record["evidence"]["sbom_ref"] == "boms/a.json"
        assert len(result["lifecycle_evidence"][0]["records"]) == (
            2 if case == "multiple" else 1
        )
    assert (
        result["issues_created"]
        == result["issues_updated"]
        == result["issues_closed"]
        == 0
    )
    assert db.read_bytes() == before
