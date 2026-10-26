from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from sbom_ops import cli
from sbom_ops.domain.identifier_candidates import (
    IdentifierTarget,
    interpret_osv_candidates,
)
from sbom_ops.domain.poc import select_poc_targets
from sbom_ops.services.identifier_review import (
    list_identifier_reviews,
    review_identifier,
)
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.identifier_candidates import IdentifierStore
from sbom_ops.storage.poc import PocStore

NOW = datetime(2026, 10, 17, tzinfo=UTC)
CVE = "CVE-2026-10001"


def observation():
    return interpret_osv_candidates(
        IdentifierTarget("GO-2026-10001", ("OSV",)),
        {"id": "GO-2026-10001", "modified": NOW.isoformat(), "aliases": [CVE]},
        observed_at=NOW,
    )


@pytest.fixture
def path(tmp_path):
    path = tmp_path / "assets.sqlite3"
    with AssetRegistry(path, create_if_missing=True):
        pass
    with IdentifierStore(path) as store:
        store.save(observation())
    return path


def approve(store, **changes):
    args = dict(
        observation_id=1,
        dt_source="OSV",
        cve=CVE,
        action="approve",
        actor="fictional-operator",
        reason="synthetic identity review",
        expires_at=(NOW + timedelta(hours=1)).isoformat(),
        now=NOW,
    )
    args.update(changes)
    return review_identifier(store, **args)


def test_preview_has_no_writes_and_approve_revoke_history(path):
    before = path.read_bytes()
    with IdentifierStore(path, read_only=True) as store:
        assert approve(store)["status"] == "preview"
    assert path.read_bytes() == before
    with IdentifierStore(path) as store:
        assert approve(store, execute=True)["review_id"] == 1
        assert (
            list_identifier_reviews(store, now=NOW)[0]["effective_status"] == "active"
        )
        assert (
            list_identifier_reviews(store, now=NOW + timedelta(hours=1))[0][
                "effective_status"
            ]
            == "expired"
        )
        assert (
            list_identifier_reviews(store, now=NOW - timedelta(seconds=1))[0][
                "effective_status"
            ]
            == "future"
        )
        result = approve(store, action="revoke", expires_at=None, execute=True)
        assert result["review_id"] == 2
        rows = list_identifier_reviews(store, now=NOW)
        assert [r["effective_status"] for r in rows] == ["revoked", "superseded"]
        assert all(r["poc_connected"] is False for r in rows)
    with PocStore(path, read_only=True) as store:
        assert store.snapshot().vulnerability_observations == ()
    targets = select_poc_targets(
        {"status": "succeeded", "assessments": [{"vulnerability_id": "GO-2026-10001"}]},
        max_cves=25,
    )
    assert not targets.cves


@pytest.mark.parametrize(
    "changes",
    [
        {"actor": " "},
        {"reason": ""},
        {"dt_source": "GITHUB"},
        {"cve": "CVE-2026-99999"},
        {"observation_id": 99},
        {"expires_at": None},
        {"expires_at": NOW.isoformat()},
        {"expires_at": (NOW + timedelta(days=2)).isoformat()},
        {"expires_at": "2026-10-17T01:00:00"},
        {"now": NOW - timedelta(seconds=1)},
        {"now": NOW + timedelta(days=2)},
        {"max_age_hours": 0},
        {"max_age_hours": float("nan")},
        {"action": "revoke", "expires_at": None},
    ],
)
def test_invalid_decision_never_writes(path, changes):
    before = path.read_bytes()
    with IdentifierStore(path) as store, pytest.raises(ValueError):
        approve(store, execute=True, **changes)
    assert path.read_bytes() == before


def test_new_observation_invalidates_approval_and_preview_must_be_rechecked(path):
    with IdentifierStore(path) as store:
        approve(store)  # preview does not reserve the current observation
        approve(store, execute=True)
        store.save(observation())
        assert (
            list_identifier_reviews(store, now=NOW)[0]["effective_status"]
            == "observation_changed"
        )
        with pytest.raises(ValueError, match="superseded"):
            approve(store, execute=True)
        approve(store, observation_id=2, execute=True)
        with pytest.raises(ValueError, match="latest approval"):
            approve(store, action="revoke", expires_at=None, execute=True)
        rows = list_identifier_reviews(store, now=NOW)
        assert [r["effective_status"] for r in rows] == ["active", "superseded"]


@pytest.mark.parametrize("status", ["withdrawn", "unresolved", "error"])
def test_bad_candidate_cannot_be_approved(path, status):
    with IdentifierStore(path) as store:
        store.save(replace(observation(), status=status))
        with pytest.raises(ValueError, match="explicit candidate"):
            approve(store, observation_id=2, execute=True)


def test_ambiguous_requires_specific_cve_and_records_actor(path):
    with IdentifierStore(path) as store:
        store.save(
            replace(observation(), cves=(CVE, "CVE-2026-10002"), status="ambiguous")
        )
        approve(store, observation_id=2, cve="CVE-2026-10002", execute=True)
        row = list_identifier_reviews(store, now=NOW)[0]
        assert row["cve"] == "CVE-2026-10002"
        assert row["actor"] == "fictional-operator"


def test_transaction_failure_rolls_back_decision(path, monkeypatch):
    with IdentifierStore(path) as store:
        original = store.append_decision

        def fail(decision):
            original(decision)
            raise ValueError("failed after insert")

        monkeypatch.setattr(store, "append_decision", fail)
        with pytest.raises(ValueError, match="after insert"):
            approve(store, execute=True)
        assert store.reviews() == []


def test_v8_migration_preserves_candidates_and_backup(path, tmp_path, monkeypatch):
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE lifecycle_evidence")
        db.execute("DROP TABLE vulnrichment_snapshots")
        db.execute("DROP TABLE identifier_reviews")
        db.execute("PRAGMA user_version=8")
    before = path.read_bytes()
    with IdentifierStore(path, read_only=True) as store:
        assert len(store.recent()) == 1
        with pytest.raises(ValueError, match="v9"):
            approve(store)
    assert path.read_bytes() == before
    with AssetRegistry(path) as registry:
        registry.backup_to(tmp_path / "v8.sqlite3")
        check = registry.check_integrity
        calls = []

        def fail():
            calls.append(1)
            if len(calls) == 2:
                raise ValueError("migration failure")
            check()

        monkeypatch.setattr(registry, "check_integrity", fail)
        with pytest.raises(ValueError, match="migration failure"):
            registry.migrate()
        assert registry.schema_version == 8
        monkeypatch.setattr(registry, "check_integrity", check)
        registry.migrate()
    with IdentifierStore(path) as store:
        assert len(store.recent()) == 1
        approve(store, execute=True)
    with AssetRegistry(tmp_path / "v8.sqlite3", read_only=True) as registry:
        assert registry.schema_version == 8


def test_cli_show_never_connects(path, monkeypatch, capsys):
    with IdentifierStore(path) as store:
        approve(store, execute=True)
    monkeypatch.setattr(cli, "OsvClient", lambda: pytest.fail("network"))
    monkeypatch.setattr(
        "sys.argv", ["sbom-ops", "id-review", "--db", str(path), "show"]
    )
    before = path.read_bytes()
    assert cli.main() == 0
    assert '"poc_connected": false' in capsys.readouterr().out
    assert path.read_bytes() == before


def test_cli_preview_approve_and_revoke(path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "OsvClient", lambda: pytest.fail("network"))
    monkeypatch.setattr(
        cli,
        "review_identifier",
        lambda store, **kwargs: review_identifier(store, now=NOW, **kwargs),
    )
    base = ["sbom-ops", "id-review", "--db", str(path)]
    fields = [
        "--observation",
        "1",
        "--dt-source",
        "OSV",
        "--cve",
        CVE,
        "--actor",
        "fictional-operator",
        "--reason",
        "synthetic review",
    ]
    command = (
        base
        + ["approve"]
        + fields
        + ["--expires-at", (NOW + timedelta(hours=1)).isoformat()]
    )
    monkeypatch.setattr("sys.argv", command)
    before = path.read_bytes()
    assert cli.main() == 0
    assert '"status": "preview"' in capsys.readouterr().out
    assert path.read_bytes() == before
    monkeypatch.setattr("sys.argv", command + ["--execute"])
    assert cli.main() == 0
    assert '"review_id": 1' in capsys.readouterr().out
    monkeypatch.setattr("sys.argv", base + ["revoke"] + fields + ["--execute"])
    assert cli.main() == 0
    assert '"review_id": 2' in capsys.readouterr().out
    with IdentifierStore(path, read_only=True) as store:
        assert (
            list_identifier_reviews(store, now=NOW)[0]["effective_status"] == "revoked"
        )
