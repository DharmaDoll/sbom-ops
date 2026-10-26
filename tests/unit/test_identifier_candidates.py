"""Synthetic OSV contract fixtures; no live data or lab imports.

Reviewed 2026-10-15: https://google.github.io/osv.dev/get-v1-vulns/
and https://ossf.github.io/osv-schema/ (id, modified, aliases, withdrawn).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from io import BytesIO
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from sbom_ops import cli
from sbom_ops.clients.osv import OsvClient, _NoRedirect
from sbom_ops.domain.identifier_candidates import (
    IdentifierFetchError,
    IdentifierTarget,
    interpret_osv_candidates,
    osv_identifier,
    select_identifier_targets,
)
from sbom_ops.domain.poc import select_poc_targets
from sbom_ops.services.identifier_candidates import collect_identifier_candidates
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.identifier_candidates import IdentifierStore
from sbom_ops.storage.poc import PocStore
from sbom_ops.storage.run_lock import exclusive_run

NOW = datetime(2026, 10, 15, tzinfo=UTC)
TARGET = IdentifierTarget("GO-2026-10001", ("OSV",))
CVE = "CVE-2026-10001"


def payload(**changes):
    return {
        "id": TARGET.original_id,
        "modified": "2026-10-14T00:00:00Z",
        "aliases": [CVE],
        **changes,
    }


def findings(*ids):
    return {
        "status": "succeeded",
        "assessments": [
            {"vulnerability_id": i, "vulnerability_source": "OSV"} for i in ids
        ],
    }


@pytest.mark.parametrize(
    "aliases,status",
    [
        ([], "unresolved"),
        ([CVE, CVE], "candidate"),
        ([CVE, "CVE-2026-10002"], "ambiguous"),
    ],
)
def test_explicit_aliases_only_and_no_approval(aliases, status):
    result = interpret_osv_candidates(
        TARGET,
        payload(
            aliases=aliases,
            related=["CVE-2020-9999"],
            upstream=["CVE-2020-9998"],
            details="CVE-2020-9997",
        ),
        observed_at=NOW,
    )
    assert result.cves == tuple(sorted(set(aliases)))
    assert result.status == status
    assert result.as_dict()["approved"] is False
    assert result.original_id == TARGET.original_id
    assert result.dt_sources == ("OSV",)


@pytest.mark.parametrize(
    "changes",
    [
        {"id": "GO-2026-99999"},
        {"modified": "2099-01-01T00:00:00Z"},
        {"modified": "2026-01-01"},
        {"modified": None},
        {"aliases": None},
        {"aliases": [42]},
    ],
)
def test_bad_response_rejected(changes):
    with pytest.raises(ValueError):
        interpret_osv_candidates(TARGET, payload(**changes), observed_at=NOW)


def test_withdrawn_not_candidate():
    row = interpret_osv_candidates(
        TARGET, payload(withdrawn="2026-10-14T01:00:00Z"), observed_at=NOW
    )
    assert row.status == "withdrawn" and row.cves == ()


def test_selection_limits_canonicalization_and_preserves_sources():
    raw = findings(CVE, TARGET.original_id, TARGET.original_id, "PRIVATE-ID")
    raw["assessments"][2]["vulnerability_source"] = "GITHUB"
    targets, unsupported = select_identifier_targets(raw, max_ids=1)
    assert targets == (IdentifierTarget(TARGET.original_id, ("GITHUB", "OSV")),)
    assert unsupported == ("PRIVATE-ID",)
    assert osv_identifier("GHSA-JFH8-C2JP-5V3Q") == "GHSA-jfh8-c2jp-5v3q"
    with pytest.raises(ValueError, match="exceed"):
        select_identifier_targets(
            findings(TARGET.original_id, "PYSEC-2026-1"), max_ids=1
        )
    with pytest.raises(ValueError):
        osv_identifier("GO-2026-10001/../../secret")
    targets, _ = select_identifier_targets(
        raw, max_ids=1, only_ids=(TARGET.original_id,)
    )
    assert len(targets) == 1
    with pytest.raises(ValueError, match="not unresolved"):
        select_identifier_targets(raw, max_ids=1, only_ids=(CVE,))


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "assets.sqlite3"
    with AssetRegistry(path, create_if_missing=True):
        pass
    return path


def test_success_then_failure_preserved_and_no_poc_join(db_path):
    with IdentifierStore(db_path) as store:
        result, skipped = collect_identifier_candidates(
            (TARGET,),
            SimpleNamespace(get_vulnerability=lambda _: payload()),
            store,
            clock=lambda: NOW,
        )
        assert not skipped and result[0]["status"] == "candidate"
        calls = []

        def fail(identifier):
            calls.append(identifier)
            raise IdentifierFetchError("http_error", status=429)

        result, skipped = collect_identifier_candidates(
            (TARGET, IdentifierTarget("PYSEC-2026-1", ("OSV",))),
            SimpleNamespace(get_vulnerability=fail),
            store,
            clock=lambda: NOW,
        )
        assert len(calls) == 1
        assert skipped == ("PYSEC-2026-1",)
        assert result[0]["status"] == "error"
        history = store.recent()
        assert [r["status"] for r in history] == ["error", "candidate"]
    with PocStore(db_path, read_only=True) as store:
        assert store.snapshot().vulnerability_observations == ()
    assert select_poc_targets(findings(TARGET.original_id), max_cves=25).cves == ()


def test_v7_compatibility_migration_backup_and_rollback(db_path, tmp_path, monkeypatch):
    with sqlite3.connect(db_path) as db:
        db.execute("DROP TABLE lifecycle_evidence")
        db.execute("DROP TABLE vulnrichment_snapshots")
        db.execute("DROP TABLE identifier_reviews")
        db.execute("DROP TABLE identifier_observations")
        db.execute("PRAGMA user_version=7")
    with PocStore(db_path):
        pass  # Old PoC updates remain supported without upgrading.
    before = db_path.read_bytes()
    with pytest.raises(ValueError, match="v8"):
        IdentifierStore(db_path)
    assert db_path.read_bytes() == before
    with AssetRegistry(db_path) as registry:
        registry.backup_to(tmp_path / "before.sqlite3")
        original = registry.check_integrity
        calls = []

        def fail_after_ddl():
            calls.append(1)
            if len(calls) == 2:
                raise ValueError("simulated failure")
            original()

        monkeypatch.setattr(registry, "check_integrity", fail_after_ddl)
        with pytest.raises(ValueError, match="simulated"):
            registry.migrate()
        assert registry.schema_version == 7
        monkeypatch.setattr(registry, "check_integrity", original)
        assert registry.migrate()
    with AssetRegistry(tmp_path / "before.sqlite3", read_only=True) as registry:
        assert registry.schema_version == 7
    with IdentifierStore(db_path, read_only=True) as store:
        assert store.recent() == []


def test_cli_preview_execute_show(tmp_path, monkeypatch, capsys):
    raw = tmp_path / "findings.json"
    raw.write_text(json.dumps(findings(TARGET.original_id)))
    path = tmp_path / "assets.sqlite3"
    args = cli.build_parser().parse_args(
        ["id-candidates", "--findings", str(raw), "--db", str(path)]
    )
    monkeypatch.setattr(cli, "OsvClient", lambda: pytest.fail("preview made request"))
    assert cli.run_identifier_candidates(args) == 0
    assert json.loads(capsys.readouterr().out)["automatic_approval"] is False
    assert not path.exists()
    monkeypatch.setattr(
        cli, "OsvClient", lambda: SimpleNamespace(get_vulnerability=lambda _: payload())
    )
    args.execute = True
    assert cli.run_identifier_candidates(args) == 0
    assert json.loads(capsys.readouterr().out)["observations"][0]["approved"] is False
    args.show, args.execute = True, False
    before = path.read_bytes()
    monkeypatch.setattr(cli, "OsvClient", lambda: pytest.fail("show made request"))
    assert cli.run_identifier_candidates(args) == 0
    assert len(json.loads(capsys.readouterr().out)["observations"]) == 1
    assert path.read_bytes() == before


def test_osv_adapter_contract_and_no_credentials():
    client = OsvClient()

    def opened(request, *, timeout):
        assert request.full_url == "https://api.osv.dev/v1/vulns/GO-2026-10001"
        assert request.get_method() == "GET"
        assert not any(
            "key" in k.lower() or "authorization" in k.lower() for k in request.headers
        )
        assert timeout == 30
        result = BytesIO(json.dumps(payload()).encode())
        result.status = 200
        return result

    client._opener = SimpleNamespace(open=opened)
    assert client.get_vulnerability(TARGET.original_id) == payload()
    assert (
        _NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid")
        is None
    )


@pytest.mark.parametrize("status", [403, 404, 429, 503])
def test_http_error_sanitized(status):
    client = OsvClient()

    def fail(*args, **kwargs):
        raise HTTPError(
            "https://api.osv.dev", status, "private body", {}, BytesIO(b"private")
        )

    client._opener = SimpleNamespace(open=fail)
    with pytest.raises(IdentifierFetchError) as error:
        client.get_vulnerability(TARGET.original_id)
    assert str(error.value) == "http_error"
    assert error.value.status == status


@pytest.mark.parametrize("kind", ["size", "json", "status"])
def test_bad_transport_response_rejected(kind):
    client = OsvClient()
    body = BytesIO(b"x" * (1024 * 1024 + 1) if kind == "size" else b"not JSON")
    body.status = 204 if kind == "status" else 200
    client._opener = SimpleNamespace(open=lambda *a, **k: body)
    with pytest.raises(IdentifierFetchError) as error:
        client.get_vulnerability(TARGET.original_id)
    assert (
        error.value.code
        == {
            "size": "response_too_large",
            "json": "invalid_json",
            "status": "http_error",
        }[kind]
    )


def test_cli_old_db_and_duplicate_never_call_provider(
    db_path, tmp_path, monkeypatch, capsys
):
    raw = tmp_path / "findings.json"
    raw.write_text(json.dumps(findings(TARGET.original_id)))
    command = [
        "sbom-ops",
        "id-candidates",
        "--db",
        str(db_path),
        "--findings",
        str(raw),
        "--execute",
    ]
    monkeypatch.setattr(cli, "OsvClient", lambda: pytest.fail("unexpected provider"))
    monkeypatch.setattr("sys.argv", command)
    with exclusive_run(db_path.with_name(db_path.name + ".identifiers.lock")):
        assert cli.main() == 3
        assert (
            json.loads(capsys.readouterr().out)["error"]
            == "identifier_update_already_running"
        )
    with sqlite3.connect(db_path) as db:
        db.execute("DROP TABLE lifecycle_evidence")
        db.execute("DROP TABLE vulnrichment_snapshots")
        db.execute("DROP TABLE identifier_reviews")
        db.execute("DROP TABLE identifier_observations")
        db.execute("PRAGMA user_version=7")
    before = db_path.read_bytes()
    assert cli.main() == 2
    assert "v8" in capsys.readouterr().err
    assert db_path.read_bytes() == before


def test_pacing_and_backup_include_history(db_path, tmp_path):
    targets = (TARGET, IdentifierTarget("PYSEC-2026-1", ("OSV",)))
    client = SimpleNamespace(
        get_vulnerability=lambda identifier: payload(id=identifier)
    )
    delays = []
    with IdentifierStore(db_path) as store:
        rows, skipped = collect_identifier_candidates(
            targets, client, store, clock=lambda: NOW, sleep=delays.append
        )
    assert delays == [3.1] and not skipped and len(rows) == 2
    with AssetRegistry(db_path) as registry:
        registry.backup_to(tmp_path / "backup.sqlite3")
    with IdentifierStore(tmp_path / "backup.sqlite3", read_only=True) as store:
        assert len(store.recent()) == 2
        with pytest.raises(sqlite3.OperationalError):
            store.save(interpret_osv_candidates(TARGET, payload(), observed_at=NOW))
