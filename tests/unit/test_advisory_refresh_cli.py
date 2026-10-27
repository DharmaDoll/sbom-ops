import json
import sys
from unittest.mock import Mock

import pytest
from test_advisory_feed_parser import RDF

from sbom_ops.cli import main
from sbom_ops.clients.advisory_feed import AdvisoryFeedClient, AdvisoryFetchError
from sbom_ops.storage.advisory_feed import AdvisoryFeedStore
from sbom_ops.storage.asset_registry import AssetRegistry


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "assets.db"
    with AssetRegistry(path, create_if_missing=True):
        pass
    return path


def invoke(monkeypatch, db, *extra):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "advisories",
            "refresh",
            "--db",
            str(db),
            "--source",
            "jpcert",
            "--output",
            "json",
            *extra,
        ],
    )
    return main()


def test_default_preview_has_no_network_or_writes(db, monkeypatch, capsys):
    fetch = Mock(side_effect=AssertionError("network forbidden"))
    monkeypatch.setattr(AdvisoryFeedClient, "fetch", fetch)
    before = db.read_bytes()
    assert invoke(monkeypatch, db) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "preview" and result["due"] is True
    assert result["state"] is None
    assert db.read_bytes() == before
    assert list(db.parent.iterdir()) == [db]
    fetch.assert_not_called()


def test_execute_saves_and_repeat_waits(db, monkeypatch, capsys):
    fetch = Mock(return_value=RDF)
    monkeypatch.setattr(AdvisoryFeedClient, "fetch", fetch)
    assert invoke(monkeypatch, db, "--execute") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "succeeded" and result["article_count"] == 2
    with AdvisoryFeedStore(db, read_only=True) as store:
        assert store.poll_state("jpcert").last_success is not None
    assert invoke(monkeypatch, db, "--execute") == 0
    assert json.loads(capsys.readouterr().out)["status"] == "not_due"
    assert fetch.call_count == 1


def test_fetch_failure_returns_nonzero_and_saves_state(db, monkeypatch, capsys):
    monkeypatch.setattr(
        AdvisoryFeedClient,
        "fetch",
        Mock(side_effect=AdvisoryFetchError("http_error", status=503)),
    )
    assert invoke(monkeypatch, db, "--execute") == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "failed" and result["freshness"] == "unknown"
    assert result["state"]["http_status"] == 503


@pytest.mark.parametrize("execute", [False, True])
def test_missing_db_not_created_and_no_request(tmp_path, monkeypatch, capsys, execute):
    db = tmp_path / "missing.db"
    fetch = Mock(side_effect=AssertionError("network forbidden"))
    monkeypatch.setattr(AdvisoryFeedClient, "fetch", fetch)
    assert invoke(monkeypatch, db, *(["--execute"] if execute else [])) == 2
    assert not db.exists() and list(tmp_path.iterdir()) == []
    assert capsys.readouterr().out == ""
    fetch.assert_not_called()


def test_invalid_interval_does_not_fetch(db, monkeypatch, capsys):
    fetch = Mock(side_effect=AssertionError("network forbidden"))
    monkeypatch.setattr(AdvisoryFeedClient, "fetch", fetch)
    assert invoke(monkeypatch, db, "--execute", "--interval-seconds", "0") == 2
    assert capsys.readouterr().out == ""
    fetch.assert_not_called()


def test_busy_lock_does_not_fetch(db, monkeypatch, capsys):
    from pathlib import Path

    from sbom_ops.storage.run_lock import exclusive_run

    fetch = Mock(side_effect=AssertionError("network forbidden"))
    monkeypatch.setattr(AdvisoryFeedClient, "fetch", fetch)
    with exclusive_run(Path(str(db.resolve()) + ".advisories.lock")):
        assert invoke(monkeypatch, db, "--execute") == 2
    assert capsys.readouterr().out == ""
    fetch.assert_not_called()
