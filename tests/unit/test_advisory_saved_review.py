import json
import socket
import sys
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from test_advisory_feed_parser import RSS
from test_lookup_input import context_run

from sbom_ops.cli import main
from sbom_ops.clients.advisory_feed import AdvisoryFeedClient
from sbom_ops.domain.advisory_poll import record_poll
from sbom_ops.services.advisory_feed_parser import parse_advisory_feed
from sbom_ops.services.advisory_review import review_saved_advisories
from sbom_ops.storage.advisory_feed import AdvisoryFeedStore
from sbom_ops.storage.asset_registry import AssetRegistry


def test_saved_description_cve_survives_without_body(tmp_path):
    db = tmp_path / "assets.db"
    findings = tmp_path / "sync.json"
    findings.write_text(json.dumps(context_run()))
    with AssetRegistry(db, create_if_missing=True):
        pass
    raw = RSS.replace(b"CVE-2026-1000", b"CVE-2026-1234")
    with AdvisoryFeedStore(db) as store:
        ids = store.save(
            parse_advisory_feed(raw, source_id="ubuntu"), fetched_at=datetime.now(UTC)
        )
    before = db.read_bytes()
    result = review_saved_advisories(db, findings, source_id="ubuntu", limit=1)
    assert result["source_run_id"] == "example-run"
    assert result["lookups"]["CVE-2026-1234"]["status"] == "matched"
    assert result["lookups"]["CVE-2026-2000"]["status"] == "no_match_in_input"
    assert result["articles"][0]["record_id"] == ids[0]
    assert result["articles"][0]["last_seen_at"]
    assert result["next_after_id"] == ids[0]
    assert "team-shop" in json.dumps(result)
    assert result["articles"][0]["article"]["source_fields"] == [
        ["pubDate", "Tue, 27 Oct 2026 01:00:00 +0000"],
        ["guid", "urn:notice:1"],
    ]
    assert db.read_bytes() == before


def test_missing_db_is_not_created(tmp_path):
    import sqlite3

    db = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        review_saved_advisories(db, tmp_path / "missing.json", source_id="jpcert")
    assert not db.exists()


def test_saved_review_shows_failed_refresh_without_losing_match(tmp_path):
    db = tmp_path / "assets.db"
    findings = tmp_path / "sync.json"
    findings.write_text(json.dumps(context_run()))
    now = datetime(2026, 10, 27, tzinfo=UTC)
    with AssetRegistry(db, create_if_missing=True):
        pass
    first = record_poll(None, now=now, interval=timedelta(hours=1))
    failed = record_poll(
        first,
        now=now + timedelta(hours=1),
        interval=timedelta(hours=1),
        error="transport_error",
    )
    with AdvisoryFeedStore(db) as store:
        items = parse_advisory_feed(
            RSS.replace(b"CVE-2026-1000", b"CVE-2026-1234"), source_id="ubuntu"
        )
        store.save_poll("ubuntu", items, first, expected=None)
        store.save_poll("ubuntu", (), failed, expected=first)
    result = review_saved_advisories(db, findings, source_id="ubuntu")
    assert result["poll"]["state"]["error"] == "transport_error"
    assert result["poll"]["state"]["last_success"] == now.isoformat()
    assert result["poll"]["freshness"] == "unknown"
    assert result["lookups"]["CVE-2026-1234"]["status"] == "matched"


@pytest.mark.parametrize("output", ["json", "review"])
def test_refresh_then_saved_review_cli(tmp_path, monkeypatch, capsys, output):
    db = tmp_path / "assets.db"
    findings = tmp_path / "sync.json"
    findings.write_text(json.dumps(context_run()))
    with AssetRegistry(db, create_if_missing=True):
        pass
    fetch = Mock(return_value=RSS.replace(b"CVE-2026-1000", b"CVE-2026-1234"))
    monkeypatch.setattr(AdvisoryFeedClient, "fetch", fetch)
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
            "ubuntu",
            "--execute",
            "--output",
            "json",
        ],
    )
    assert main() == 0
    assert json.loads(capsys.readouterr().out)["status"] == "succeeded"
    before = db.read_bytes()

    def forbidden(*args, **kwargs):
        raise AssertionError("review must not fetch")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(AdvisoryFeedClient, "fetch", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "advisories",
            "review",
            "--db",
            str(db),
            "--source",
            "ubuntu",
            "--findings",
            str(findings),
            "--output",
            output,
        ],
    )
    assert main() == 0
    text = capsys.readouterr().out
    assert "team-shop" in text and "example-run" in text
    assert "https://example.test/notice" in text
    assert db.read_bytes() == before
