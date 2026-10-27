import json
import sys
from datetime import UTC, datetime
from unittest.mock import Mock

from test_advisory_feed_parser import RDF

from sbom_ops.cli import main
from sbom_ops.clients.advisory_feed import AdvisoryFeedClient
from sbom_ops.services.advisory_feed_parser import parse_advisory_feed
from sbom_ops.storage.advisory_feed import AdvisoryFeedStore
from sbom_ops.storage.asset_registry import AssetRegistry


def test_list_pagination_is_readonly(tmp_path, monkeypatch, capsys):
    db = tmp_path / "assets.db"
    with AssetRegistry(db, create_if_missing=True):
        pass
    with AdvisoryFeedStore(db) as store:
        ids = store.save(
            parse_advisory_feed(RDF, source_id="jpcert"), fetched_at=datetime.now(UTC)
        )
    before = db.read_bytes()
    fetch = Mock(side_effect=AssertionError("no network"))
    monkeypatch.setattr(AdvisoryFeedClient, "fetch", fetch)
    cursor = 0
    seen = []
    for _ in range(3):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "sbom-ops",
                "advisories",
                "list",
                "--db",
                str(db),
                "--source",
                "jpcert",
                "--limit",
                "1",
                "--after-id",
                str(cursor),
                "--output",
                "json",
            ],
        )
        assert main() == 0
        output = json.loads(capsys.readouterr().out)
        assert output["poll"]["state"] is None
        assert output["poll"]["freshness"] == "unknown"
        seen.extend(row["record_id"] for row in output["articles"])
        if output["next_after_id"] is None:
            break
        cursor = output["next_after_id"]
    assert seen == list(ids)
    assert db.read_bytes() == before
    fetch.assert_not_called()
