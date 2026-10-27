import json
import sys
from dataclasses import replace
from datetime import timedelta

from test_advisory_feed_storage import NOW, item

from sbom_ops.cli import main
from sbom_ops.services.advisory_history import advisory_history
from sbom_ops.storage.advisory_feed import AdvisoryFeedStore
from sbom_ops.storage.asset_registry import AssetRegistry


def test_correction_reappearance_and_unretained_changes(tmp_path):
    db = tmp_path / "assets.db"
    with AssetRegistry(db, create_if_missing=True):
        pass
    first = item()
    corrected = replace(first, title="Corrected")
    body_changed = replace(
        first, source_fields=(("description", "different private-body CVE-2026-1000"),)
    )
    with AdvisoryFeedStore(db) as store:
        for hour, value in enumerate((first, corrected, first, body_changed)):
            store.save((value,), fetched_at=NOW + timedelta(hours=hour))
    before = db.read_bytes()
    result = advisory_history(db, source_id="fixture", item_key=first.item_key)
    rows = result["revisions"]
    assert len(rows) == 4
    assert rows[0]["change"]["kind"] == "first_observation"
    assert rows[1]["change"]["changed_fields"] == ["title"]
    assert rows[2]["change"]["changed_fields"] == ["title"]
    assert rows[3]["change"]["changed_fields"] == []
    assert rows[3]["change"]["fingerprint_changed"] is True
    assert rows[3]["change"]["previous_record_id"] == rows[2]["record_id"]
    assert "private-body" not in json.dumps(result)
    assert result["warnings"]
    assert db.read_bytes() == before


def test_no_history_is_not_a_resolution_verdict(tmp_path):
    db = tmp_path / "assets.db"
    with AssetRegistry(db, create_if_missing=True):
        pass
    result = advisory_history(db, source_id="fixture", item_key="missing")
    assert result["status"] == "no_saved_history"
    assert result["revisions"] == [] and result["warnings"]


def test_cli_cve_correction_keeps_before_and_after(tmp_path, monkeypatch, capsys):
    db = tmp_path / "assets.db"
    with AssetRegistry(db, create_if_missing=True):
        pass
    first = replace(item(), source_id="jpcert")
    corrected = replace(first, source_fields=(("description", "CVE-2026-2000"),))
    with AdvisoryFeedStore(db) as store:
        store.save((first,), fetched_at=NOW)
        store.save((corrected,), fetched_at=NOW + timedelta(hours=1))
    before = db.read_bytes()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sbom-ops",
            "advisories",
            "history",
            "--db",
            str(db),
            "--source",
            "jpcert",
            "--item-key",
            first.item_key,
            "--output",
            "json",
        ],
    )
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["revisions"][1]["change"]["changed_fields"] == ["cve_mentions"]
    assert result["revisions"][0]["metadata"]["cve_mentions"][0][0] == "CVE-2026-1000"
    assert result["revisions"][1]["metadata"]["cve_mentions"][0][0] == "CVE-2026-2000"
    assert db.read_bytes() == before
