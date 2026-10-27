from dataclasses import replace
from datetime import timedelta

import pytest
from test_advisory_feed_storage import NOW, item

from sbom_ops.storage.advisory_feed import AdvisoryFeedStore
from sbom_ops.storage.asset_registry import AssetRegistry


@pytest.fixture
def path(tmp_path):
    result = tmp_path / "assets.db"
    with AssetRegistry(result, create_if_missing=True):
        pass
    return result


def test_latest_revision_paging_keeps_absent_articles(path):
    first = item()
    second = replace(first, item_key="second")
    correction = replace(first, title="Corrected")
    with AdvisoryFeedStore(path) as store:
        original_ids = store.save((first, second), fetched_at=NOW)
        corrected_id = store.save((correction,), fetched_at=NOW + timedelta(hours=1))[0]
        page = store.latest("fixture", limit=1)
        assert [row["record_id"] for row in page] == [original_ids[1]]
        next_page = store.latest("fixture", after_id=page[-1]["record_id"], limit=1)
        assert [row["record_id"] for row in next_page] == [corrected_id]
        assert next_page[0]["metadata"]["title"] == "Corrected"
        assert next_page[0]["metadata"]["cve_mentions"] == [
            ["CVE-2026-1000", "description"]
        ]
        assert store.latest("fixture", after_id=corrected_id) == ()
        assert len(store.history(*first.identity)) == 2


def test_sources_are_separate_and_readonly(path):
    with AdvisoryFeedStore(path) as store:
        store.save((item(), replace(item(), source_id="other")), fetched_at=NOW)
    before = path.read_bytes()
    with AdvisoryFeedStore(path, read_only=True) as store:
        rows = store.latest("fixture")
        assert len(rows) == 1 and rows[0]["metadata"]["source_id"] == "fixture"
        assert store.latest("missing") == ()
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "after,limit", [(-1, 1), (True, 1), (0, 0), (0, 501), (0, True)]
)
def test_invalid_cursor_or_limit_rejected(path, after, limit):
    with AdvisoryFeedStore(path) as store:
        with pytest.raises(ValueError):
            store.latest("fixture", after_id=after, limit=limit)
