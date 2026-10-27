from datetime import timedelta
from unittest.mock import Mock

import pytest
from test_advisory_feed_parser import RDF
from test_advisory_feed_storage import NOW

from sbom_ops.clients.advisory_feed import AdvisoryFetchError
from sbom_ops.services.advisory_refresh import refresh_advisories
from sbom_ops.storage.advisory_feed import AdvisoryFeedStore
from sbom_ops.storage.asset_registry import AssetRegistry


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "assets.db"
    with AssetRegistry(path, create_if_missing=True):
        pass
    with AdvisoryFeedStore(path) as store:
        yield store


def test_success_then_not_due_has_no_request_or_duplicate(store):
    client = Mock()
    client.fetch.return_value = RDF
    first = refresh_advisories(store, client, source_id="jpcert", now=NOW)
    assert first.status == "succeeded"
    assert len(first.items) == len(first.record_ids) == 2
    second = refresh_advisories(store, client, source_id="jpcert", now=NOW)
    assert second.status == "not_due" and second.items == ()
    assert client.fetch.call_count == 1
    assert store.poll_state("jpcert") == first.state
    repeated = refresh_advisories(
        store, client, source_id="jpcert", now=NOW + timedelta(hours=1)
    )
    assert repeated.record_ids == first.record_ids


@pytest.mark.parametrize("failure", ["transport", "parse"])
def test_failure_preserves_success_and_existing_articles(store, failure):
    client = Mock()
    client.fetch.return_value = RDF
    first = refresh_advisories(store, client, source_id="jpcert", now=NOW)
    if failure == "transport":
        client.fetch.side_effect = AdvisoryFetchError(
            "http_error", status=429, retry_after="7200"
        )
    else:
        client.fetch.return_value = b"<invalid private-content>"
    result = refresh_advisories(
        store, client, source_id="jpcert", now=NOW + timedelta(hours=1)
    )
    assert result.status == "failed"
    assert result.items == () and result.record_ids == ()
    assert result.state.last_success == first.state.last_success
    assert result.state.error == (
        "http_error" if failure == "transport" else "invalid_feed"
    )
    assert "private-content" not in repr(result)
    assert len(store.history("jpcert", "https://example.test/wr#1")) == 1
    assert store.poll_state("jpcert") == result.state
    if failure == "transport":
        assert result.state.next_attempt == NOW + timedelta(hours=3)


def test_invalid_config_fails_before_network(store):
    client = Mock()
    with pytest.raises(ValueError):
        refresh_advisories(store, client, source_id="other", now=NOW)
    with pytest.raises(ValueError):
        refresh_advisories(
            store, client, source_id="jpcert", now=NOW, interval=timedelta(0)
        )
    client.fetch.assert_not_called()


def test_db_error_propagates_without_recording_a_fetch_failure(store, monkeypatch):
    import sqlite3

    client = Mock()
    client.fetch.return_value = RDF

    def fail_save(*args, **kwargs):
        raise sqlite3.OperationalError("fixture")

    monkeypatch.setattr(store, "save_poll", fail_save)
    with pytest.raises(sqlite3.OperationalError):
        refresh_advisories(store, client, source_id="jpcert", now=NOW)
    assert store.poll_state("jpcert") is None


def test_rate_limit_blocks_requests_until_retry_time(store):
    client = Mock()
    client.fetch.side_effect = AdvisoryFetchError(
        "http_error", status=503, retry_after="7200"
    )
    refresh_advisories(store, client, source_id="jpcert", now=NOW)
    result = refresh_advisories(
        store, client, source_id="jpcert", now=NOW + timedelta(hours=1)
    )
    assert result.status == "not_due"
    assert result.state.last_success is None
    assert client.fetch.call_count == 1


def test_empty_feed_is_success_but_does_not_remove_history(store):
    client = Mock()
    client.fetch.return_value = RDF
    refresh_advisories(store, client, source_id="jpcert", now=NOW)
    client.fetch.return_value = (
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
        b'xmlns="http://purl.org/rss/1.0/"><channel/></rdf:RDF>'
    )
    result = refresh_advisories(
        store, client, source_id="jpcert", now=NOW + timedelta(hours=1)
    )
    assert result.status == "succeeded" and result.items == ()
    assert len(store.history("jpcert", "https://example.test/wr#1")) == 1


def test_fragment_siblings_correction_failure_and_recovery(store):
    client = Mock()
    corrected = RDF.replace(b"CVE-2026-1000", b"CVE-2026-2000")
    client.fetch.side_effect = [
        RDF,
        RDF,
        corrected,
        AdvisoryFetchError("transport_error"),
        RDF,
    ]
    results = [
        refresh_advisories(
            store, client, source_id="jpcert", now=NOW + timedelta(hours=hour)
        )
        for hour in range(5)
    ]
    assert [result.status for result in results] == [
        "succeeded",
        "succeeded",
        "succeeded",
        "failed",
        "succeeded",
    ]
    assert results[0].record_ids == results[1].record_ids
    assert results[2].record_ids[1] == results[0].record_ids[1]
    assert results[2].record_ids[0] != results[0].record_ids[0]
    first = store.history("jpcert", "https://example.test/wr#1")
    second = store.history("jpcert", "https://example.test/wr#2")
    assert len(first) == 3 and len(second) == 1
    assert [row["metadata"]["cve_mentions"][0][0] for row in first] == [
        "CVE-2026-1000",
        "CVE-2026-2000",
        "CVE-2026-1000",
    ]
    assert results[3].state.last_success == NOW + timedelta(hours=2)
    assert results[4].state.error is None
    assert len(store.latest("jpcert")) == 2
