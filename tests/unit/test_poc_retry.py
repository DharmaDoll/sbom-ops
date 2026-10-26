from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import BytesIO
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from sbom_ops import cli
from sbom_ops.clients.vulnerability_lookup import VulnerabilityLookupClient
from sbom_ops.domain.poc import PocFetchError, PocRecord, PocTargets
from sbom_ops.domain.poc_retry import (
    PocRetryPolicy,
    PocSourceState,
    retry_after_deadline,
)
from sbom_ops.services.poc_refresh import collect_poc_snapshot
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.poc import PocStore

NOW = datetime(2026, 10, 14, tzinfo=UTC)
CVE = "CVE-2026-10001"
SOURCE = "vulnerability-lookup:https://vulnerability.circl.lu"


@pytest.mark.parametrize(
    "header,seconds",
    [
        (None, 0),
        ("120", 120),
        (" 0 ", 0),
        ("-1", 0),
        ("garbage", 0),
        ("Wed, 14 Oct 2026 00:02:00 GMT", 120),
        ("Tue, 13 Oct 2026 00:00:00 GMT", 0),
        ("１２０", 0),
        ("0" * 5000, 0),
    ],
)
def test_retry_after_seconds_dates_and_invalid_values(header, seconds):
    assert retry_after_deadline(header, NOW) == NOW + timedelta(seconds=seconds)


def test_long_server_wait_is_not_capped_to_local_backoff():
    policy = PocRetryPolicy(60, 120)
    state = policy.failure(
        PocSourceState(SOURCE),
        now=NOW,
        error="http_error",
        status=429,
        retry_after="86400",
    )
    assert state.retry_at == (NOW + timedelta(days=1)).isoformat()
    assert retry_after_deadline("9" * 100, NOW) == datetime.max.replace(tzinfo=UTC)


def test_exponential_backoff_is_bounded():
    policy = PocRetryPolicy(10, 25)
    state = PocSourceState(SOURCE)
    for expected in (10, 20, 25, 25):
        state = policy.failure(state, now=NOW, error="transport_error")
        assert state.retry_at == (NOW + timedelta(seconds=expected)).isoformat()
    with pytest.raises(ValueError):
        PocRetryPolicy(100, 10)


class Source:
    source = SOURCE

    def __init__(self, failure: Exception | None = None):
        self.failure = failure
        self.calls = []

    def get_poc_sightings(self, cve):
        self.calls.append(cve)
        if self.failure:
            raise self.failure
        return {"metadata": {"count": 0, "page": 1, "per_page": 1}, "data": []}


@pytest.fixture
def path(tmp_path):
    db = tmp_path / "assets.sqlite3"
    with AssetRegistry(db, create_if_missing=True):
        pass
    return db


def run(path, client, *, now=NOW, cves=(CVE,)):
    with PocStore(path) as store:
        return collect_poc_snapshot(
            PocTargets(cves, ()),
            client,
            clock=lambda: now,
            sleep=lambda _: None,
            repository=store,
        )


def test_restart_and_new_cve_cannot_bypass_provider_wait(path):
    run(path, Source(PocFetchError("http_error", status=429, retry_after="120")))
    before = path.read_bytes()
    waiting = Source()
    result = run(
        path, waiting, now=NOW + timedelta(seconds=119), cves=("CVE-2026-10002",)
    )
    assert waiting.calls == []
    assert result["collection"]["status"] == "partial"
    assert result["collection"]["results"][0]["error"] == "source_cooldown"
    assert (
        result["collection"]["source_state"]["retry_at"]
        == (NOW + timedelta(seconds=120)).isoformat()
    )
    assert path.read_bytes() == before  # skipped runs don't extend the wait
    recovered = Source()
    result = run(path, recovered, now=NOW + timedelta(seconds=120))
    assert recovered.calls == [CVE]
    assert result["collection"]["source_state"]["failures"] == 0
    assert result["collection"]["source_state"]["retry_at"] is None


def test_failure_count_survives_restart_and_does_not_block_other_source(path):
    run(path, Source(PocFetchError("transport_error")))
    result = run(
        path,
        Source(PocFetchError("http_error", status=503)),
        now=NOW + timedelta(seconds=60),
    )
    assert result["collection"]["source_state"]["failures"] == 2
    assert (
        result["collection"]["source_state"]["retry_at"]
        == (NOW + timedelta(seconds=180)).isoformat()
    )
    other = Source()
    other.source = "https://another.invalid"
    run(path, other, now=NOW + timedelta(seconds=61))
    assert other.calls == [CVE]


def test_waiting_keeps_fresh_successes_and_failed_evidence_unchanged(path):
    run(path, Source())
    run(path, Source(PocFetchError("http_error", status=429)), cves=("CVE-2026-10002",))
    client = Source()
    result = run(path, client, cves=(CVE, "CVE-2026-10002"))
    assert client.calls == []
    assert result["collection"]["results"][0]["cached"]
    with PocStore(path, read_only=True) as store:
        assert store.get("CVE-2026-10002", SOURCE).error == "http_error"
        assert store.get(CVE, SOURCE).success.record_count == 0


def test_wait_and_evidence_commit_or_rollback_together(path):
    with PocStore(path) as store:
        record = PocRecord(CVE, SOURCE, NOW.isoformat(), error="http_error")
        state = PocRetryPolicy().failure(
            PocSourceState(SOURCE), now=NOW, error="http_error"
        )
        # A bad record must not leave a source-wide barrier committed by itself.
        with pytest.raises(sqlite3.IntegrityError):
            store.save(replace(record, cve=None), state)
        assert store.source_state(SOURCE).failures == 0
        assert store.get(CVE, SOURCE) is None


def test_http_adapter_carries_retry_after_without_logging_body():
    client = VulnerabilityLookupClient()

    def fail(*args, **kwargs):
        raise HTTPError(
            "https://example.invalid",
            429,
            "private",
            {"Retry-After": "120"},
            BytesIO(b"private"),
        )

    client._opener = SimpleNamespace(open=fail)
    with pytest.raises(PocFetchError) as caught:
        client.get_poc_sightings(CVE)
    assert caught.value.retry_after == "120"
    assert "private" not in str(caught.value)


def test_preview_exposes_wait_without_network_or_changes(
    path, tmp_path, monkeypatch, capsys
):
    # Long future wait makes this CLI test independent of the machine's clock.
    run(
        path,
        Source(PocFetchError("http_error", status=429, retry_after="9999999999999999")),
    )
    before = path.read_bytes()
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps({"status": "succeeded", "assessments": [{"vulnerability_id": CVE}]})
    )
    monkeypatch.setattr(
        "sys.argv",
        ["sbom-ops", "poc-fetch", "--db", str(path), "--findings", str(findings)],
    )
    monkeypatch.setattr(
        cli, "VulnerabilityLookupClient", lambda *a, **k: pytest.fail("network")
    )
    assert cli.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["update_cves"] == []
    assert payload["source_state"]["retry_at"].startswith("9999-")
    assert path.read_bytes() == before


def test_v6_readable_and_backup_preserves_poc_before_v7_migration(path, tmp_path):
    run(path, Source())
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE lifecycle_evidence")
        db.execute("DROP TABLE vulnrichment_snapshots")
        db.execute("DROP TABLE identifier_reviews")
        db.execute("DROP TABLE identifier_observations")
        db.execute("DROP TABLE poc_source_state")
        db.execute("PRAGMA user_version=6")
    before = path.read_bytes()
    with PocStore(path, read_only=True) as store:
        assert store.get(CVE, SOURCE).success.record_count == 0
    with pytest.raises(ValueError, match="v7"):
        PocStore(path)
    assert path.read_bytes() == before
    with AssetRegistry(path) as registry:
        registry.backup_to(tmp_path / "v6.sqlite3")
        registry.migrate()
    with PocStore(path) as store:
        assert store.get(CVE, SOURCE).success.record_count == 0
        assert store.source_state(SOURCE).failures == 0
    with AssetRegistry(tmp_path / "v6.sqlite3", read_only=True) as registry:
        assert registry.schema_version == 6
