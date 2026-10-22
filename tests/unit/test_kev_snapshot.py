import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from sbom_ops.clients import kev as kev_module
from sbom_ops.clients.http import HttpApiError
from sbom_ops.clients.kev import KevApiError, KevClient
from sbom_ops.domain.kev import KevSnapshot, catalog_details
from sbom_ops.domain.triage_evidence import TriageValue

NOW = datetime(2026, 10, 22, tzinfo=UTC)


def test_incomplete_catalog_cannot_assert_absence() -> None:
    snapshot = KevSnapshot(
        "https://cisa.example/feed",
        frozenset(),
        NOW,
        NOW + timedelta(hours=1),
        "fetched",
    )
    assert snapshot.membership("CVE-2026-0001", now=NOW) is TriageValue.UNKNOWN


def complete_snapshot() -> KevSnapshot:
    return KevSnapshot(
        "https://cisa.example/feed",
        frozenset({"CVE-2026-0001"}),
        NOW,
        NOW + timedelta(hours=1),
        "fetched",
        "2026.10.22",
        NOW - timedelta(days=1),
        True,
    )


def test_complete_fresh_membership() -> None:
    snapshot = complete_snapshot()
    assert snapshot.membership("CVE-2026-0001", now=NOW) is TriageValue.YES
    assert snapshot.membership("CVE-2026-0002", now=NOW) is TriageValue.NO


@pytest.mark.parametrize(
    "cve", ["GHSA-example", "cve-2026-0001", "CVE-2026-0001\n", ""]
)
def test_unresolved_identity_is_unknown(cve: str) -> None:
    assert complete_snapshot().membership(cve, now=NOW) is TriageValue.UNKNOWN


@pytest.mark.parametrize("seconds", [-1, 3600, 3601])
@pytest.mark.parametrize("cve", ["CVE-2026-0001", "CVE-2026-0002"])
def test_time_boundaries_do_not_assert_membership(seconds: int, cve: str) -> None:
    assert (
        complete_snapshot().membership(cve, now=NOW + timedelta(seconds=seconds))
        is TriageValue.UNKNOWN
    )


def test_stale_and_future_release_are_unknown() -> None:
    for snapshot in (
        replace(complete_snapshot(), mode="stale"),
        replace(complete_snapshot(), released_at=NOW + timedelta(seconds=1)),
        replace(complete_snapshot(), expires_at=NOW),
    ):
        assert snapshot.membership("CVE-2026-0002", now=NOW) is TriageValue.UNKNOWN


def test_revision_tracks_content_not_revalidation_time() -> None:
    snapshot = complete_snapshot()
    assert (
        replace(
            snapshot, mode="revalidated", checked_at=NOW + timedelta(minutes=1)
        ).revision
        == snapshot.revision
    )
    assert replace(snapshot, catalog_version="next").revision != snapshot.revision
    assert replace(snapshot, cve_ids=frozenset()).revision != snapshot.revision
    assert (
        replace(snapshot, source="https://other.example/feed").revision
        != snapshot.revision
    )


def test_mutable_input_cannot_change_snapshot() -> None:
    ids = {"CVE-2026-0001"}
    snapshot = replace(complete_snapshot(), cve_ids=ids)
    ids.clear()
    assert snapshot.membership("CVE-2026-0001", now=NOW) is TriageValue.YES


@pytest.mark.parametrize(
    "changes",
    [
        {"complete": 1},
        {"catalog_version": None},
        {"released_at": None},
        {"cve_ids": frozenset({"bad-id"})},
        {"mode": "failed"},
        {"checked_at": NOW.replace(tzinfo=None)},
        {"expires_at": NOW - timedelta(seconds=1)},
    ],
)
def test_invalid_snapshot_is_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        replace(complete_snapshot(), **changes)


def test_naive_evaluation_time_rejected() -> None:
    with pytest.raises(ValueError):
        complete_snapshot().membership("CVE-2026-0001", now=NOW.replace(tzinfo=None))


def catalog() -> dict[str, object]:
    return {
        "catalogVersion": "2026.10.22",
        "dateReleased": NOW.isoformat(),
        "count": 1,
        "vulnerabilities": [{"cveID": "CVE-2026-0001"}],
    }


def test_catalog_coverage_contract() -> None:
    assert catalog_details(catalog()) == {
        "version": "2026.10.22",
        "released_at": NOW.isoformat(),
        "count": 1,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"catalogVersion": ""},
        {"catalogVersion": None},
        {"count": True},
        {"count": 2},
        {"count": -1},
        {"dateReleased": "2026-10-22"},
        {"dateReleased": "bad-date"},
        {"vulnerabilities": [None]},
        {"vulnerabilities": [{"cveID": "CVE-２０２６-0001"}]},
        {"vulnerabilities": [{"cveID": "CVE-2026-0001"}] * 2, "count": 2},
    ],
)
def test_incomplete_catalog_is_not_coverage_evidence(
    changes: dict[str, object],
) -> None:
    assert catalog_details(catalog() | changes) is None


def test_fetch_cache_revalidation_and_stale(monkeypatch, tmp_path) -> None:
    clock = [NOW.timestamp()]
    monkeypatch.setattr(kev_module.time, "time", lambda: clock[0])
    calls = []

    def fetch(request, **kwargs):
        calls.append(request)
        return catalog(), {"ETag": "synthetic-version"}

    monkeypatch.setattr(kev_module, "request_json", fetch)
    client = KevClient(
        "https://cisa.example/feed",
        cache_path=str(tmp_path / "kev.json"),
        cache_ttl_seconds=60,
        allow_stale_cache=True,
    )
    fetched = client.get_snapshot()
    assert fetched.complete and fetched.mode == "fetched"
    assert fetched.membership("CVE-2026-0002", now=NOW) is TriageValue.NO
    clock[0] += 10
    cached = client.get_snapshot()
    assert cached.mode == "cache" and len(calls) == 1
    assert cached.checked_at == fetched.checked_at
    assert cached.expires_at == fetched.expires_at

    def unchanged(request, **kwargs):
        assert request.get_header("If-none-match") == "synthetic-version"
        raise HttpApiError("not modified", status=304)

    monkeypatch.setattr(kev_module, "request_json", unchanged)
    refreshed = client.get_snapshot(force_refresh=True)
    assert refreshed.mode == "revalidated"
    assert refreshed.revision == fetched.revision
    assert refreshed.checked_at == NOW + timedelta(seconds=10)
    assert refreshed.expires_at == NOW + timedelta(seconds=70)

    def unavailable(*args, **kwargs):
        raise HttpApiError("offline")

    monkeypatch.setattr(kev_module, "request_json", unavailable)
    stale = client.get_snapshot(force_refresh=True)
    assert stale.mode == "stale" and client.used_stale_cache
    assert stale.checked_at == refreshed.checked_at
    assert (
        stale.membership("CVE-2026-0001", now=NOW + timedelta(seconds=10))
        is TriageValue.UNKNOWN
    )
    strict = KevClient(
        "https://cisa.example/feed", cache_path=str(tmp_path / "kev.json")
    )
    assert strict.get_snapshot().mode == "cache"
    with pytest.raises(KevApiError):
        strict.get_snapshot(force_refresh=True)
    assert strict.last_snapshot is None


@pytest.mark.parametrize("version", [None, 1])
def test_old_cache_cannot_gain_completeness_from_304(
    monkeypatch, tmp_path, version
) -> None:
    record = {
        "fetched_at": NOW.timestamp() - 100,
        "cve_ids": ["CVE-2026-0001"],
        "metadata": {"etag": "old"},
    }
    if version is not None:
        record["schema_version"] = version
        record["sha256"] = kev_module._cache_digest(record)
    path = tmp_path / "kev.json"
    path.write_text(json.dumps(record))
    monkeypatch.setattr(kev_module.time, "time", lambda: NOW.timestamp())

    def unchanged(*args, **kwargs):
        raise HttpApiError("not modified", status=304)

    monkeypatch.setattr(kev_module, "request_json", unchanged)
    snapshot = KevClient(
        "https://cisa.example/feed", cache_path=str(path), cache_ttl_seconds=60
    ).get_snapshot()
    assert snapshot.mode == "revalidated" and not snapshot.complete
    assert snapshot.membership("CVE-2026-0002", now=NOW) is TriageValue.UNKNOWN


@pytest.mark.parametrize("change", ["source", "catalog", "digest"])
def test_invalid_v2_cache_is_not_stale_fallback(monkeypatch, tmp_path, change) -> None:
    path = tmp_path / "kev.json"
    monkeypatch.setattr(kev_module.time, "time", lambda: NOW.timestamp())
    monkeypatch.setattr(kev_module, "request_json", lambda *a, **k: (catalog(), {}))
    client = KevClient(
        "https://cisa.example/feed", cache_path=str(path), allow_stale_cache=True
    )
    client.get_snapshot()
    record = json.loads(path.read_text())
    if change == "source":
        record["source"] = "https://other.example/feed"
    elif change == "catalog":
        record["catalog"]["count"] = 2
    else:
        record["sha256"] = "0" * 64
    if change != "digest":
        record.pop("sha256")
        record["sha256"] = kev_module._cache_digest(record)
    path.write_text(json.dumps(record))

    def unavailable(*args, **kwargs):
        raise HttpApiError("offline")

    monkeypatch.setattr(kev_module, "request_json", unavailable)
    with pytest.raises(KevApiError):
        client.get_snapshot(force_refresh=True)
    assert client.last_snapshot is None and not client.used_stale_cache
