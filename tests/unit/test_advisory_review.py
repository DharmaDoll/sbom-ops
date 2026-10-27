import json
import socket
from pathlib import Path

import pytest

from sbom_ops.domain.advisory_feed import AdvisoryFeedItem
from sbom_ops.services.advisory_review import review_advisories
from sbom_ops.services.orchestrator import RunResult


def snapshot(path: Path) -> str:
    payload = RunResult(
        run_id="saved-run",
        duration_seconds=0,
        kev_used_stale_cache=False,
        projects_processed=0,
        findings_processed=0,
        issues_created=0,
        issues_updated=0,
        issues_closed=0,
        dry_run=True,
    ).as_dict()
    raw = json.dumps(payload)
    path.write_text(raw)
    return raw


def test_no_cve_and_no_match_are_distinct_offline(tmp_path, monkeypatch):
    path = tmp_path / "sync.json"
    raw = snapshot(path)

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    items = (
        AdvisoryFeedItem("jpcert", "one", "https://example.org/1", "Notice"),
        AdvisoryFeedItem(
            "jpcert",
            "two",
            "https://example.org/2",
            "Notice",
            (("description", "CVE-2026-1234 CVE-2026-5678 private body"),),
        ),
    )
    result = review_advisories(items, path)
    assert result["scope"] == "saved_sync_only"
    assert result["source_run_id"] == "saved-run"
    assert result["articles"][0]["status"] == "cve_not_observed"
    assert result["articles"][1]["status"] == "cve_observed"
    assert result["articles"][1]["cves"] == ["CVE-2026-1234", "CVE-2026-5678"]
    assert all(r["status"] == "no_match_in_input" for r in result["lookups"].values())
    assert "private body" not in json.dumps(result)
    assert result["warnings"]
    assert path.read_text() == raw


def test_invalid_snapshot_not_disguised_as_no_match(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"status":"failed"}')
    with pytest.raises(ValueError):
        review_advisories((), path)


def test_duplicate_article_rejected(tmp_path):
    path = tmp_path / "sync.json"
    snapshot(path)
    item = AdvisoryFeedItem("jpcert", "one", "https://example.org/1", "Notice")
    with pytest.raises(ValueError):
        review_advisories((item, item), path)


def test_match_keeps_asset_context_and_reads_snapshot_once(tmp_path, monkeypatch):
    from test_lookup_input import context_run

    import sbom_ops.services.advisory_review as service

    payload = context_run()
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    original = service.read_lookup_document
    calls = []

    def read_once(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(service, "read_lookup_document", read_once)
    items = tuple(
        AdvisoryFeedItem("jpcert", key, "https://example.org/" + key, "CVE-2026-1234")
        for key in ("one", "two")
    )
    result = review_advisories(items, path)
    assert calls == [path]
    assert len(result["articles"]) == 2
    assert len(result["lookups"]) == 1
    lookup = result["lookups"]["CVE-2026-1234"]
    assert lookup["status"] == "matched"
    assert lookup["source_run_id"] == "example-run"
    assert lookup["results"][0]["finding"] == payload["review_queue"][0]
    assert "team-shop" in json.dumps(lookup)
    assert "expired" in json.dumps(lookup)
