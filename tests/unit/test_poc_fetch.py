"""Mock contract: official VL GET /api/sighting/ with page=1, per_page=1.

API: https://www.vulnerability-lookup.org/documentation/api.html
Policy: https://vulnerability.circl.lu/.well-known/api-policy.json
Reviewed 2026-10-13. Synthetic responses; no live payloads or lab imports.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import pytest

from sbom_ops import cli
from sbom_ops.clients.vulnerability_lookup import (
    VulnerabilityLookupClient,
    _NoRedirect,
)
from sbom_ops.domain.advisory import (
    EvidenceFreshness,
    PocReportStatus,
    summarize_poc_reports,
)
from sbom_ops.domain.poc import (
    PocFetchError,
    PocTargets,
    interpret_poc_sightings,
    select_poc_targets,
)
from sbom_ops.services.advisory_snapshot import load_advisory_snapshot
from sbom_ops.services.poc_refresh import collect_poc_snapshot
from sbom_ops.storage.poc_snapshot import save_poc_snapshot

NOW = datetime(2026, 10, 13, tzinfo=UTC)
CVE = "CVE-2021-44228"


def response(count: int = 2) -> dict:
    return {
        "metadata": {"count": count, "page": 1, "per_page": 1},
        "data": (
            [
                {
                    "vulnerability": CVE,
                    "type": "published-proof-of-concept",
                    "creation_timestamp": "2026-10-12T00:00:00Z",
                    "content": "DO NOT RETAIN",
                    "author": {"login": "DO NOT RETAIN"},
                }
            ]
            if count
            else []
        ),
    }


def findings(*ids: str) -> dict:
    return {
        "status": "succeeded",
        "assessments": [
            {"vulnerability_id": value, "vulnerability_aliases": []} for value in ids
        ],
    }


def interpret(payload: object):
    return interpret_poc_sightings(
        payload, cve=CVE, source="test", observed_at=NOW, ttl=timedelta(hours=6)
    )


def test_target_selection_explicit_aliases_and_unresolved() -> None:
    payload = findings(CVE.lower(), "GHSA-explicit", "GHSA-unresolved", CVE)
    payload["assessments"][1]["vulnerability_aliases"] = [CVE, "CVE-2024-12345"]
    targets = select_poc_targets(payload, max_cves=2)
    assert targets == PocTargets((CVE, "CVE-2024-12345"), ("GHSA-unresolved",))
    with pytest.raises(ValueError, match="exceeds"):
        select_poc_targets(payload, max_cves=1)


@pytest.mark.parametrize(
    "ids,status,cves,unresolved",
    [
        ((), "no_findings", 0, 0),
        (("GO-2026-10001", "GO-2026-10001"), "no_resolvable_cves", 0, 1),
        ((CVE, CVE), "resolved", 1, 0),
        ((CVE, "GHSA-unresolved"), "partially_resolved", 1, 1),
    ],
)
def test_target_summary_distinguishes_empty_from_unresolved(
    ids, status, cves, unresolved
):
    targets = select_poc_targets(findings(*ids), max_cves=25)
    assert targets.summary() == {
        "status": status,
        "cve_count": cves,
        "unresolved_id_count": unresolved,
    }


@pytest.mark.parametrize("field", ["description", "references", "related", "upstream"])
def test_cve_mentions_outside_explicit_aliases_do_not_resolve_id(field):
    payload = findings("GO-2026-10001")
    payload["assessments"][0][field] = CVE if field == "description" else [CVE]
    assert select_poc_targets(payload, max_cves=25) == PocTargets(
        (), ("GO-2026-10001",)
    )


@pytest.mark.parametrize("identifier", [None, "GO-2026-10001"])
def test_no_cve_cli_makes_no_request_and_explains_why(
    tmp_path, monkeypatch, capsys, identifier
):
    input_path = tmp_path / "findings.json"
    input_path.write_text(json.dumps(findings(*([identifier] if identifier else []))))
    monkeypatch.setattr(
        VulnerabilityLookupClient,
        "get_poc_sightings",
        lambda *a, **k: pytest.fail("unresolved ID sent to PoC provider"),
    )
    args = cli.build_parser().parse_args(
        ["poc-fetch", "--findings", str(input_path), "--db", str(tmp_path / "db")]
    )
    assert cli.run_poc_fetch(args) == 0
    preview = json.loads(capsys.readouterr().out)
    args.execute = True
    assert cli.run_poc_fetch(args) == (1 if identifier else 0)
    result = json.loads(capsys.readouterr().out)
    assert result["selection"] == preview["selection"]
    assert result["selection"]["status"] == (
        "no_resolvable_cves" if identifier else "no_findings"
    )
    assert result["results"] == []
    assert result["unresolved_ids"] == ([identifier] if identifier else [])


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"status": "failed", "assessments": []},
        {"status": "succeeded", "assessments": [None]},
        {
            "status": "succeeded",
            "assessments": [
                {"vulnerability_id": CVE, "vulnerability_aliases": "alias"}
            ],
        },
    ],
)
def test_invalid_input_is_not_empty_success(payload) -> None:
    with pytest.raises(ValueError):
        select_poc_targets(payload, max_cves=25)


@pytest.mark.parametrize(
    "count,outcome,complete",
    [(0, "not_observed", True), (1, "available", True), (2, "available", False)],
)
def test_provider_count_not_unique_exploit_count(count, outcome, complete) -> None:
    observation = interpret(response(count))
    assert observation.outcome.value == outcome
    assert observation.record_count == count
    assert observation.complete is complete
    assert "DO NOT RETAIN" not in json.dumps(observation.as_dict())
    assert observation.effective_freshness(now=NOW) == EvidenceFreshness.FRESH
    assert (
        observation.effective_freshness(now=NOW + timedelta(hours=6))
        == EvidenceFreshness.STALE
    )
    assert (
        observation.effective_freshness(now=NOW - timedelta(seconds=1))
        == EvidenceFreshness.UNKNOWN
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["metadata"].update(count=True),
        lambda p: p["metadata"].update(count=-1),
        lambda p: p["metadata"].update(count=0),
        lambda p: p["metadata"].update(page=2),
        lambda p: p["data"].clear(),
        lambda p: p["data"][0].update(vulnerability="CVE-2024-9999"),
        lambda p: p["data"][0].update(type="exploited"),
        lambda p: p["data"][0].update(creation_timestamp="2026-10-14T00:00:00Z"),
        lambda p: p["data"][0].update(creation_timestamp="2026-10-12T00:00:00"),
    ],
)
def test_invalid_or_future_sighting_cannot_be_evidence(mutate) -> None:
    payload = response()
    mutate(payload)
    with pytest.raises(ValueError):
        interpret(payload)


class FakeSource:
    source = "vulnerability-lookup:https://example.invalid"

    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[str] = []

    def get_poc_sightings(self, cve: str) -> object:
        self.calls.append(cve)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_transport_failure_stops_batch_and_never_means_absent(status) -> None:
    client = FakeSource(PocFetchError("http_error", status=status))
    pauses = []
    snapshot = collect_poc_snapshot(
        PocTargets((CVE, "CVE-2024-12345"), ()),
        client,
        clock=lambda: NOW,
        sleep=pauses.append,
    )
    assert client.calls == [CVE]
    assert pauses == []
    assert snapshot["collection"]["status"] == "partial"
    assert all(
        o["outcome"] == "unknown" for o in snapshot["vulnerability_observations"]
    )
    results = snapshot["collection"]["results"]
    assert results[0]["http_status"] == status
    assert results[0]["last_success_at"] is None
    assert results[1]["attempted"] is False


def test_pacing_and_roundtrip_to_existing_snapshot_reader(tmp_path) -> None:
    client = FakeSource(response(0))
    pauses = []
    snapshot = collect_poc_snapshot(
        PocTargets((CVE, "CVE-2024-12345"), ("GHSA-unresolved",)),
        client,
        clock=lambda: NOW,
        sleep=pauses.append,
    )
    path = tmp_path / "snapshot.json"
    save_poc_snapshot(path, snapshot)
    loaded = load_advisory_snapshot(path)
    assert len(loaded.vulnerability_observations) == 2
    assert pauses == [3.1]
    assert snapshot["collection"]["status"] == "partial"
    assert snapshot["collection"]["results"][0]["last_success_at"] == NOW.isoformat()
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        save_poc_snapshot(path, {})
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_bad_envelope_saved_as_unknown(tmp_path) -> None:
    snapshot = collect_poc_snapshot(
        PocTargets((CVE,), ()), FakeSource({}), clock=lambda: NOW
    )
    path = tmp_path / "snapshot.json"
    save_poc_snapshot(path, snapshot)
    loaded = load_advisory_snapshot(path)
    assert (
        summarize_poc_reports(loaded.vulnerability_observations).status
        == PocReportStatus.UNKNOWN
    )
    assert snapshot["collection"]["results"][0]["error"] == "invalid_response"


def test_collected_report_joins_primary_cve_or_explicit_alias_only(tmp_path) -> None:
    snapshot = collect_poc_snapshot(
        PocTargets((CVE,), ()), FakeSource(response()), clock=lambda: NOW
    )
    path = tmp_path / "poc.json"
    save_poc_snapshot(path, snapshot)
    loaded = load_advisory_snapshot(path)
    primary = loaded.observations_for(CVE)
    alias = loaded.observations_for("GHSA-explicit", (CVE,))
    assert primary == alias
    assert summarize_poc_reports(primary, now=NOW).status == PocReportStatus.REPORTED
    assert loaded.observations_for("GHSA-unresolved") == ()


@pytest.mark.parametrize(
    "kwargs",
    [{"ttl_seconds": 0}, {"pacing_seconds": 0}, {"pacing_seconds": float("nan")}],
)
def test_bad_collection_settings_fail_before_network(kwargs) -> None:
    client = FakeSource(response())
    with pytest.raises(ValueError):
        collect_poc_snapshot(PocTargets((CVE,), ()), client, **kwargs)
    assert client.calls == []


class Reply(BytesIO):
    status = 200


def test_client_only_sends_cve_and_filter_and_optional_key() -> None:
    client = VulnerabilityLookupClient(api_key="test-only-key")
    captured = []

    def open_request(req, *, timeout):
        captured.append(req)
        assert timeout == 30
        return Reply(json.dumps(response()).encode())

    client._opener = SimpleNamespace(open=open_request)
    assert client.get_poc_sightings(CVE) == response()
    req = captured[0]
    assert urlsplit(req.full_url).path == "/api/sighting/"
    assert parse_qs(urlsplit(req.full_url).query) == {
        "vuln_id": [CVE],
        "type": ["published-proof-of-concept"],
        "page": ["1"],
        "per_page": ["1"],
    }
    assert req.get_header("X-api-key") == "test-only-key"
    assert "content" not in req.get_header("X-fields")
    assert (
        _NoRedirect().redirect_request(
            req, None, 302, "", {}, "https://elsewhere.invalid"
        )
        is None
    )


@pytest.mark.parametrize("body", [b"not JSON", b"x" * (1024 * 1024 + 1)])
def test_client_bounds_and_sanitizes_response(body) -> None:
    client = VulnerabilityLookupClient()
    client._opener = SimpleNamespace(open=lambda *a, **k: Reply(body))
    with pytest.raises(PocFetchError) as exc:
        client.get_poc_sightings(CVE)
    assert str(exc.value) in {"invalid_json", "response_too_large"}


def test_client_sanitizes_http_error() -> None:
    client = VulnerabilityLookupClient()

    def fail(*args, **kwargs):
        raise HTTPError(
            "https://example.invalid", 429, "PRIVATE", {}, BytesIO(b"PRIVATE")
        )

    client._opener = SimpleNamespace(open=fail)
    with pytest.raises(PocFetchError) as exc:
        client.get_poc_sightings(CVE)
    assert exc.value.status == 429
    assert "PRIVATE" not in str(exc.value)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.invalid",
        "https://key@example.invalid",
        "https://example.invalid/?key=x",
    ],
)
def test_unsafe_source_url_rejected(url) -> None:
    with pytest.raises(ValueError):
        VulnerabilityLookupClient(url)


def test_cli_preview_has_no_network_or_config_or_writes(
    tmp_path, monkeypatch, capsys
) -> None:
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(findings(CVE)))

    def forbidden(*args, **kwargs):
        pytest.fail("preview must not construct a client or load DT/GitHub config")

    monkeypatch.setattr(cli, "VulnerabilityLookupClient", forbidden)
    monkeypatch.setattr(cli, "load_config", forbidden)
    monkeypatch.setattr("sys.argv", ["sbom-ops", "poc-fetch", "--findings", str(path)])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["cves"] == [CVE]
    assert list(tmp_path.iterdir()) == [path]


def test_cli_execute_and_failure_exit_code(tmp_path, monkeypatch, capsys) -> None:
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(findings(CVE)))
    output = tmp_path / "poc.json"
    monkeypatch.setattr(
        cli, "VulnerabilityLookupClient", lambda *a, **k: FakeSource({})
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "sbom-ops",
            "poc-fetch",
            "--findings",
            str(path),
            "--execute",
            "--db",
            str(tmp_path / "assets.sqlite3"),
            "--output",
            str(output),
        ],
    )
    assert cli.main() == 1
    assert json.loads(capsys.readouterr().out)["status"] == "partial"
    assert (
        load_advisory_snapshot(output).vulnerability_observations[0].outcome.value
        == "unknown"
    )
    assert cli.main() == 2  # previous evidence is never overwritten
