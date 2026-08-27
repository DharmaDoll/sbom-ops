from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbom_ops.clients import dependency_track as dependency_track_module
from sbom_ops.clients.dependency_track import (
    DependencyTrackApiError,
    DependencyTrackClient,
)
from sbom_ops.clients.http import HttpJsonResponse

FIXTURES = Path(__file__).parents[1] / "fixtures"


def load_fixture(name: str) -> object:
    return json.loads((FIXTURES / name).read_text())


def test_dependency_track_finding_is_normalized() -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": load_fixture(
            "dependency-track-findings.json"
        ),
        "/api/v1/vulnerability/project/project-1": load_fixture(
            "dependency-track-vulnerabilities.json"
        ),
    }
    client._request_json = lambda path, params=None: payloads[path]  # type: ignore[method-assign]

    findings = client.get_project_findings("project-1")

    assert findings[0].vulnerability_id == "CVE-2026-0001"
    assert findings[0].vulnerability_source == "NVD"
    assert findings[0].component_uuid == "component-1"
    assert findings[0].component_purl == "pkg:generic/openssl@3.0.0"
    assert findings[0].epss_score == 0.91
    assert findings[0].analysis_state == "NOT_SET"
    assert findings[0].cwes == (78,)
    assert findings[1].analysis_state == "NOT_AFFECTED"
    assert findings[1].epss_score == 0.82


def test_bom_upload_returns_processing_token(monkeypatch, tmp_path) -> None:
    bom_path = tmp_path / "bom.json"
    bom_path.write_text('{"bomFormat":"CycloneDX"}')
    captured = {}

    def fake_request_json(request, **kwargs):
        captured["request"] = request
        return {"token": "token-1"}

    monkeypatch.setattr(dependency_track_module, "request_json", fake_request_json)

    result = DependencyTrackClient("https://dtrack.example", "api-key").upload_bom(
        "project-1", bom_path
    )

    assert result.token == "token-1"
    assert captured["request"].get_method() == "POST"
    assert b'name="project"' in captured["request"].data
    assert b"project-1" in captured["request"].data


def test_bom_upload_by_project_coordinates_uses_auto_create(
    monkeypatch, tmp_path
) -> None:
    bom_path = tmp_path / "bom.json"
    bom_path.write_text('{"bomFormat":"CycloneDX"}')
    captured = {}

    def fake_request_json(request, **kwargs):
        captured["request"] = request
        return {"token": "token-2"}

    monkeypatch.setattr(dependency_track_module, "request_json", fake_request_json)

    result = DependencyTrackClient(
        "https://dtrack.example", "api-key"
    ).upload_bom_by_project_coordinates("dt-lab", "1.0.0", bom_path)

    assert result.token == "token-2"
    body = captured["request"].data
    assert b'name="autoCreate"' in body
    assert b"true" in body
    assert b'name="projectName"' in body
    assert b"dt-lab" in body
    assert b'name="projectVersion"' in body
    assert b"1.0.0" in body


def test_dependency_track_observation_records_safe_metadata(monkeypatch) -> None:
    def fake_request_json(request, **kwargs):
        assert kwargs["return_response"] is True
        return HttpJsonResponse(
            payload={"uuid": "project-1"},
            status=200,
            headers={
                "Content-Type": "application/json",
                "X-Total-Count": "1",
                "Set-Cookie": "must-not-be-recorded",
            },
            duration_seconds=0.25,
        )

    monkeypatch.setattr(dependency_track_module, "request_json", fake_request_json)

    observation = DependencyTrackClient(
        "https://dtrack.example", "api-key"
    ).observe_project_lookup("dt lab", "1.0.0")

    assert observation.path == "/api/v1/project/lookup"
    assert observation.query == (("name", "dt lab"), ("version", "1.0.0"))
    assert observation.status == 200
    assert dict(observation.headers) == {
        "Content-Type": "application/json",
        "X-Total-Count": "1",
    }
    assert observation.duration_seconds == 0.25


def test_wait_for_bom_processing_polls_until_complete(monkeypatch) -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    responses = iter([{"processing": True}, {"processing": False}])
    client._request_json = lambda path, params=None: next(responses)  # type: ignore[method-assign]
    monkeypatch.setattr(dependency_track_module.time, "sleep", lambda _: None)

    client.wait_for_bom_processing("token-1", timeout=1, poll_interval=0)


def test_project_listing_uses_offset_limit_pagination() -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key", page_size=2)
    requests: list[dict[str, str] | None] = []
    pages = {
        0: [{"uuid": "project-1", "name": "one"}, {"uuid": "project-2", "name": "two"}],
        2: [{"uuid": "project-3", "name": "three"}],
    }

    def fake_request(path, params=None):
        requests.append(params)
        offset = int(params["offset"]) if params else 0
        return pages[offset]

    client._request_json = fake_request  # type: ignore[method-assign]

    projects = client.list_projects()

    assert [project.uuid for project in projects] == [
        "project-1",
        "project-2",
        "project-3",
    ]
    assert requests == [
        {"offset": "0", "limit": "2"},
        {"offset": "2", "limit": "2"},
    ]


def test_project_listing_rejects_a_repeated_pagination_page() -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key", page_size=1)
    client._request_json = lambda path, params=None: [  # type: ignore[method-assign]
        {"uuid": "project-1", "name": "one"}
    ]

    with pytest.raises(DependencyTrackApiError, match="pagination did not advance"):
        client.list_projects()


def test_finding_without_vulnerability_identifier_is_rejected() -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": [{"component": {"name": "openssl"}}],
        "/api/v1/vulnerability/project/project-1": [],
    }
    client._request_json = lambda path, params=None: payloads[path]  # type: ignore[method-assign]

    with pytest.raises(DependencyTrackApiError, match="no vulnerability identifier"):
        client.get_project_findings("project-1")


def test_dependency_track_http_failure_is_normalized(monkeypatch) -> None:
    def fail_request(*args, **kwargs):
        raise dependency_track_module.HttpApiError("upstream", status=503)

    monkeypatch.setattr(dependency_track_module, "request_json", fail_request)

    with pytest.raises(DependencyTrackApiError, match="HTTP 503"):
        DependencyTrackClient("https://dtrack.example", "api-key").list_projects()
