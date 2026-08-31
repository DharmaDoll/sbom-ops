from __future__ import annotations

import json

import pytest
from dt_lab import client as client_module
from dt_lab.client import DependencyTrackLabApiError, DependencyTrackLabClient
from dt_lab.domain import (
    AnalysisAction,
    AnalysisJustification,
    AnalysisResponse,
    AnalysisState,
    DependencyTrackObservation,
)

from sbom_ops.clients.http import HttpApiError, HttpJsonResponse


def test_bom_upload_by_project_coordinates_uses_auto_create(
    monkeypatch, tmp_path
) -> None:
    bom_path = tmp_path / "bom.json"
    bom_path.write_text('{"bomFormat":"CycloneDX"}')
    captured = {}

    def fake_request_json(request, **kwargs):
        captured["request"] = request
        return {"token": "token-2"}

    monkeypatch.setattr(client_module, "request_json", fake_request_json)

    result = DependencyTrackLabClient(
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


def test_vex_upload_uses_existing_project_and_multipart_document(
    monkeypatch, tmp_path
) -> None:
    vex_path = tmp_path / "decision.cdx.json"
    vex_path.write_text('{"bomFormat":"CycloneDX","vulnerabilities":[]}')
    captured = {}

    def fake_request_json(request, **kwargs):
        captured["request"] = request
        return {"token": "vex-token-1"}

    monkeypatch.setattr(client_module, "request_json", fake_request_json)

    result = DependencyTrackLabClient(
        "https://dtrack.example", "analysis-key"
    ).upload_vex_for_project("project-1", vex_path)

    request = captured["request"]
    assert result.token == "vex-token-1"
    assert request.method == "POST"
    assert request.full_url.endswith("/api/v1/vex")
    assert request.get_header("Content-type").startswith("multipart/form-data;")
    assert b'name="project"' in request.data
    assert b"project-1" in request.data
    assert b'name="vex"; filename="decision.cdx.json"' in request.data
    assert b"application/vnd.cyclonedx+json" in request.data
    assert vex_path.read_bytes() in request.data


def test_observation_records_safe_metadata(monkeypatch) -> None:
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

    monkeypatch.setattr(client_module, "request_json", fake_request_json)

    observation = DependencyTrackLabClient(
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


def test_observes_direct_components_and_services() -> None:
    client = DependencyTrackLabClient("https://dtrack.example", "api-key")
    requests: list[tuple[str, str, dict[str, str] | None]] = []

    def fake_observe(path, params=None):
        requests.append(("single", path, params))
        return DependencyTrackObservation(
            method="GET",
            path=path,
            query=tuple(sorted((params or {}).items())),
            status=200,
            headers=(),
            duration_seconds=0.01,
            payload={},
        )

    def fake_paginated_observe(path, params=None):
        requests.append(("paginated", path, params))
        return DependencyTrackObservation(
            method="GET",
            path=path,
            query=tuple(sorted((params or {}).items())),
            status=200,
            headers=(),
            duration_seconds=0.01,
            payload=[],
        )

    client._observe_json = fake_observe  # type: ignore[method-assign]
    client._observe_paginated_json = fake_paginated_observe  # type: ignore[method-assign]

    client.observe_project_direct_components("project-1")
    client.observe_project_services("project-1")

    assert requests == [
        (
            "paginated",
            "/api/v1/component/project/project-1",
            {"onlyDirect": "true"},
        ),
        ("single", "/api/v1/service/project/project-1", None),
    ]


def test_observes_every_component_page() -> None:
    client = DependencyTrackLabClient("https://dtrack.example", "api-key")
    requests: list[dict[str, str]] = []

    def fake_observe(path, params=None):
        assert path == "/api/v1/component/project/project-1"
        assert params is not None
        requests.append(params)
        page_number = int(params["pageNumber"])
        start = (page_number - 1) * 100
        stop = min(start + 100, 205)
        return DependencyTrackObservation(
            method="GET",
            path=path,
            query=tuple(sorted(params.items())),
            status=200,
            headers=(("X-Total-Count", "205"),),
            duration_seconds=0.1,
            payload=[{"index": index} for index in range(start, stop)],
        )

    client._observe_json = fake_observe  # type: ignore[method-assign]

    observation = client.observe_project_components("project-1")

    assert [item["index"] for item in observation.payload] == list(range(205))
    assert [request["pageNumber"] for request in requests] == ["1", "2", "3"]
    assert observation.query == (("pageSize", "100"),)
    assert observation.duration_seconds == pytest.approx(0.3)


def test_paginated_observation_rejects_incomplete_total() -> None:
    client = DependencyTrackLabClient("https://dtrack.example", "api-key")

    def fake_observe(path, params=None):
        return DependencyTrackObservation(
            method="GET",
            path=path,
            query=(),
            status=200,
            headers=(("x-total-count", "101"),),
            duration_seconds=0.1,
            payload=[{"index": index} for index in range(99)],
        )

    client._observe_json = fake_observe  # type: ignore[method-assign]

    with pytest.raises(DependencyTrackLabApiError, match="ended before X-Total-Count"):
        client.observe_project_components("project-1")


def test_bom_export_requests_cyclonedx_json(monkeypatch) -> None:
    captured = {}

    def fake_request_json(request, **kwargs):
        captured["request"] = request
        return HttpJsonResponse(
            payload={"bomFormat": "CycloneDX"},
            status=200,
            headers={"Content-Type": "application/vnd.cyclonedx+json"},
            duration_seconds=0.01,
        )

    monkeypatch.setattr(client_module, "request_json", fake_request_json)

    observation = DependencyTrackLabClient(
        "https://dtrack.example", "api-key"
    ).observe_project_bom_export("project-1")

    assert captured["request"].get_header("Accept") == (
        "application/vnd.cyclonedx+json"
    )
    assert observation.payload == {"bomFormat": "CycloneDX"}


def test_vex_export_requests_cyclonedx_json(monkeypatch) -> None:
    captured = {}

    def fake_request_json(request, **kwargs):
        captured["request"] = request
        return HttpJsonResponse(
            payload={"bomFormat": "CycloneDX", "specVersion": "1.5"},
            status=200,
            headers={"Content-Type": "application/vnd.cyclonedx+json"},
            duration_seconds=0.01,
        )

    monkeypatch.setattr(client_module, "request_json", fake_request_json)

    observation = DependencyTrackLabClient(
        "https://dtrack.example", "api-key"
    ).observe_project_vex_export("project-1")

    assert captured["request"].get_header("Accept") == (
        "application/vnd.cyclonedx+json"
    )
    assert captured["request"].full_url.endswith(
        "/api/v1/vex/cyclonedx/project/project-1?download=false&version=1.5"
    )
    assert observation.payload["specVersion"] == "1.5"


def test_wait_for_bom_processing_polls_until_complete(monkeypatch) -> None:
    client = DependencyTrackLabClient("https://dtrack.example", "api-key")
    responses = iter([{"processing": True}, {"processing": False}])
    client._request_json = lambda path, params=None: next(responses)  # type: ignore[method-assign]
    monkeypatch.setattr(client_module.time, "sleep", lambda _: None)

    client.wait_for_bom_processing("token-1", timeout=1, poll_interval=0)


def test_records_analysis_decision_with_documented_payload(monkeypatch) -> None:
    captured = {}

    def fake_request_json(request, **kwargs):
        captured["request"] = request
        captured["kwargs"] = kwargs
        return HttpJsonResponse(
            payload={"analysisState": "IN_TRIAGE", "isSuppressed": False},
            status=200,
            headers={"Content-Type": "application/json"},
            duration_seconds=0.01,
        )

    monkeypatch.setattr(client_module, "request_json", fake_request_json)
    action = AnalysisAction(
        id="begin-triage",
        component_purl="pkg:maven/example/component@1.0.0",
        vulnerability_id="CVE-2026-0001",
        vulnerability_source="NVD",
        state=AnalysisState.IN_TRIAGE,
        justification=AnalysisJustification.NOT_SET,
        response=AnalysisResponse.NOT_SET,
        detail="Synthetic detail.",
        comment="Synthetic comment.",
        suppressed=False,
    )

    observation = DependencyTrackLabClient(
        "https://dtrack.example", "analysis-key"
    ).record_analysis_decision(
        project_uuid="project-1",
        component_uuid="component-1",
        vulnerability_uuid="vulnerability-1",
        action=action,
    )

    request = captured["request"]
    payload = json.loads(request.data.decode("utf-8"))
    assert request.method == "PUT"
    assert request.full_url.endswith("/api/v1/analysis")
    assert request.get_header("Content-type") == "application/json"
    assert payload == {
        "project": "project-1",
        "component": "component-1",
        "vulnerability": "vulnerability-1",
        "analysisState": "IN_TRIAGE",
        "analysisJustification": "NOT_SET",
        "analysisResponse": "NOT_SET",
        "analysisDetails": "Synthetic detail.",
        "comment": "Synthetic comment.",
        "isSuppressed": False,
    }
    assert captured["kwargs"]["return_response"] is True
    assert observation.request_payload == payload


def test_observes_analysis_trail_with_all_finding_coordinates() -> None:
    client = DependencyTrackLabClient("https://dtrack.example", "read-key")
    requests: list[tuple[str, dict[str, str] | None]] = []

    def fake_observe(path, params=None):
        requests.append((path, params))
        return DependencyTrackObservation(
            method="GET",
            path=path,
            query=tuple(sorted((params or {}).items())),
            status=200,
            headers=(),
            duration_seconds=0.01,
            payload={},
        )

    client._observe_json = fake_observe  # type: ignore[method-assign]

    client.observe_analysis_trail("project-1", "component-1", "vulnerability-1")

    assert requests == [
        (
            "/api/v1/analysis",
            {
                "project": "project-1",
                "component": "component-1",
                "vulnerability": "vulnerability-1",
            },
        )
    ]


def test_observes_current_team_for_least_privilege_preflight() -> None:
    client = DependencyTrackLabClient("https://dtrack.example", "analysis-key")
    requests: list[str] = []

    def fake_observe(path, params=None):
        requests.append(path)
        return DependencyTrackObservation(
            method="GET",
            path=path,
            query=(),
            status=200,
            headers=(),
            duration_seconds=0.01,
            payload={"permissions": [{"name": "VULNERABILITY_ANALYSIS"}]},
        )

    client._observe_json = fake_observe  # type: ignore[method-assign]

    client.observe_current_team()

    assert requests == ["/api/v1/team/self"]


def test_delete_project_requires_a_204_empty_response(monkeypatch) -> None:
    captured = {}

    def fake_request_json(request, **kwargs):
        captured["request"] = request
        captured["kwargs"] = kwargs
        return HttpJsonResponse(
            payload=None,
            status=204,
            headers={},
            duration_seconds=0.01,
        )

    monkeypatch.setattr(client_module, "request_json", fake_request_json)

    DependencyTrackLabClient("https://dtrack.example", "cleanup-key").delete_project(
        "018f6aca-9705-7f61-a36b-4f16ec3b1f4a"
    )

    request = captured["request"]
    assert request.method == "DELETE"
    assert request.full_url.endswith(
        "/api/v1/project/018f6aca-9705-7f61-a36b-4f16ec3b1f4a"
    )
    assert request.get_header("X-api-key") == "cleanup-key"
    assert captured["kwargs"]["allow_empty"] is True
    assert captured["kwargs"]["return_response"] is True


def test_delete_project_preserves_http_status(monkeypatch) -> None:
    def fail_request(request, **kwargs):
        raise HttpApiError("forbidden", status=403)

    monkeypatch.setattr(client_module, "request_json", fail_request)

    with pytest.raises(DependencyTrackLabApiError) as captured:
        DependencyTrackLabClient(
            "https://dtrack.example", "cleanup-key"
        ).delete_project("018f6aca-9705-7f61-a36b-4f16ec3b1f4a")

    assert captured.value.status == 403
