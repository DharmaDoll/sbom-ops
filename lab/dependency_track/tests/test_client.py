from __future__ import annotations

import pytest
from dt_lab import client as client_module
from dt_lab.client import DependencyTrackLabApiError, DependencyTrackLabClient
from dt_lab.domain import DependencyTrackObservation

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

    client.observe_project_direct_components("project-1")
    client.observe_project_services("project-1")

    assert requests == [
        (
            "/api/v1/component/project/project-1",
            {"onlyDirect": "true"},
        ),
        ("/api/v1/service/project/project-1", None),
    ]


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


def test_wait_for_bom_processing_polls_until_complete(monkeypatch) -> None:
    client = DependencyTrackLabClient("https://dtrack.example", "api-key")
    responses = iter([{"processing": True}, {"processing": False}])
    client._request_json = lambda path, params=None: next(responses)  # type: ignore[method-assign]
    monkeypatch.setattr(client_module.time, "sleep", lambda _: None)

    client.wait_for_bom_processing("token-1", timeout=1, poll_interval=0)


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
