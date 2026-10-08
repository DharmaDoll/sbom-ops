from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from sbom_ops.clients import dependency_track as dependency_track_module
from sbom_ops.clients.dependency_track import (
    DependencyTrackApiError,
    DependencyTrackClient,
)

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
    assert findings[0].cvss_score == 9.8
    assert findings[0].cvss_version == "CVSSv3"
    assert findings[0].vulnerability_aliases == (
        "CVE-2026-1001",
        "GHSA-abcd-efgh-ijkl",
    )
    assert findings[0].component_uuid == "component-1"
    assert findings[0].component_purl == "pkg:generic/openssl@3.0.0"
    assert findings[0].epss_score == 0.91
    assert findings[0].analysis_state == "NOT_SET"
    assert findings[0].analysis_detail == (
        "Reviewed by AppSec.\nReachability is not yet confirmed."
    )
    assert findings[0].cwes == (78,)
    assert findings[1].analysis_state == "NOT_AFFECTED"
    assert findings[1].epss_score == 0.82


def test_dependency_track_preserves_zero_scores_before_fallbacks() -> None:
    finding_payloads = load_fixture("dependency-track-findings.json")
    assert isinstance(finding_payloads, list)
    finding_payloads[0]["vulnerability"]["cvssV3BaseScore"] = 0.0
    finding_payloads[0]["vulnerability"]["cvssV4Score"] = 8.8
    finding_payloads[0]["vulnerability"]["epssScore"] = 0.0
    finding_payloads[0]["epssScore"] = 0.7
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": finding_payloads,
        "/api/v1/vulnerability/project/project-1": [],
    }
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    client._request_json = lambda path, params=None: payloads[path]  # type: ignore[method-assign]

    finding = client.get_project_findings("project-1")[0]

    assert finding.cvss_score == 0.0
    assert finding.cvss_version == "CVSSv3"
    assert finding.epss_score == 0.0


def test_dependency_track_reads_cvss_v4_score_field() -> None:
    finding_payloads = load_fixture("dependency-track-findings.json")
    assert isinstance(finding_payloads, list)
    vulnerability = finding_payloads[0]["vulnerability"]
    vulnerability.pop("cvssV3BaseScore")
    vulnerability["cvssV4Score"] = 8.8
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": finding_payloads,
        "/api/v1/vulnerability/project/project-1": [],
    }
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    client._request_json = lambda path, params=None: payloads[path]  # type: ignore[method-assign]

    finding = client.get_project_findings("project-1")[0]

    assert finding.cvss_score == 8.8
    assert finding.cvss_version == "CVSSv4"


def test_dependency_track_does_not_promote_alias_to_primary_identifier() -> None:
    finding_payloads = load_fixture("dependency-track-findings.json")
    assert isinstance(finding_payloads, list)
    finding_payloads[0]["vulnerability"].pop("vulnId")
    finding_payloads[0]["vulnerability"].pop("id", None)
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": finding_payloads,
        "/api/v1/vulnerability/project/project-1": [],
    }
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    client._request_json = lambda path, params=None: payloads[path]  # type: ignore[method-assign]

    with pytest.raises(
        DependencyTrackApiError, match="finding has no vulnerability identifier"
    ):
        client.get_project_findings("project-1")


def test_dependency_track_treats_non_finite_scores_as_unavailable() -> None:
    finding_payloads = load_fixture("dependency-track-findings.json")
    assert isinstance(finding_payloads, list)
    finding_payloads[0]["vulnerability"]["cvssV3BaseScore"] = float("nan")
    finding_payloads[0]["vulnerability"].pop("cvssV4Score")
    finding_payloads[0]["vulnerability"]["cvssV4BaseScore"] = True
    finding_payloads[0]["vulnerability"]["epssScore"] = float("nan")
    finding_payloads[0]["epssScore"] = float("inf")
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": finding_payloads,
        "/api/v1/vulnerability/project/project-1": [],
    }
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    client._request_json = lambda path, params=None: payloads[path]  # type: ignore[method-assign]

    finding = client.get_project_findings("project-1")[0]

    assert finding.cvss_score is None
    assert finding.epss_score is None


def test_dependency_track_treats_out_of_range_scores_as_unavailable() -> None:
    finding_payloads = load_fixture("dependency-track-findings.json")
    assert isinstance(finding_payloads, list)
    finding_payloads[0]["vulnerability"]["cvssV3BaseScore"] = 10.1
    finding_payloads[0]["vulnerability"]["cvssV4Score"] = 10.1
    finding_payloads[0]["vulnerability"]["epssScore"] = 1.01
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": finding_payloads,
        "/api/v1/vulnerability/project/project-1": [],
    }
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    client._request_json = lambda path, params=None: payloads[path]  # type: ignore[method-assign]

    finding = client.get_project_findings("project-1")[0]

    assert finding.cvss_score is None
    assert finding.epss_score is None


@pytest.mark.parametrize(
    "change",
    [
        {"analysis_detail": "Updated human analysis note"},
        {"component_purl": "pkg:generic/openssl@3.0.1"},
    ],
)
def test_wait_for_analysis_rechecks_when_assessment_input_changes(
    monkeypatch, change
) -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": load_fixture(
            "dependency-track-findings.json"
        ),
        "/api/v1/vulnerability/project/project-1": [],
    }
    client._request_json = lambda path, params=None: payloads[path]  # type: ignore[method-assign]
    original_finding = client.get_project_findings("project-1")[0]
    changed_finding = replace(original_finding, **change)
    snapshots = iter(([original_finding], [changed_finding], [changed_finding]))
    poll_count = 0

    def next_snapshot(project_uuid: str):
        nonlocal poll_count
        del project_uuid
        poll_count += 1
        return next(snapshots)

    client.get_project_findings = next_snapshot  # type: ignore[method-assign]
    monkeypatch.setattr(dependency_track_module.time, "sleep", lambda _: None)

    findings = client.wait_for_analysis("project-1", timeout=10, poll_interval=0)

    assert poll_count == 3
    assert findings[0] == changed_finding


def test_project_findings_include_suppressed_for_reconciliation() -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    requests: list[tuple[str, dict[str, str] | None]] = []
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": load_fixture(
            "dependency-track-findings.json"
        ),
        "/api/v1/vulnerability/project/project-1": [],
    }

    def fake_request(path, params=None):
        requests.append((path, params))
        return payloads[path]

    client._request_json = fake_request  # type: ignore[method-assign]

    client.get_project_findings("project-1")

    assert (
        "/api/v1/finding/project/project-1",
        {"suppressed": "true"},
    ) in requests


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
        0: [
            {"uuid": "project-1", "name": "one", "version": "sha256-abc"},
            {"uuid": "project-2", "name": "two"},
        ],
        2: [{"uuid": "project-3", "name": "three"}],
    }

    def fake_request(path, params=None, *, include_headers=False):
        assert include_headers
        requests.append(params)
        offset = int(params["offset"]) if params else 0
        return pages[offset], {"X-Total-Count": "3"}

    client._request_json = fake_request  # type: ignore[method-assign]

    projects = client.list_projects()

    assert [project.uuid for project in projects] == [
        "project-1",
        "project-2",
        "project-3",
    ]
    assert projects[0].version == "sha256-abc"
    assert projects[1].version is None
    assert requests == [
        {"offset": "0", "limit": "2"},
        {"offset": "2", "limit": "2"},
    ]


def test_project_listing_rejects_a_repeated_pagination_page() -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key", page_size=1)
    client._request_json = (  # type: ignore[method-assign]
        lambda path, params=None, *, include_headers=False: (
            [{"uuid": "project-1", "name": "one"}],
            {"X-Total-Count": "2"},
        )
    )

    with pytest.raises(DependencyTrackApiError, match="pagination did not advance"):
        client.list_projects()


def test_finding_without_vulnerability_identifier_is_rejected() -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": [
            {
                "component": {"uuid": "component-1", "name": "openssl"},
                "vulnerability": {},
            }
        ],
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


@pytest.mark.parametrize("invalid_page", [None, {}, {"findings": None}, [None]])
def test_malformed_finding_collection_never_looks_empty(invalid_page: object) -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    payloads = {
        "/api/v1/project/project-1": {"uuid": "project-1", "name": "service-a"},
        "/api/v1/finding/project/project-1": invalid_page,
    }
    client._request_json = lambda path, params=None: payloads[path]  # type: ignore[method-assign]

    with pytest.raises(DependencyTrackApiError, match="malformed collection"):
        client.get_project_findings("project-1")


def test_project_pagination_rejects_invalid_later_page() -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key", page_size=2)

    def fake_request(
        path: str,
        params: dict[str, str] | None = None,
        *,
        include_headers: bool = False,
    ) -> tuple[list[dict[str, str] | None], dict[str, str]]:
        assert path == "/api/v1/project"
        assert params is not None
        assert include_headers
        if params["offset"] == "0":
            return (
                [
                    {"uuid": "project-1", "name": "one"},
                    {"uuid": "project-2", "name": "two"},
                ],
                {"X-Total-Count": "4"},
            )
        return [{"uuid": "project-3", "name": "three"}, None], {"X-Total-Count": "4"}

    client._request_json = fake_request  # type: ignore[method-assign]

    with pytest.raises(DependencyTrackApiError, match="malformed collection item"):
        client.list_projects()


@pytest.mark.parametrize(
    ("second_page", "second_headers", "error"),
    [
        ([{"uuid": "project-2", "name": "two"}], {}, "missing pagination total"),
        (
            [{"uuid": "project-2", "name": "two"}],
            {"X-Total-Count": "3"},
            "pagination total changed",
        ),
        ([], {"X-Total-Count": "2"}, "pagination ended before total"),
    ],
)
def test_project_pagination_rejects_partial_or_inconsistent_response(
    second_page: list[dict[str, str]], second_headers: dict[str, str], error: str
) -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key", page_size=1)

    def fake_request(
        path: str,
        params: dict[str, str] | None = None,
        *,
        include_headers: bool = False,
    ) -> tuple[list[dict[str, str]], dict[str, str]]:
        assert path == "/api/v1/project"
        assert params is not None
        assert include_headers
        if params["offset"] == "0":
            return [{"uuid": "project-1", "name": "one"}], {"X-Total-Count": "2"}
        return second_page, second_headers

    client._request_json = fake_request  # type: ignore[method-assign]

    with pytest.raises(DependencyTrackApiError, match=error):
        client.list_projects()


@pytest.mark.parametrize("invalid_payload", [None, [], {"name": "service-a"}])
def test_project_identity_must_match_requested_uuid(invalid_payload: object) -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    client._request_json = lambda path, params=None: invalid_payload  # type: ignore[method-assign]

    with pytest.raises(DependencyTrackApiError, match="incomplete identity"):
        client.get_project_findings("project-1")


def test_malformed_bom_processing_response_is_not_complete() -> None:
    client = DependencyTrackClient("https://dtrack.example", "api-key")
    client._request_json = lambda path, params=None: {"processing": "false"}  # type: ignore[method-assign]

    with pytest.raises(DependencyTrackApiError, match="response is malformed"):
        client.wait_for_bom_processing("token-1", timeout=1, poll_interval=0)
