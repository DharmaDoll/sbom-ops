from __future__ import annotations

import json
from pathlib import Path

from sbom_ops.clients.dependency_track import DependencyTrackClient

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
    assert findings[0].epss_score == 0.91
    assert findings[0].analysis_state == "NOT_SET"
    assert findings[0].cwes == (78,)
    assert findings[1].analysis_state == "NOT_AFFECTED"
    assert findings[1].epss_score == 0.82
