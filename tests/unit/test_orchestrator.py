from __future__ import annotations

from sbom_ops.clients.dependency_track import (
    DependencyTrackFinding,
    DependencyTrackProject,
)
from sbom_ops.config import (
    AppConfig,
    DependencyTrackConfig,
    GitHubConfig,
    IntelligenceConfig,
    PriorityConfig,
    RuntimeConfig,
)
from sbom_ops.services.orchestrator import Orchestrator


def config() -> AppConfig:
    return AppConfig(
        dependency_track=DependencyTrackConfig("https://dtrack", "dt-key"),
        github=GitHubConfig("gh-key", "acme", "service-a"),
        intelligence=IntelligenceConfig(),
        priority=PriorityConfig(),
        runtime=RuntimeConfig(),
    )


def finding(
    vulnerability_id: str,
    *,
    severity: str = "HIGH",
    analysis_state: str | None = "NOT_SET",
) -> DependencyTrackFinding:
    return DependencyTrackFinding(
        project_uuid="project-1",
        project_name="service-a",
        component_name="openssl",
        component_version="3.0.0",
        vulnerability_id=vulnerability_id,
        severity=severity,
        cvss_score=8.0,
        cwes=(78,),
        description="description",
        epss_score=0.1,
        analysis_state=analysis_state,
        is_suppressed=False,
        analysis_detail=None,
        finding_id=f"finding-{vulnerability_id}",
        vulnerability_uuid=f"vulnerability-{vulnerability_id}",
        vulnerability_source="NVD",
    )


class FakeDependencyTrack:
    def list_projects(self) -> list[DependencyTrackProject]:
        return [DependencyTrackProject("project-1", "service-a")]

    def get_project_findings(self, project_uuid: str) -> list[DependencyTrackFinding]:
        return [
            finding("CVE-2026-0001"),
            finding("CVE-2026-0002", analysis_state="NOT_AFFECTED"),
        ]


class FakeKev:
    def get_known_exploited_vulnerabilities(self) -> set[str]:
        return {"CVE-2026-0001"}


class FakeGitHub:
    def __init__(self) -> None:
        self.updated: list[int] = []
        self.closed: list[int] = []
        self.created: list[tuple[str, str, list[str]]] = []

    def find_open_issue_by_finding_key(self, finding_key: str) -> dict | None:
        if finding_key.endswith("CVE-2026-0001"):
            return {"number": 11}
        return None

    def list_open_issues(self, label: str) -> list[dict]:
        return [
            {
                "number": 12,
                "body": "<!-- sbom-ops:finding-key=project-1:old:1:CVE-2025-0001 -->",
            }
        ]

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        self.created.append((title, body, labels))
        return {"number": 13}

    def update_issue(self, issue_number: int, title: str, body: str) -> dict:
        self.updated.append(issue_number)
        return {"number": issue_number}

    def close_issue(self, issue_number: int) -> dict:
        self.closed.append(issue_number)
        return {"number": issue_number}


def test_orchestrator_updates_actionable_and_closes_stale_issue() -> None:
    github = FakeGitHub()
    result = Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()

    assert result.projects_processed == 1
    assert result.findings_processed == 2
    assert result.issues_created == 0
    assert result.issues_updated == 1
    assert result.issues_closed == 1
    assert github.updated == [11]
    assert github.closed == [12]


def test_orchestrator_dry_run_does_not_mutate_github() -> None:
    github = FakeGitHub()
    runtime = RuntimeConfig(dry_run=True)
    dry_config = AppConfig(
        config().dependency_track,
        config().github,
        config().intelligence,
        config().priority,
        runtime,
    )

    result = Orchestrator(dry_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert result.dry_run is True
    assert result.issues_updated == 1
    assert result.issues_closed == 1
    assert github.updated == []
    assert github.closed == []
