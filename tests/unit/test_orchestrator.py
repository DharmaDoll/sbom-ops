from __future__ import annotations

from dataclasses import replace

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
    WorkflowConfig,
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

    def wait_for_analysis(
        self, project_uuid: str, *, timeout: float, poll_interval: float
    ) -> list[DependencyTrackFinding]:
        return self.get_project_findings(project_uuid)


class FakeDependencyTrackWithExcludedFinding(FakeDependencyTrack):
    def get_project_findings(self, project_uuid: str) -> list[DependencyTrackFinding]:
        return [finding("CVE-2026-0002", analysis_state="NOT_AFFECTED")]


class FakeKev:
    def get_known_exploited_vulnerabilities(self) -> set[str]:
        return {"CVE-2026-0001"}


class FakeGitHub:
    def __init__(
        self,
        *,
        missing_count: int = 0,
        legacy_only: bool = False,
        tracked_issue_key: str = "project-1:old:1:CVE-2025-0001",
    ) -> None:
        self.updated: list[int] = []
        self.updated_bodies: list[str] = []
        self.closed: list[int] = []
        self.created: list[tuple[str, str, list[str]]] = []
        self.missing_count = missing_count
        self.legacy_only = legacy_only
        self.tracked_issue_key = tracked_issue_key
        self.searched_keys: list[str] = []

    def find_open_issue_by_finding_key(self, finding_key: str) -> dict | None:
        self.searched_keys.append(finding_key)
        if not self.legacy_only and finding_key.startswith("v2:project-1:"):
            return {"number": 11}
        if self.legacy_only and finding_key == (
            "project-1:openssl:3.0.0:CVE-2026-0001"
        ):
            return {"number": 11}
        return None

    def list_open_issues(self, label: str) -> list[dict]:
        missing_marker = (
            f"\n<!-- sbom-ops:missing-count={self.missing_count} -->"
            if self.missing_count
            else ""
        )
        return [
            {
                "number": 12,
                "title": "old finding",
                "body": (
                    f"<!-- sbom-ops:finding-key={self.tracked_issue_key} -->"
                    f"{missing_marker}"
                ),
            }
        ]

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        self.created.append((title, body, labels))
        return {"number": 13}

    def update_issue(self, issue_number: int, title: str, body: str) -> dict:
        self.updated.append(issue_number)
        self.updated_bodies.append(body)
        return {"number": issue_number}

    def close_issue(self, issue_number: int) -> dict:
        self.closed.append(issue_number)
        return {"number": issue_number}


def test_orchestrator_keeps_stale_issue_open_by_default() -> None:
    github = FakeGitHub()
    result = Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()

    assert result.projects_processed == 1
    assert result.findings_processed == 2
    assert result.issues_created == 0
    assert result.issues_updated == 1
    assert result.issues_closed == 0
    assert github.updated == [11]
    assert github.closed == []
    assert result.actions[0].startswith("update v2:project-1:")
    assert result.actions[0].endswith("issue=#11 priority=P0")
    assert result.actions[1] == (
        "keep-open project-1:old:1:CVE-2025-0001 issue=#12 "
        "reason=automatic_closure_disabled"
    )


def test_orchestrator_marks_first_verified_absence_without_closing() -> None:
    github = FakeGitHub()
    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
        workflow=WorkflowConfig(close_missing_findings=True),
    )

    result = Orchestrator(safe_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert result.issues_updated == 2
    assert result.issues_closed == 0
    assert github.updated == [11, 12]
    assert "<!-- sbom-ops:finding-state=MISSING -->" in github.updated_bodies[1]
    assert "<!-- sbom-ops:missing-count=1 -->" in github.updated_bodies[1]
    assert github.closed == []


def test_orchestrator_migrates_an_existing_legacy_key() -> None:
    github = FakeGitHub(legacy_only=True)

    result = Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()

    assert result.issues_created == 0
    assert github.searched_keys[0].startswith("v2:project-1:")
    assert github.searched_keys[1] == ("project-1:openssl:3.0.0:CVE-2026-0001")
    assert github.updated_bodies[0].startswith(
        "<!-- sbom-ops:finding-key=v2:project-1:"
    )


def test_orchestrator_resets_missing_count_when_finding_reappears() -> None:
    github = FakeGitHub(
        missing_count=1,
        tracked_issue_key="project-1:openssl:3.0.0:CVE-2026-0002",
    )

    result = Orchestrator(
        config(), FakeDependencyTrackWithExcludedFinding(), FakeKev(), github
    ).run()

    assert result.issues_updated == 1
    assert result.issues_closed == 0
    assert github.updated == [12]
    assert "<!-- sbom-ops:finding-state=ACTIVE -->" in github.updated_bodies[0]
    assert "sbom-ops:missing-count" not in github.updated_bodies[0]


def test_orchestrator_closes_after_second_verified_absence() -> None:
    github = FakeGitHub(missing_count=1)
    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
        workflow=WorkflowConfig(close_missing_findings=True),
    )

    result = Orchestrator(safe_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert result.issues_updated == 2
    assert result.issues_closed == 1
    assert github.updated == [11, 12]
    assert "<!-- sbom-ops:finding-state=RESOLVED -->" in github.updated_bodies[1]
    assert github.closed == [12]
    assert result.actions[1].endswith("count=2 reason=consecutive_absence_confirmed")


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
    assert result.issues_closed == 0
    assert github.updated == []
    assert github.closed == []
