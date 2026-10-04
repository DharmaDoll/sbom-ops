from __future__ import annotations

from dataclasses import replace

import pytest

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
from sbom_ops.domain.advisory import (
    AdvisorySnapshot,
    EvidenceFreshness,
    EvidenceOutcome,
    ExposureStatus,
    VulnerabilityEvidenceObservation,
)
from sbom_ops.domain.assets import (
    AssetDeployment,
    AssetInventorySnapshot,
    BusinessCriticality,
    DeploymentStatus,
)
from sbom_ops.services.orchestrator import Orchestrator, ProjectSelectionError


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
    def get_known_exploited_vulnerabilities(
        self, *, force_refresh: bool = False
    ) -> set[str]:
        del force_refresh
        return {"CVE-2026-0001"}


class FakeGitHub:
    def __init__(
        self,
        *,
        missing_count: int = 0,
        finding_state_marker: str | None = None,
        legacy_only: bool = False,
        tracked_issue_key: str = "project-1:old:1:CVE-2025-0001",
    ) -> None:
        self.updated: list[int] = []
        self.updated_bodies: list[str] = []
        self.closed: list[int] = []
        self.created: list[tuple[str, str, list[str]]] = []
        self.missing_count = missing_count
        self.finding_state_marker = finding_state_marker
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
        state_marker = (
            f"\n<!-- sbom-ops:finding-state={self.finding_state_marker} -->"
            if self.finding_state_marker
            else ""
        )
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
                    f"{state_marker}"
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
    assert result.run_id
    assert result.duration_seconds >= 0
    assert result.kev_used_stale_cache is False
    assert result.analysis_snapshot_status.value == "not_requested"
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
    assert len(result.assessments) == 2
    assert result.assessments[0].priority.value == "P0"
    assert result.assessments[0].analysis_state.value == "NOT_SET"
    assert result.assessments[0].in_kev is True
    payload = result.as_dict()
    assert payload["status"] == "succeeded"
    assert payload["run_id"] == result.run_id
    assert payload["kev_used_stale_cache"] is False
    assert payload["analysis_snapshot_status"] == "not_requested"
    assert payload["assessments"][0]["vulnerability_source"] == "NVD"
    assert payload["assessments"][0]["severity"] == "HIGH"
    assert payload["assessments"][0]["cvss_score"] == 8.0
    assert payload["assessments"][0]["epss_score"] == 0.1
    assert payload["assessments"][0]["priority"] == "P0"
    assert payload["assessments"][0]["is_suppressed"] is False
    assert payload["assessments"][0]["in_kev"] is True
    assert payload["assessments"][0]["component_uuid"] is None
    assert payload["assessments"][0]["component_purl"] is None
    assert payload["actions"] == list(result.actions)


def test_action_neutral_assessment_preserves_component_identity() -> None:
    class DependencyTrackWithPurl(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            del project_uuid
            return [
                replace(
                    finding("CVE-2026-0003"),
                    component_uuid="component-3",
                    component_purl="pkg:pypi/example@1.2.3",
                    vulnerability_aliases=(
                        "CVE-2026-0001",
                        "GHSA-abcd-efgh-ijkl",
                    ),
                    cvss_version="CVSSv4",
                )
            ]

    disabled_config = replace(config(), github=replace(config().github, enabled=False))
    result = Orchestrator(
        disabled_config,
        DependencyTrackWithPurl(),
        FakeKev(),
        FakeGitHub(),
    ).run()

    assessment = result.as_dict()["assessments"][0]
    assert assessment["component_uuid"] == "component-3"
    assert assessment["component_purl"] == "pkg:pypi/example@1.2.3"
    assert assessment["component_name"] == "openssl"
    assert assessment["component_version"] == "3.0.0"
    assert assessment["vulnerability_aliases"] == [
        "CVE-2026-0001",
        "GHSA-abcd-efgh-ijkl",
    ]
    assert assessment["cvss_version"] == "CVSSv4"
    assert assessment["priority"] == "P0"
    assert assessment["in_kev"] is True


def test_explicit_cve_alias_can_match_kev_without_replacing_primary_id() -> None:
    class DependencyTrackWithCveAlias(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            del project_uuid
            return [
                replace(
                    finding("GHSA-abcd-efgh-ijkl"),
                    vulnerability_source="GITHUB",
                    vulnerability_aliases=("cve-2026-0001",),
                )
            ]

    disabled_config = replace(config(), github=replace(config().github, enabled=False))
    result = Orchestrator(
        disabled_config,
        DependencyTrackWithCveAlias(),
        FakeKev(),
        FakeGitHub(),
    ).run()

    assessment = result.as_dict()["assessments"][0]
    assert assessment["vulnerability_id"] == "GHSA-abcd-efgh-ijkl"
    assert assessment["vulnerability_aliases"] == ["cve-2026-0001"]
    assert assessment["in_kev"] is True
    assert assessment["priority"] == "P0"
    assert assessment["rationale"] == ["KEV match"]


def test_advisory_snapshot_matches_explicit_cve_alias_without_changing_priority() -> (
    None
):
    class DependencyTrackWithAlias(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            del project_uuid
            return [
                replace(
                    finding("GHSA-abcd-efgh-ijkl"),
                    vulnerability_aliases=("CVE-2026-0001",),
                )
            ]

    snapshot = AdvisorySnapshot(
        snapshot_id="test-snapshot",
        generated_at="2026-10-03T00:00:00Z",
        vulnerability_observations=(
            VulnerabilityEvidenceObservation(
                vulnerability_id="cve-2026-0001",
                source="lookup",
                signal="exploit_reference",
                outcome=EvidenceOutcome.AVAILABLE,
                observed_at="2026-10-03T00:00:00Z",
                source_revision=None,
                freshness=EvidenceFreshness.FRESH,
                record_count=1,
                complete=True,
            ),
        ),
        project_exposure=(),
    )
    disabled_config = replace(config(), github=replace(config().github, enabled=False))
    baseline = Orchestrator(
        disabled_config,
        DependencyTrackWithAlias(),
        FakeKev(),
        FakeGitHub(),
    ).run()

    result = Orchestrator(
        disabled_config,
        DependencyTrackWithAlias(),
        FakeKev(),
        advisory_snapshot=snapshot,
    ).run()

    assessment = result.assessments[0]
    assert result.advisory_snapshot_status.value == "loaded"
    assert result.advisory_snapshot_id == "test-snapshot"
    assert result.as_dict()["advisory_snapshot_generated_at"] == (
        "2026-10-03T00:00:00Z"
    )
    assert assessment.advisory_observations[0].vulnerability_id == "cve-2026-0001"
    assert assessment.priority == baseline.assessments[0].priority


def test_asset_inventory_keeps_project_scope_and_does_not_change_priority() -> None:
    class TwoProjects(FakeDependencyTrack):
        def list_projects(self) -> list[DependencyTrackProject]:
            return [
                DependencyTrackProject("project-1", "service-a"),
                DependencyTrackProject("project-2", "service-b"),
            ]

        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            return [
                replace(
                    finding("CVE-2026-0001"),
                    project_uuid=project_uuid,
                    project_name=project_uuid,
                )
            ]

    def deployment(project_uuid: str) -> AssetDeployment:
        return AssetDeployment(
            project_uuid=project_uuid,
            service_id="service-a",
            environment="production",
            owner="team-a",
            deployed_version="service-a@1.0.0",
            deployment_status=DeploymentStatus.DEPLOYED,
            exposure_status=ExposureStatus.CONFIRMED,
            criticality=BusinessCriticality.CRITICAL,
            source="reviewed-inventory",
            observed_at="2026-10-04T00:00:00Z",
            expires_at="2099-01-01T00:00:00Z",
        )

    snapshot = AssetInventorySnapshot(
        snapshot_id="assets-1",
        generated_at="2026-10-04T00:00:00Z",
        deployments=(deployment("project-1"), deployment("project-3")),
        sha256="example-digest",
    )
    disabled_config = replace(config(), github=replace(config().github, enabled=False))
    baseline = Orchestrator(
        disabled_config, TwoProjects(), FakeKev(), FakeGitHub()
    ).run()
    result = Orchestrator(
        disabled_config,
        TwoProjects(),
        FakeKev(),
        FakeGitHub(),
        asset_inventory=snapshot,
    ).run()

    assert result.asset_inventory_status.value == "loaded"
    assert result.asset_inventory_id == "assets-1"
    assert result.asset_unmapped_project_uuids == ("project-2",)
    assert result.asset_unmatched_project_uuids == ("project-3",)
    assert [item.project_uuid for item in result.asset_deployments] == ["project-1"]
    assert [item.priority for item in result.assessments] == [
        item.priority for item in baseline.assessments
    ]
    assert result.actions == baseline.actions == ()


def test_non_cve_alias_does_not_match_kev() -> None:
    class DependencyTrackWithGhsaAlias(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            del project_uuid
            return [
                replace(
                    finding("GHSA-abcd-efgh-ijkl"),
                    vulnerability_aliases=(
                        "GHSA-wxyz-1234-5678",
                        "CVE-2026-0001-extra",
                    ),
                )
            ]

    disabled_config = replace(config(), github=replace(config().github, enabled=False))
    result = Orchestrator(
        disabled_config,
        DependencyTrackWithGhsaAlias(),
        FakeKev(),
        FakeGitHub(),
    ).run()

    assessment = result.as_dict()["assessments"][0]
    assert assessment["in_kev"] is False
    assert assessment["priority"] != "P0"


def test_orchestrator_marks_first_verified_absence_without_closing() -> None:
    github = FakeGitHub()
    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
        workflow=WorkflowConfig(close_missing_findings=True),
    )

    result = Orchestrator(safe_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert result.analysis_snapshot_status.value == "stable"
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
    github = FakeGitHub(missing_count=1, finding_state_marker="MISSING")
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


def test_orchestrator_does_not_close_from_a_count_without_missing_state() -> None:
    github = FakeGitHub(missing_count=1)
    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
        workflow=WorkflowConfig(close_missing_findings=True),
    )

    result = Orchestrator(safe_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert result.issues_closed == 0
    assert github.closed == []
    assert "<!-- sbom-ops:finding-state=MISSING -->" in github.updated_bodies[1]
    assert "<!-- sbom-ops:missing-count=1 -->" in github.updated_bodies[1]
    assert result.actions[1].endswith("count=1 reason=awaiting_absence_confirmation")


@pytest.mark.parametrize(
    "duplicate_marker",
    [
        "<!-- sbom-ops:finding-state=MISSING -->",
        "<!-- sbom-ops:missing-count=1 -->",
    ],
)
def test_orchestrator_restarts_duplicate_missing_metadata(
    duplicate_marker: str,
) -> None:
    class DuplicateMetadataGitHub(FakeGitHub):
        def list_open_issues(self, label: str) -> list[dict]:
            issues = super().list_open_issues(label)
            issues[0]["body"] += f"\n{duplicate_marker}"
            return issues

    github = DuplicateMetadataGitHub(missing_count=1, finding_state_marker="MISSING")
    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
        workflow=WorkflowConfig(close_missing_findings=True),
    )

    result = Orchestrator(safe_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert result.issues_closed == 0
    assert github.updated_bodies[1].count("sbom-ops:finding-state=MISSING") == 1
    assert github.updated_bodies[1].count("sbom-ops:missing-count=1") == 1


def test_orchestrator_resets_stale_missing_state_when_finding_reappears() -> None:
    github = FakeGitHub(
        finding_state_marker="MISSING",
        tracked_issue_key="project-1:openssl:3.0.0:CVE-2026-0002",
    )

    result = Orchestrator(
        config(), FakeDependencyTrackWithExcludedFinding(), FakeKev(), github
    ).run()

    assert result.issues_closed == 0
    assert github.updated == [12]
    assert "<!-- sbom-ops:finding-state=ACTIVE -->" in github.updated_bodies[0]
    assert "sbom-ops:missing-count" not in github.updated_bodies[0]


def test_analysis_snapshot_status_reports_no_projects() -> None:
    class NoProjects(FakeDependencyTrack):
        def list_projects(self) -> list[DependencyTrackProject]:
            return []

    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
        github=replace(config().github, enabled=False),
    )
    result = Orchestrator(safe_config, NoProjects(), FakeKev(), FakeGitHub()).run()

    assert result.projects_processed == 0
    assert result.analysis_snapshot_status.value == "no_projects"


def test_suppressed_finding_cancels_pending_absence_closure() -> None:
    # DT lab 2026-09-01: suppressed=true retains suppressed inventory.
    class SuppressedInventory(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            return [replace(finding("CVE-2026-0002"), is_suppressed=True)]

    github = FakeGitHub(
        missing_count=1,
        tracked_issue_key="project-1:openssl:3.0.0:CVE-2026-0002",
    )
    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
        workflow=WorkflowConfig(close_missing_findings=True),
    )
    result = Orchestrator(safe_config, SuppressedInventory(), FakeKev(), github).run()

    assert result.issues_created == 0
    assert result.issues_closed == 0
    assert github.closed == []
    assert github.updated == [12]
    assert "<!-- sbom-ops:finding-state=ACTIVE -->" in github.updated_bodies[0]
    assert "sbom-ops:missing-count" not in github.updated_bodies[0]


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


def test_orchestrator_can_disable_github_issue_actions() -> None:
    github = FakeGitHub()
    disabled_config = replace(config(), github=replace(config().github, enabled=False))

    result = Orchestrator(
        disabled_config, FakeDependencyTrack(), FakeKev(), github
    ).run()

    assert result.findings_processed == 2
    assert result.issues_created == 0
    assert result.issues_updated == 0
    assert result.issues_closed == 0
    assert result.actions == ()
    assert len(result.assessments) == 2
    assert github.created == []
    assert github.updated == []
    assert github.closed == []


def test_assessment_exposes_missing_scores_without_changing_priority_policy() -> None:
    class MissingScores(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            return [
                replace(
                    finding("GHSA-ABCD-1234-5678", severity="HIGH"),
                    cvss_score=None,
                    epss_score=None,
                    vulnerability_source="GITHUB",
                )
            ]

    disabled_config = replace(config(), github=replace(config().github, enabled=False))
    result = Orchestrator(
        disabled_config, MissingScores(), FakeKev(), FakeGitHub()
    ).run()

    assessment = result.as_dict()["assessments"][0]
    assert assessment["vulnerability_source"] == "GITHUB"
    assert assessment["severity"] == "HIGH"
    assert assessment["cvss_score"] is None
    assert assessment["epss_score"] is None
    assert assessment["priority"] == "P3"
    assert assessment["in_kev"] is False
    assert assessment["rationale"] == [
        "Default monitoring priority",
        "EPSS unavailable",
        "CVSS unavailable; severity label is not used as a score fallback",
    ]


def test_assessment_preserves_dependency_track_analysis_detail() -> None:
    analyst_note = "Reviewed by AppSec.\nReachability is not yet confirmed."

    class FindingWithAnalysisDetail(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            del project_uuid
            return [replace(finding("CVE-2026-0005"), analysis_detail=analyst_note)]

    disabled_config = replace(config(), github=replace(config().github, enabled=False))
    result = Orchestrator(
        disabled_config,
        FindingWithAnalysisDetail(),
        FakeKev(),
        FakeGitHub(),
    ).run()

    assessment = result.as_dict()["assessments"][0]
    assert assessment["analysis_detail"] == analyst_note


def test_unavailable_project_filter_fails_before_external_workflow_actions() -> None:
    github = FakeGitHub()
    selected_config = replace(
        config(),
        runtime=replace(config().runtime, project_uuids=("missing-project",)),
    )

    with pytest.raises(ProjectSelectionError, match="not accessible: missing-project"):
        Orchestrator(selected_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert github.created == []
    assert github.updated == []
    assert github.closed == []
