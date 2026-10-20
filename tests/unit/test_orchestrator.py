from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, tzinfo

import pytest

from sbom_ops.clients.dependency_track import (
    DependencyTrackApiError,
    DependencyTrackClient,
    DependencyTrackFinding,
    DependencyTrackProject,
)
from sbom_ops.clients.github import GitHubApiError
from sbom_ops.config import (
    AppConfig,
    DependencyTrackConfig,
    GitHubConfig,
    IntelligenceConfig,
    PriorityConfig,
    RuntimeConfig,
)
from sbom_ops.domain.advisory import (
    AdvisorySnapshot,
    EvidenceFreshness,
    EvidenceOutcome,
    ExposureStatus,
    VulnerabilityEvidenceObservation,
)
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegisteredService,
    RegistryDeploymentStatus,
    RegistryProjectStatus,
    ReportedDeployment,
    ReviewedProjectLink,
)
from sbom_ops.domain.assets import (
    AssetDeployment,
    AssetInventorySnapshot,
    BusinessCriticality,
    DeploymentStatus,
)
from sbom_ops.domain.issue_body import IssueBodyError, new_issue_body, parse_issue_body
from sbom_ops.domain.issue_catalog import IssueIdentityError
from sbom_ops.domain.models import Finding, Severity
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
        self.list_calls: list[str] = []
        identity = Finding(
            "project-1",
            "service-a",
            "openssl",
            "3.0.0",
            "CVE-2026-0001",
            Severity.HIGH,
            8.0,
            (78,),
            "description",
            vulnerability_source="NVD",
        )
        self.matched_key = (
            identity.legacy_finding_key() if legacy_only else identity.finding_key()
        )

    def list_issues(self) -> list[dict]:
        self.list_calls.append("repository")
        # Listing and detail reads are separate: subclasses can simulate an edit
        # between them without changing the initial inventory.
        return [
            FakeGitHub.get_issue(self, 11),
            *[{**issue, "state": "open"} for issue in self.list_open_issues("sbom")],
        ]

    def get_issue(self, issue_number: int) -> dict:
        if issue_number == 11:
            return {
                "number": 11,
                "title": "human title",
                "state": "open",
                "body": f"<!-- sbom-ops:finding-key={self.matched_key} -->",
            }
        return {**self.list_open_issues("sbom")[0], "state": "open"}

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
        return {"number": 13, "state": "open", "title": title, "body": body}

    def update_issue(self, issue_number: int, title: str | None, body: str) -> dict:
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
        "reason=absence_not_verified"
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


def test_reviewed_registry_link_is_output_only_and_does_not_change_issues(
    tmp_path,
) -> None:
    from sbom_ops.services.asset_updates import plan_service_update
    from sbom_ops.storage.asset_registry import AssetRegistry

    class LinkedDependencyTrack(FakeDependencyTrack):
        def list_projects(self) -> list[DependencyTrackProject]:
            return [DependencyTrackProject("project-1", "checkout-api/web", "v1")]

    snapshot = AssetRegistrySnapshot(
        services=(
            RegisteredService(
                "checkout-api", "team-checkout", BusinessCriticality.HIGH, "payments"
            ),
        ),
        links=(
            ReviewedProjectLink(
                "project-1",
                "checkout-api/web",
                "v1",
                "checkout-api",
                "web",
                "alice",
                "2026-10-06T00:00:00Z",
            ),
        ),
        deployment_reports=(
            ReportedDeployment(
                "checkout-api",
                "web",
                "production",
                "v1",
                DeploymentStatus.DEPLOYED,
                ExposureStatus.UNKNOWN,
                "alice",
                "reviewed deployment record",
                "2026-10-07T00:00:00Z",
                "2099-10-07T00:00:00Z",
                1,
            ),
            ReportedDeployment(
                "checkout-api",
                "web",
                "production",
                "v1",
                DeploymentStatus.NOT_DEPLOYED,
                ExposureStatus.UNKNOWN,
                "alice",
                "reviewed stop record",
                "2026-10-08T00:00:00Z",
                "2099-10-08T00:00:00Z",
                2,
                supersedes_report_id=1,
            ),
        ),
    )
    baseline_github = FakeGitHub()
    linked_github = FakeGitHub()
    baseline = Orchestrator(
        config(), LinkedDependencyTrack(), FakeKev(), baseline_github
    ).run()
    linked = Orchestrator(
        config(),
        LinkedDependencyTrack(),
        FakeKev(),
        linked_github,
        asset_registry=snapshot,
    ).run()

    assert linked.registry_snapshot_status.value == "loaded"
    review = linked.as_dict()["review_queue"]
    assert len(review) == len(linked.assessments)
    assert review[0]["asset"]["owner"] == "team-checkout"
    assert review[0]["environments"][0]["deployment_status"] == "not_deployed"
    assert baseline.as_dict()["review_queue"][0]["asset_status"] == "not_requested"
    assert linked.registry_projects[0].status is RegistryProjectStatus.MATCHED
    assert linked.registry_deployments[0].status is RegistryDeploymentStatus.REPORTED
    assert linked.registry_deployments[0].report_ids == (2,)
    assert (
        linked.registry_deployments[0].deployment_status
        is DeploymentStatus.NOT_DEPLOYED
    )
    assert linked.as_dict()["registry_deployments"][0]["source"] == "human_reported"
    assert linked.as_dict()["registry_projects"][0]["owner"] == "team-checkout"
    assert linked.asset_inventory_status.value == "not_requested"
    assert linked.assessments == baseline.assessments
    assert linked.actions == baseline.actions
    assert (linked.issues_created, linked.issues_updated, linked.issues_closed) == (
        baseline.issues_created,
        baseline.issues_updated,
        baseline.issues_closed,
    )
    assert linked_github.created == baseline_github.created
    assert linked_github.updated_bodies == baseline_github.updated_bodies
    assert linked_github.closed == baseline_github.closed

    with AssetRegistry(tmp_path / "assets.sqlite3", create_if_missing=True) as registry:
        registry.register_service(snapshot.services[0])
        registry.update_service(
            plan_service_update(
                registry,
                service_id="checkout-api",
                owner="new-team",
                criticality=BusinessCriticality.CRITICAL,
                actor="alice",
                reason="transfer",
            )
        )
        updated_snapshot = replace(snapshot, services=registry.list_services())
    updated_github = FakeGitHub()
    updated = Orchestrator(
        config(),
        LinkedDependencyTrack(),
        FakeKev(),
        updated_github,
        asset_registry=updated_snapshot,
    ).run()
    assert updated.as_dict()["review_queue"][0]["asset"]["owner"] == "new-team"
    assert updated.as_dict()["review_queue"][0]["asset"]["criticality"] == "critical"
    assert updated.assessments == linked.assessments
    assert updated.registry_deployments == linked.registry_deployments
    assert updated.actions == linked.actions
    assert updated_github.created == linked_github.created
    assert updated_github.updated_bodies == linked_github.updated_bodies
    assert updated_github.closed == linked_github.closed
    for state, disabled_snapshot in (
        ("retired", replace(updated_snapshot, retired_services=("checkout-api",))),
        (
            "retired",
            replace(updated_snapshot, retired_deployables=(("checkout-api", "web"),)),
        ),
        (
            "revoked",
            replace(updated_snapshot, links=(), revoked_project_uuids=("project-1",)),
        ),
    ):
        lifecycle_github = FakeGitHub()
        result = Orchestrator(
            config(),
            LinkedDependencyTrack(),
            FakeKev(),
            lifecycle_github,
            asset_registry=disabled_snapshot,
        ).run()
        row = result.as_dict()["review_queue"][0]
        assert row["asset_status"] == state
        assert row["asset"] is None and row["environments"] == []
        assert result.assessments == updated.assessments
        assert result.findings_processed == updated.findings_processed
        assert result.actions == updated.actions
        assert lifecycle_github.created == updated_github.created
        assert lifecycle_github.updated_bodies == updated_github.updated_bodies
        assert lifecycle_github.closed == updated_github.closed


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


@pytest.mark.parametrize(
    ("observed_at", "expires_at", "freshness", "poc_status"),
    [
        ("2026-10-07T00:00:00Z", "2026-10-09T00:00:00Z", "fresh", "reported"),
        ("2026-10-09T00:00:00Z", "2026-10-10T00:00:00Z", "unknown", "unknown"),
        ("2026-10-07T00:00:00Z", "2026-10-08T00:00:00Z", "stale", "unknown"),
    ],
)
def test_explicit_poc_reports_order_equal_risk_output_without_workflow_change(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    observed_at: str,
    expires_at: str,
    freshness: str,
    poc_status: str,
) -> None:
    from sbom_ops import cli

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:
            return datetime(2026, 10, 8, tzinfo=UTC).astimezone(tz)

    monkeypatch.setattr("sbom_ops.domain.advisory.datetime", FixedDatetime)

    class EqualFindings(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            del project_uuid
            return [finding("CVE-2026-0001"), finding("CVE-2026-0002")]

    class NoKev:
        def get_known_exploited_vulnerabilities(
            self, *, force_refresh: bool = False
        ) -> set[str]:
            del force_refresh
            return set()

    snapshot = AdvisorySnapshot(
        snapshot_id="poc-report",
        generated_at="2026-10-07T00:00:00Z",
        vulnerability_observations=(
            VulnerabilityEvidenceObservation(
                vulnerability_id="CVE-2026-0002",
                source="lookup",
                signal="published_poc",
                outcome=EvidenceOutcome.AVAILABLE,
                observed_at=observed_at,
                source_revision=None,
                freshness=EvidenceFreshness.FRESH,
                record_count=2,
                complete=True,
                expires_at=expires_at,
            ),
        ),
        project_exposure=(),
    )
    disabled_config = replace(config(), github=replace(config().github, enabled=False))
    baseline = Orchestrator(disabled_config, EqualFindings(), NoKev()).run()
    orchestrator = Orchestrator(
        disabled_config, EqualFindings(), NoKev(), advisory_snapshot=snapshot
    )
    result = orchestrator.run()

    assert [item.vulnerability_id for item in result.assessments] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]
    expected_order = ["CVE-2026-0001", "CVE-2026-0002"]
    if poc_status == "reported":
        expected_order.reverse()
    output = result.as_dict()["assessments"]
    assert [item["vulnerability_id"] for item in output] == expected_order
    poc_assessment = next(
        item for item in output if item["vulnerability_id"] == "CVE-2026-0002"
    )
    assert poc_assessment["poc_reports"] == {
        "status": poc_status,
        "sources": [
            {
                "vulnerability_id": "CVE-2026-0002",
                "source": "lookup",
                "outcome": "available",
                "record_count": 2,
                "observed_at": observed_at,
                "freshness": "fresh",
                "effective_freshness": freshness,
                "expires_at": expires_at,
                "complete": True,
                "last_attempt_at": None,
                "last_error": None,
                "last_http_status": None,
            }
        ],
    }
    assert [item.priority for item in result.assessments] == [
        item.priority for item in baseline.assessments
    ]
    assert result.actions == baseline.actions == ()

    monkeypatch.setattr(cli, "Orchestrator", lambda **kwargs: orchestrator)
    assert cli.run_sync(disabled_config) == 0
    text = capsys.readouterr().out
    lines = [line for line in text.splitlines() if line.startswith("finding ")]
    assert len(lines) == 2
    assert all(
        f"vulnerability={cve}" in line
        for cve, line in zip(expected_order, lines, strict=True)
    )
    poc_line = next(line for line in lines if "vulnerability=CVE-2026-0002" in line)
    assert f"poc_reported={poc_status}" in poc_line
    review = result.as_dict()["review_queue"]
    assert [item["vulnerability_id"] for item in review] == expected_order
    assert (
        next(
            item["poc_reports"]
            for item in review
            if item["vulnerability_id"] == "CVE-2026-0002"
        )
        == poc_assessment["poc_reports"]
    )
    assert cli.run_sync(disabled_config, "review") == 0
    review_text = capsys.readouterr().out
    assert review_text.index(expected_order[0]) < review_text.index(expected_order[1])
    assert "情報源=lookup ID=CVE-2026-0002 件数=2" in review_text
    assert f"鮮度判定={freshness}" in review_text
    assert ("PoC=報告あり" in review_text) is (poc_status == "reported")


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


def test_orchestrator_stable_snapshot_does_not_verify_absence() -> None:
    github = FakeGitHub()
    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
    )

    result = Orchestrator(safe_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert result.analysis_snapshot_status.value == "stable"
    assert result.issues_updated == 1
    assert result.issues_closed == 0
    assert github.updated == [11]
    assert result.as_dict()["absence_verification"]["finding_state"] == "UNKNOWN"
    assert github.closed == []


def test_orchestrator_migrates_an_existing_legacy_key() -> None:
    github = FakeGitHub(legacy_only=True)

    result = Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()

    assert result.issues_created == 0
    assert github.list_calls == ["repository"]
    assert parse_issue_body(github.updated_bodies[0]).finding_key.startswith(
        "v2:project-1:"
    )
    assert "移行前の本文" in github.updated_bodies[0]


@pytest.mark.parametrize("duplicate", [False, True])
def test_closed_issue_is_reviewed_and_duplicate_identity_stops_writes(
    duplicate: bool,
) -> None:
    class ClosedGitHub(FakeGitHub):
        def list_issues(self) -> list[dict]:
            rows = super().list_issues()
            rows[0]["state"] = "closed"
            if duplicate:
                rows.append({**rows[0], "number": 99, "state": "open"})
            return rows

    github = ClosedGitHub()
    if duplicate:
        with pytest.raises(IssueIdentityError, match="multiple"):
            Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    else:
        result = Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
        assert any(action.startswith("review-closed ") for action in result.actions)
        assert result.issues_created == result.issues_updated == 0
    assert github.created == github.updated == github.closed == []


def test_ambiguous_legacy_identity_cannot_choose_one_current_component() -> None:
    class TwoComponents(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            return [
                replace(finding("CVE-2026-0001"), component_uuid=value)
                for value in ("a", "b")
            ]

    github = FakeGitHub(legacy_only=True)
    with pytest.raises(IssueIdentityError, match="multiple current identities"):
        Orchestrator(config(), TwoComponents(), FakeKev(), github).run()
    assert github.created == github.updated == []


@pytest.mark.parametrize(
    "inventory_failure",
    [GitHubApiError("page limit"), IssueIdentityError("invalid key")],
)
def test_issue_inventory_failure_stops_before_any_writes(
    inventory_failure: Exception,
) -> None:
    class FailedGitHub(FakeGitHub):
        def list_issues(self) -> list[dict]:
            raise inventory_failure

    github = FailedGitHub()
    with pytest.raises(type(inventory_failure)):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.created == github.updated == []


def test_later_repository_read_failure_prevents_earlier_repository_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TwoProjects(FakeDependencyTrack):
        def list_projects(self) -> list[DependencyTrackProject]:
            return [
                DependencyTrackProject("project-1", "a"),
                DependencyTrackProject("project-2", "b"),
            ]

    class FailedGitHub(FakeGitHub):
        def list_issues(self) -> list[dict]:
            raise GitHubApiError("second repository page failed")

    first, second = FakeGitHub(), FailedGitHub()
    runner = Orchestrator(config(), TwoProjects(), FakeKev(), first)
    monkeypatch.setattr(
        runner,
        "_github_target",
        lambda project: (
            first if project == "project-1" else second,
            "sbom",
            ("acme", project, "sbom"),
        ),
    )
    with pytest.raises(GitHubApiError, match="second repository"):
        runner.run()
    assert first.created == first.updated == second.created == second.updated == []


@pytest.mark.parametrize("response_lost", [False, True])
def test_create_is_not_repeated_for_duplicate_finding_rows_or_after_reconciliation(
    response_lost: bool,
) -> None:
    class RepeatedFinding(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            return [finding("CVE-2026-0001")] * 2

    class PersistedGitHub(FakeGitHub):
        issues: list[dict]

        def __init__(self) -> None:
            super().__init__()
            self.issues = []

        def list_issues(self) -> list[dict]:
            return list(self.issues)

        def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
            row = super().create_issue(title, body, labels)
            self.issues.append(row)
            if response_lost:
                raise GitHubApiError("response lost after server accepted POST")
            return row

        def get_issue(self, issue_number: int) -> dict:
            return dict(self.issues[0])

    github = PersistedGitHub()
    first = Orchestrator(config(), RepeatedFinding(), FakeKev(), github).run()
    assert first.issues_created == 1
    assert len(github.created) == 1
    assert (
        any("create-reconciled" in action for action in first.actions) == response_lost
    )
    second = Orchestrator(config(), RepeatedFinding(), FakeKev(), github).run()
    assert second.issues_created == 0
    assert second.issues_updated == 1
    assert len(github.created) == 1


def test_unconfirmed_create_stops_without_retrying_post() -> None:
    class UnknownGitHub(FakeGitHub):
        attempts = 0

        def list_issues(self) -> list[dict]:
            return []

        def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
            self.attempts += 1
            raise GitHubApiError("timeout")

    github = UnknownGitHub()
    with pytest.raises(GitHubApiError, match="outcome is unknown"):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.attempts == 1
    assert github.updated == []


@pytest.mark.parametrize("dry_run", [False, True])
def test_update_uses_latest_body_preserves_notes_and_human_title(dry_run: bool) -> None:
    class LatestGitHub(FakeGitHub):
        reads = 0

        def get_issue(self, issue_number: int) -> dict:
            self.reads += 1
            issue = super().get_issue(issue_number)
            issue["body"] = (
                "先頭メモ\n"
                + new_issue_body(self.matched_key, "old data")
                + "\n直前の追記  "
            )
            return issue

        def update_issue(self, issue_number: int, title: str | None, body: str) -> dict:
            assert title is None  # Do not send a title field in the PATCH.
            assert body.startswith("先頭メモ\n")
            assert body.endswith("\n直前の追記  ")
            assert "old data" not in parse_issue_body(body).managed
            assert "CVE-2026-0001" in parse_issue_body(body).managed
            return super().update_issue(issue_number, title, body)

    github = LatestGitHub()
    run_config = replace(config(), runtime=RuntimeConfig(dry_run=dry_run))
    result = Orchestrator(run_config, FakeDependencyTrack(), FakeKev(), github).run()
    assert result.issues_updated == 1
    assert github.reads == 1
    assert github.updated == ([] if dry_run else [11])


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize(
    "changes",
    [
        {"state": "closed"},
        {"pull_request": {}},
        {"body": None},
        {"body": "<!-- sbom-ops:managed:start -->"},
        {"body": new_issue_body("other-finding", "text")},
        {"number": 999},
        {"number": True},
        {"title": None},
    ],
)
def test_update_refuses_changed_or_ambiguous_issue(
    changes: dict, dry_run: bool
) -> None:
    class ChangedGitHub(FakeGitHub):
        def get_issue(self, issue_number: int) -> dict:
            return {**super().get_issue(issue_number), **changes}

    github = ChangedGitHub()
    run_config = replace(config(), runtime=RuntimeConfig(dry_run=dry_run))
    with pytest.raises(IssueBodyError):
        Orchestrator(run_config, FakeDependencyTrack(), FakeKev(), github).run()
    assert github.created == github.updated == github.closed == []


def test_reappearance_reads_latest_notes_before_migration() -> None:
    class LatestGitHub(FakeGitHub):
        def get_issue(self, issue_number: int) -> dict:
            issue = super().get_issue(issue_number)
            issue["body"] += "\n読み取り直前の担当メモ  "
            return issue

    github = LatestGitHub(
        missing_count=2,
        tracked_issue_key="project-1:openssl:3.0.0:CVE-2026-0002",
    )
    Orchestrator(
        config(), FakeDependencyTrackWithExcludedFinding(), FakeKev(), github
    ).run()
    assert github.updated == [12]
    assert github.updated_bodies[0].endswith("\n読み取り直前の担当メモ  ")
    assert parse_issue_body(github.updated_bodies[0]).missing_count == 0


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
    assert (
        "sbom-ops:missing-count"
        not in parse_issue_body(github.updated_bodies[0]).managed
    )


def test_orchestrator_ignores_historical_absence_count() -> None:
    github = FakeGitHub(missing_count=1, finding_state_marker="MISSING")
    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
    )

    result = Orchestrator(safe_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert result.issues_updated == 1
    assert result.issues_closed == 0
    assert github.updated == [11]
    assert github.closed == []
    assert result.actions[1].endswith("reason=absence_not_verified")


def test_dt_read_failure_never_marks_or_closes_a_missing_finding() -> None:
    class FailedDependencyTrack(FakeDependencyTrack):
        def wait_for_analysis(
            self, project_uuid: str, *, timeout: float, poll_interval: float
        ) -> list[DependencyTrackFinding]:
            raise DependencyTrackApiError("malformed collection")

    github = FakeGitHub(missing_count=1, finding_state_marker="MISSING")
    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
    )

    with pytest.raises(DependencyTrackApiError, match="malformed collection"):
        Orchestrator(safe_config, FailedDependencyTrack(), FakeKev(), github).run()

    assert github.created == []
    assert github.updated == []
    assert github.closed == []


def test_orchestrator_does_not_close_from_a_count_without_missing_state() -> None:
    github = FakeGitHub(missing_count=1)
    safe_config = replace(
        config(),
        runtime=RuntimeConfig(wait_for_analysis=True),
    )

    result = Orchestrator(safe_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert result.issues_closed == 0
    assert github.closed == []
    assert github.updated == [11]
    assert result.actions[1].endswith("reason=absence_not_verified")


@pytest.mark.parametrize(
    "duplicate_marker",
    [
        "<!-- sbom-ops:finding-state=MISSING -->",
        "<!-- sbom-ops:missing-count=1 -->",
    ],
)
def test_orchestrator_ignores_duplicate_missing_metadata(
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
    )

    result = Orchestrator(safe_config, FakeDependencyTrack(), FakeKev(), github).run()

    assert result.issues_closed == 0
    assert github.updated == [11]
    assert github.closed == []


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
    assert (
        "sbom-ops:missing-count"
        not in parse_issue_body(github.updated_bodies[0]).managed
    )


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
    assert result.as_dict()["absence_verification"]["finding_state"] == "UNKNOWN"


@pytest.mark.parametrize("wait_for_analysis", [False, True])
def test_later_project_read_failure_prevents_all_github_operations(
    wait_for_analysis: bool,
) -> None:
    class LaterFailure(FakeDependencyTrack):
        def list_projects(self) -> list[DependencyTrackProject]:
            return [
                DependencyTrackProject("project-1", "service-a"),
                DependencyTrackProject("project-2", "service-b"),
            ]

        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            if project_uuid == "project-2":
                raise DependencyTrackApiError("read failed after bounded retries")
            return super().get_project_findings(project_uuid)

    class NoCallsGitHub(FakeGitHub):
        def list_issues(self) -> list[dict]:
            pytest.fail("GitHub must not be queried before all DT reads succeed")

    github = NoCallsGitHub()
    run_config = replace(
        config(), runtime=RuntimeConfig(wait_for_analysis=wait_for_analysis)
    )
    with pytest.raises(DependencyTrackApiError, match="read failed"):
        Orchestrator(run_config, LaterFailure(), FakeKev(), github).run()
    assert github.list_calls == []
    assert github.created == github.updated == github.closed == []


@pytest.mark.parametrize("github_enabled", [False, True])
@pytest.mark.parametrize("rows", [[], [finding("CVE-2026-0001")]])
def test_two_identical_dt_responses_do_not_prove_resolution(
    monkeypatch: pytest.MonkeyPatch,
    github_enabled: bool,
    rows: list[DependencyTrackFinding],
) -> None:
    dt = DependencyTrackClient("https://dtrack.invalid", "test-key")
    calls: list[str] = []

    def read(project_uuid: str) -> list[DependencyTrackFinding]:
        calls.append(project_uuid)
        return rows

    monkeypatch.setattr(dt, "list_projects", FakeDependencyTrack().list_projects)
    monkeypatch.setattr(dt, "get_project_findings", read)
    run_config = replace(
        config(),
        dependency_track=replace(
            config().dependency_track, analysis_poll_interval_seconds=0
        ),
        runtime=RuntimeConfig(wait_for_analysis=True),
        github=replace(config().github, enabled=github_enabled),
    )
    github = FakeGitHub(missing_count=999, finding_state_marker="MISSING")
    result = Orchestrator(run_config, dt, FakeKev(), github).run()
    assert len(calls) == 2  # Use the real stability wait, not the one-read fake.
    assert result.analysis_snapshot_status.value == "stable"
    assert result.findings_processed == len(rows)
    assert result.as_dict()["absence_verification"]["finding_state"] == "UNKNOWN"
    assert result.as_dict()["absence_verification"]["missing_count"] == 0
    assert result.issues_closed == 0
    assert github.closed == []
    assert 12 not in github.updated
    if not github_enabled:
        assert github.list_calls == github.updated == []


def test_observation_series_never_inherits_historical_missing_count() -> None:
    class SeriesDT(FakeDependencyTrack):
        rows: list[DependencyTrackFinding] | None = []

        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            if self.rows is None:
                raise DependencyTrackApiError("analysis response unavailable")
            return self.rows

    class StatefulGitHub(FakeGitHub):
        def __init__(self) -> None:
            super().__init__(
                missing_count=999,
                finding_state_marker="MISSING",
                tracked_issue_key="project-1:openssl:3.0.0:CVE-2026-0002",
            )
            self.issue = super().list_open_issues("security")[0]

        def list_open_issues(self, label: str) -> list[dict]:
            return [dict(self.issue)]

        def update_issue(self, issue_number: int, title: str | None, body: str) -> dict:
            if issue_number == 12:
                self.issue["body"] = body
            return super().update_issue(issue_number, title, body)

    dt = SeriesDT()
    github = StatefulGitHub()
    full = FakeDependencyTrack().get_project_findings("project-1")
    run_config = replace(config(), runtime=RuntimeConfig(wait_for_analysis=True))
    # Empty/partial snapshots can occur during analysis. Failure breaks the run,
    # not into an empty success; reappearance clears legacy markers.
    for rows in [[], [full[0]], None, [], full, [], [full[0]], None, [], full]:
        dt.rows = rows
        if rows is None:
            before = (
                len(github.updated),
                len(github.list_calls),
                github.issue["body"],
            )
            with pytest.raises(DependencyTrackApiError):
                Orchestrator(run_config, dt, FakeKev(), github).run()
            assert before == (
                len(github.updated),
                len(github.list_calls),
                github.issue["body"],
            )
        else:
            result = Orchestrator(run_config, dt, FakeKev(), github).run()
            assert result.issues_closed == 0
            assert result.as_dict()["absence_verification"]["missing_count"] == 0
        assert github.closed == []
    assert "finding-state=ACTIVE" in github.issue["body"]
    assert "missing-count" not in parse_issue_body(github.issue["body"]).managed


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
    )
    result = Orchestrator(safe_config, SuppressedInventory(), FakeKev(), github).run()

    assert result.issues_created == 0
    assert result.issues_closed == 0
    assert github.closed == []
    assert github.updated == [12]
    assert "<!-- sbom-ops:finding-state=ACTIVE -->" in github.updated_bodies[0]
    assert (
        "sbom-ops:missing-count"
        not in parse_issue_body(github.updated_bodies[0]).managed
    )


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
