from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, tzinfo
from pathlib import Path

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
    WorkflowConfig,
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
from sbom_ops.domain.issue_intent import IssueIntentError, IssueJournalBusy
from sbom_ops.domain.issue_labels import IssueLabelError
from sbom_ops.domain.models import Finding, Severity
from sbom_ops.domain.workflow import GitHubWriteAuthorizationError
from sbom_ops.domain.workflow_audit import WorkflowAudit, WorkflowEvent
from sbom_ops.services.orchestrator import Orchestrator, ProjectSelectionError
from sbom_ops.storage.issue_journal import IssueJournal


@pytest.fixture(autouse=True)
def workflow_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "workflow.sqlite3"
    IssueJournal.initialize(path)
    base = config()
    monkeypatch.setattr(
        __name__ + ".config",
        lambda: replace(base, workflow=WorkflowConfig(issue_journal_file=str(path))),
    )
    return path


def config() -> AppConfig:
    return AppConfig(
        dependency_track=DependencyTrackConfig("https://dtrack", "dt-key"),
        github=GitHubConfig("gh-key", "acme", "service-a", enabled=True),
        intelligence=IntelligenceConfig(),
        priority=PriorityConfig(),
        runtime=RuntimeConfig(github_write=True),
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


def test_reference_context_is_explicitly_not_requested_by_default() -> None:
    settings = config()
    settings = replace(settings, github=replace(settings.github, enabled=False))
    result = Orchestrator(
        settings, dependency_track=FakeDependencyTrack(), kev=FakeKev()
    ).run()
    assert result.as_dict().get("triage_context_status") == "not_requested"
    assert result.as_dict().get("triage_contexts") == []


@pytest.mark.parametrize("environment", ["production", "staging"])
@pytest.mark.parametrize("case", ["expired", "required", "not_required", "maintenance"])
def test_reference_context_preserves_sources_and_workflow(
    environment: str,
    case: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json
    from datetime import timedelta

    from sbom_ops.domain.kev import KevSnapshot
    from sbom_ops.domain.triage_input import SelectedCisaSnapshot, TriageInput
    from sbom_ops.domain.vulnrichment_snapshot import VulnrichmentSnapshot

    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 22, tzinfo=UTC).astimezone(tz)

    monkeypatch.setattr("sbom_ops.services.orchestrator.datetime", FixedClock)
    kev_ids = (
        frozenset({"CVE-2026-0001"}) if case in {"expired", "required"} else frozenset()
    )

    class LinkedDT(FakeDependencyTrack):
        def list_projects(self):
            return [DependencyTrackProject("project-1", "service-a", "build-1")]

    class EvidenceKev(FakeKev):
        calls = 0

        def get_known_exploited_vulnerabilities(self, *, force_refresh=False):
            self.calls += 1
            self.last_snapshot = KevSnapshot(
                "https://cisa.example/feed",
                kev_ids,
                datetime(2026, 1, 1, tzinfo=UTC),
                datetime(2099, 1, 1, tzinfo=UTC),
                "cache",
                "fixture-v1",
                datetime(2025, 1, 1, tzinfo=UTC),
                True,
            )
            return set(kev_ids)

    registry = AssetRegistrySnapshot(
        (RegisteredService("service-a", "team", BusinessCriticality.HIGH, "test"),),
        (
            ReviewedProjectLink(
                "project-1",
                "service-a",
                "build-1",
                "service-a",
                "api",
                "operator",
                "2026-01-01T00:00:00Z",
            ),
        ),
        (
            ReportedDeployment(
                "service-a",
                "api",
                "production",
                "build-1",
                DeploymentStatus.DEPLOYED,
                (
                    ExposureStatus.REJECTED
                    if case == "maintenance"
                    else ExposureStatus.CONFIRMED
                ),
                "operator",
                "synthetic",
                "2026-01-01T00:00:00Z",
                "2099-01-01T00:00:00Z",
                1,
            ),
        ),
    )
    payload = json.loads(
        (Path(__file__).parents[1] / "fixtures/vulnrichment_synthetic.json").read_text()
    )
    if case == "maintenance":
        content = payload["containers"]["adp"][0]["metrics"][0]["other"]["content"]
        content["options"] = [
            {"Exploitation": "poc"},
            {"Automatable": "no"},
            {"Technical Impact": "partial"},
        ]
    snapshot = VulnrichmentSnapshot.capture(
        payload,
        cve="CVE-2026-0001",
        revision="a" * 40,
        retrieved_at=datetime(2026, 10, 22, tzinfo=UTC),
        max_age=timedelta(hours=1) if case == "expired" else timedelta(days=2),
    )
    before_gh, after_gh = FakeGitHub(), FakeGitHub()
    baseline = Orchestrator(
        config(), LinkedDT(), EvidenceKev(), before_gh, asset_registry=registry
    ).run()
    kev = EvidenceKev()
    result = Orchestrator(
        config(),
        LinkedDT(),
        kev,
        after_gh,
        asset_registry=registry,
        triage_input=TriageInput(environment, (SelectedCisaSnapshot(7, snapshot),)),
    ).run()
    assert kev.calls == 1
    assert result.assessments == baseline.assessments
    assert after_gh.created == before_gh.created
    assert after_gh.updated_bodies == before_gh.updated_bodies
    assert after_gh.closed == before_gh.closed
    rows = result.as_dict()["triage_contexts"]
    assert len(rows) == 2
    row = rows[0]
    assert row["cisa"]["snapshot_id"] == 7
    assert row["cisa"]["exploitation"] == "poc"
    assert row["kev"]["checked_at"] == "2026-01-01T00:00:00+00:00"
    factors = {item["factor"]: item for item in row["evidence"]["factors"]}
    assert factors["automatable"]["status"] == (
        "expired" if case == "expired" else "known"
    )
    expected_auto = (
        "unknown" if case == "expired" else ("no" if case == "maintenance" else "yes")
    )
    assert factors["automatable"]["value"] == expected_auto
    reference = row["reference"]
    guidance = row["guidance"]
    assert guidance["asset_owner"] == "team"
    assert guidance["asset"]["service_id"] == "service-a"
    assert guidance["asset"]["environment"] == environment
    assert guidance["automatic_actions"] is False
    actions = {item["code"]: item for item in guidance["actions"]}
    if case == "expired":
        assert actions["confirm_automatable"]["reason"] == "expired"
        assert actions["confirm_automatable"]["role"] == "security"
        assert actions["confirm_automatable"]["assignee"] is None
    if environment != "production":
        assert actions["confirm_public_exposure"]["assignee"] == "team"
        assert "対象環境" in actions["confirm_public_exposure"]["instruction"]
    if case == "required" and environment == "production":
        assert "plan_forensic_triage" in actions
    else:
        assert "plan_forensic_triage" not in actions
    if case == "expired" or environment != "production":
        assert reference["status"] == "pending"
        if case == "expired":
            assert "automatable:expired" in reference["missing"]
    else:
        assert reference["status"] == "matched"
        assert reference["calendar_days"] == (None if case == "maintenance" else 3)
        assert reference["deadline_kind"] == (
            "next_major_update_or_rebuild" if case == "maintenance" else "calendar_days"
        )
        assert reference["forensic_triage"] == (
            "specified_by_reference"
            if case == "required"
            else "not_specified_by_reference"
        )
    assert row["reference"]["due_at"] is None
    assert row["reference"]["organizational_sla_adopted"] is False
    assert factors["kev"]["value"] == ("yes" if kev_ids else "no")
    assert factors["public_exposure"]["value"] == (
        ("no" if case == "maintenance" else "yes")
        if environment == "production"
        else "unknown"
    )
    assert rows[1]["cisa"] is None
    assert "cisa_unavailable" in rows[1]["reasons"]
    assert not row["priority_changed"] and not row["deadline_calculated"]
    json.dumps(result.as_dict())
    from sbom_ops.cli import print_triage_contexts

    print_triage_contexts(result)
    text = capsys.readouterr().out
    assert "優先度・対応期限は変更しません" in text
    if case == "expired" or environment != "production":
        assert "参照期限: 判定待ち" in text
    elif case == "required":
        assert "参照期限区分: 3暦日" in text
        assert "表による追加指定あり" in text
    else:
        assert "調査不要・侵害なしの意味ではありません" in text
        if case == "maintenance":
            assert "参照期限区分: 次回の予定された主要更新・再構築時" in text
    assert "固定版・自社SLAではありません" in text
    assert "次の行動" in text
    assert "確認先" in text
    assert f"環境={environment}" in text


def test_reference_context_legacy_kev_does_not_invent_provenance() -> None:
    from sbom_ops.domain.triage_input import TriageInput

    settings = config()
    settings = replace(settings, github=replace(settings.github, enabled=False))
    result = Orchestrator(
        settings,
        FakeDependencyTrack(),
        FakeKev(),
        asset_registry=AssetRegistrySnapshot((), ()),
        triage_input=TriageInput("production"),
    ).run()
    row = result.as_dict()["triage_contexts"][0]
    assert row["kev"] is None
    assert "kev_unavailable" in row["reasons"]
    assert row["evidence"]["asset_link_verified"] is False
    assert row["guidance"]["asset_owner"] is None
    assert row["guidance"]["asset"] is None
    assert all(item["assignee"] is None for item in row["guidance"]["actions"])


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
        self.labels = ["sbom", "sbom-P0"]
        self.label_changes: list[tuple[str, object]] = []
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
                "labels": list(self.labels),
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
                "labels": [],
                "body": (
                    f"<!-- sbom-ops:finding-key={self.tracked_issue_key} -->"
                    f"{state_marker}"
                    f"{missing_marker}"
                ),
            }
        ]

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        self.created.append((title, body, labels))
        return {
            "number": 13,
            "state": "open",
            "title": title,
            "body": body,
            "labels": list(labels),
        }

    def add_issue_labels(self, issue_number: int, labels: list[str]) -> list:
        self.label_changes.append(("add", labels))
        self.labels.extend(name for name in labels if name not in self.labels)
        return list(self.labels)

    def remove_issue_label(self, issue_number: int, label: str) -> list:
        self.label_changes.append(("remove", label))
        self.labels.remove(label)
        return list(self.labels)

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
        runtime=RuntimeConfig(wait_for_analysis=True, github_write=True),
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
    # A new orchestrator/process must not treat the still-empty list as permission
    # to resend a POST whose outcome is unknown.
    with pytest.raises(IssueIntentError, match="cannot be reconciled"):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.attempts == 1


@pytest.mark.parametrize("state", ["open", "closed"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_restart_reconciles_visible_issue_without_creating_again(
    workflow_journal: Path,
    state: str,
    dry_run: bool,
) -> None:
    github = FakeGitHub()
    key = github.matched_key
    with IssueJournal(workflow_journal) as journal:
        intent = journal.reserve("ACME/Service-A", key, "previous-run")
    original_list = github.list_issues
    github.list_issues = lambda: [
        {**row, "state": state} if row["number"] == 11 else row
        for row in original_list()
    ]
    result = Orchestrator(
        replace(config(), runtime=RuntimeConfig(dry_run=dry_run, github_write=True)),
        FakeDependencyTrack(),
        FakeKev(),
        github,
    ).run()
    assert github.created == []
    assert any("reconcile-create" in item for item in result.actions)
    if state == "closed":
        assert any("review-closed" in item for item in result.actions)
        assert github.updated == []
    with IssueJournal(workflow_journal, read_only=True) as journal:
        saved = journal.records()[0]
    assert saved.state == ("pending" if dry_run else "confirmed")
    if dry_run:
        assert saved == intent
        assert github.updated == []
    else:
        assert saved.issue_number == 11
        assert saved.confirmed_run_id == result.run_id


@pytest.mark.parametrize("confirmed", [False, True])
def test_journal_preflight_stops_all_writes_even_for_absent_finding(
    workflow_journal: Path,
    confirmed: bool,
) -> None:
    with IssueJournal(workflow_journal) as journal:
        intent = journal.reserve("acme/service-a", "v2:absent:unknown", "old-run")
        if confirmed:
            journal.confirm(intent, 99, "old-run")
    github = FakeGitHub()
    with pytest.raises(IssueIntentError, match="cannot be reconciled"):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.created == github.updated == []


def test_confirmed_issue_number_cannot_be_rebound(workflow_journal: Path) -> None:
    github = FakeGitHub()
    with IssueJournal(workflow_journal) as journal:
        intent = journal.reserve("acme/service-a", github.matched_key, "old-run")
        journal.confirm(intent, 99, "old-run")
    with pytest.raises(IssueIntentError, match="cannot be reconciled"):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.created == github.updated == []


def test_journal_ignores_other_repositories(workflow_journal: Path) -> None:
    with IssueJournal(workflow_journal) as journal:
        intent = journal.reserve("acme/other-repo", "unknown", "old-run")
    github = FakeGitHub()
    Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.updated == [11]
    with IssueJournal(workflow_journal, read_only=True) as journal:
        assert journal.records() == (intent,)


def test_intent_is_committed_before_post_and_survives_interruption(
    workflow_journal: Path,
) -> None:
    import sqlite3

    class InterruptedGitHub(FakeGitHub):
        def list_issues(self) -> list[dict]:
            return []

        def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
            # Independent DB connection sees the commit before HTTP dispatch.
            with sqlite3.connect(workflow_journal) as db:
                row = db.execute("SELECT state FROM issue_create_intents").fetchone()
            assert row == ("pending",)
            raise KeyboardInterrupt

    github = InterruptedGitHub()
    with pytest.raises(KeyboardInterrupt):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    with IssueJournal(workflow_journal) as journal:
        assert journal.records()[0].state == "pending"
    with pytest.raises(IssueIntentError, match="cannot be reconciled"):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()


def test_journal_confirmation_failure_cannot_allow_resend(
    workflow_journal: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CreatedGitHub(FakeGitHub):
        def list_issues(self) -> list[dict]:
            return []

    def fail_confirm(*args: object) -> None:
        raise OSError("disk unavailable")

    github = CreatedGitHub()
    with monkeypatch.context() as patch:
        patch.setattr(IssueJournal, "confirm", fail_confirm)
        with pytest.raises(OSError, match="disk unavailable"):
            Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert len(github.created) == 1
    with pytest.raises(IssueIntentError):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert len(github.created) == 1


def test_disabled_github_never_opens_journal_and_dry_run_never_requires_init(
    tmp_path: Path,
) -> None:
    invalid = str(tmp_path / "nonexistent.sqlite3")
    base = replace(config(), workflow=WorkflowConfig(issue_journal_file=invalid))
    github = FakeGitHub()
    disabled = replace(base, github=replace(base.github, enabled=False))
    Orchestrator(disabled, FakeDependencyTrack(), FakeKev(), github).run()
    assert not Path(invalid).exists()
    without_journal = replace(base, workflow=WorkflowConfig())
    with pytest.raises(IssueIntentError, match="require"):
        Orchestrator(without_journal, FakeDependencyTrack(), FakeKev(), github).run()
    with pytest.raises(FileNotFoundError):
        Orchestrator(base, FakeDependencyTrack(), FakeKev(), github).run()
    preview = replace(without_journal, runtime=RuntimeConfig(dry_run=True))
    Orchestrator(preview, FakeDependencyTrack(), FakeKev(), github).run()
    assert github.created == github.updated == []


def test_write_without_explicit_grant_stops_before_journal_and_external_reads(
    workflow_journal: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnreadableDT(FakeDependencyTrack):
        def list_projects(self) -> list[DependencyTrackProject]:
            pytest.fail("unapproved run must not read DT")

    def unexpected_journal(*args: object, **kwargs: object) -> None:
        pytest.fail("unapproved run must not open workflow DB")

    before = workflow_journal.read_bytes()
    monkeypatch.setattr(
        "sbom_ops.services.orchestrator.IssueJournal", unexpected_journal
    )
    github = FakeGitHub()
    base = config()
    unapproved = replace(base, runtime=replace(base.runtime, github_write=False))
    audit = WorkflowAudit()
    with pytest.raises(GitHubWriteAuthorizationError, match="--github-write"):
        Orchestrator(unapproved, UnreadableDT(), FakeKev(), github).run(audit=audit)
    assert github.created == github.updated == github.list_calls == []
    assert workflow_journal.read_bytes() == before
    assert audit.events[-1].error_type == "GitHubWriteAuthorizationError"


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize(
    "flags",
    [
        (),
        ("--dry-run",),
        ("--github-write",),
        ("--github-write", "--dry-run"),
        ("--github-write", "--no-github"),
    ],
)
def test_cli_write_switches_control_real_orchestration(
    workflow_journal: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    enabled: bool,
    flags: tuple[str, ...],
) -> None:
    import json

    from sbom_ops import cli

    values = {
        "SBOM_OPS_DT_BASE_URL": "https://dt.example",
        "SBOM_OPS_DT_API_KEY": "test-key",
        "SBOM_OPS_GITHUB_ENABLED": str(enabled).lower(),
        "SBOM_OPS_GITHUB_OWNER": "acme",
        "SBOM_OPS_GITHUB_REPO": "service-a",
        "SBOM_OPS_GITHUB_TOKEN": "test-token",
        "SBOM_OPS_ISSUE_JOURNAL_FILE": str(workflow_journal),
        "SBOM_OPS_DRY_RUN": "false",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SBOM_OPS_CONFIG_FILE", raising=False)
    github = FakeGitHub()
    monkeypatch.setattr(
        cli,
        "Orchestrator",
        lambda config, **kwargs: Orchestrator(
            config, FakeDependencyTrack(), FakeKev(), github, **kwargs
        ),
    )
    monkeypatch.setattr("sys.argv", ["sbom-ops", "sync", "--output", "json", *flags])
    denied = enabled and not flags
    writes = enabled and flags == ("--github-write",)
    before = workflow_journal.read_bytes()
    assert cli.main() == (2 if denied else 0)
    result = json.loads(capsys.readouterr().out)
    if denied:
        assert result["error_type"] == "GitHubWriteAuthorizationError"
        assert github.list_calls == []
    assert github.updated == ([11] if writes else [])
    assert github.created == github.closed == []
    if not writes:
        assert workflow_journal.read_bytes() == before


def test_busy_journal_stops_before_external_reads(workflow_journal: Path) -> None:
    class UnreadableDT(FakeDependencyTrack):
        def list_projects(self) -> list[DependencyTrackProject]:
            pytest.fail("busy run must not read external systems")

    with IssueJournal(workflow_journal):
        with pytest.raises(IssueJournalBusy):
            Orchestrator(config(), UnreadableDT(), FakeKev(), FakeGitHub()).run()


def test_reservation_failure_prevents_post(monkeypatch: pytest.MonkeyPatch) -> None:
    class EmptyGitHub(FakeGitHub):
        def list_issues(self) -> list[dict]:
            return []

    def fail_reserve(*args: object) -> None:
        raise OSError("disk unavailable")

    monkeypatch.setattr(IssueJournal, "reserve", fail_reserve)
    github = EmptyGitHub()
    with pytest.raises(OSError, match="disk unavailable"):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.created == github.updated == []


@pytest.mark.parametrize("dry_run", [False, True])
def test_priority_downgrade_updates_existing_issue_and_preserves_human_labels(
    dry_run: bool,
) -> None:
    class NoKev(FakeKev):
        def get_known_exploited_vulnerabilities(
            self, *, force_refresh: bool = False
        ) -> set[str]:
            return set()

    class ConcurrentLabelGitHub(FakeGitHub):
        def add_issue_labels(self, issue_number: int, labels: list[str]) -> list:
            # A human label added after GET must not be lost in a full replacement.
            self.labels.append("human-added-after-read")
            return super().add_issue_labels(issue_number, labels)

    github = ConcurrentLabelGitHub()
    github.labels = ["sbom", "sbom-P0", "human", "sbom-P0-note", "other-P1"]
    original = list(github.labels)
    run_config = replace(
        config(), runtime=RuntimeConfig(dry_run=dry_run, github_write=True)
    )
    result = Orchestrator(run_config, FakeDependencyTrack(), NoKev(), github).run()
    assert result.issues_updated == 1
    assert result.issues_created == result.issues_closed == 0
    assert any("labels " in action and "sbom-P2" in action for action in result.actions)
    if dry_run:
        assert github.labels == original
        assert github.updated == github.label_changes == []
    else:
        assert github.label_changes == [("add", ["sbom-P2"]), ("remove", "sbom-P0")]
        assert set(github.labels) == set(original) - {"sbom-P0"} | {
            "sbom-P2",
            "human-added-after-read",
        }
        assert "P2" in github.updated_bodies[0]
        # Re-reading on a later run is idempotent for the managed label set.
        Orchestrator(run_config, FakeDependencyTrack(), NoKev(), github).run()
        assert len(github.label_changes) == 2


@pytest.mark.parametrize("failure", ["timeout", "missing", "invalid"])
def test_unconfirmed_label_addition_never_removes_old_priority(failure: str) -> None:
    class FailedAdd(FakeGitHub):
        def add_issue_labels(self, issue_number: int, labels: list[str]) -> list:
            self.label_changes.append(("add", labels))
            if failure == "timeout":
                raise GitHubApiError("label response lost")
            return [] if failure == "missing" else {}

    github = FailedAdd()
    github.labels = ["sbom", "sbom-P1", "human"]
    with pytest.raises((GitHubApiError, IssueLabelError)):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.label_changes == [("add", ["sbom-P0"])]
    assert github.labels == ["sbom", "sbom-P1", "human"]


@pytest.mark.parametrize("failure", ["timeout", "still-present", "invalid"])
def test_label_removal_failure_stops_without_retry(failure: str) -> None:
    class FailedRemove(FakeGitHub):
        def remove_issue_label(self, issue_number: int, label: str) -> list:
            self.label_changes.append(("remove", label))
            if failure == "timeout":
                raise GitHubApiError("label response lost")
            return list(self.labels) if failure == "still-present" else None

    github = FailedRemove()
    github.labels = ["sbom", "sbom-P0", "sbom-P1", "sbom-P2", "human"]
    with pytest.raises((GitHubApiError, IssueLabelError)):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.label_changes == [("remove", "sbom-P1")]


@pytest.mark.parametrize("operation", ["add", "remove"])
def test_next_run_reconciles_applied_label_write_after_response_loss(
    operation: str,
) -> None:
    class LostResponse(FakeGitHub):
        failed = False

        def add_issue_labels(self, issue_number: int, labels: list[str]) -> list:
            result = super().add_issue_labels(issue_number, labels)
            if operation == "add" and not self.failed:
                self.failed = True
                raise GitHubApiError("response lost after applying labels")
            return result

        def remove_issue_label(self, issue_number: int, label: str) -> list:
            result = super().remove_issue_label(issue_number, label)
            if operation == "remove" and not self.failed:
                self.failed = True
                raise GitHubApiError("response lost after applying labels")
            return result

    github = LostResponse()
    github.labels = ["sbom", "sbom-P1", "human"]
    with pytest.raises(GitHubApiError):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.label_changes == [("add", ["sbom-P0"]), ("remove", "sbom-P1")]
    assert set(github.labels) == {"sbom", "sbom-P0", "human"}


@pytest.mark.parametrize("existing", [False, True])
def test_p3_updates_existing_issue_but_does_not_create_one(existing: bool) -> None:
    class LowRiskDT(FakeDependencyTrack):
        def get_project_findings(
            self, project_uuid: str
        ) -> list[DependencyTrackFinding]:
            return [replace(finding("CVE-2026-0001"), cvss_score=1.0, epss_score=0.0)]

    class NoKev(FakeKev):
        def get_known_exploited_vulnerabilities(
            self, *, force_refresh: bool = False
        ) -> set[str]:
            return set()

    class MaybeExisting(FakeGitHub):
        def list_issues(self) -> list[dict]:
            return super().list_issues() if existing else []

    github = MaybeExisting()
    result = Orchestrator(config(), LowRiskDT(), NoKev(), github).run()
    assert result.issues_created == result.issues_closed == 0
    assert result.issues_updated == int(existing)
    assert github.created == []
    assert github.labels == (["sbom", "sbom-P3"] if existing else ["sbom", "sbom-P0"])


def test_partial_failure_is_audited_with_one_run_id_and_without_raw_error(
    workflow_journal: Path,
) -> None:
    class FailedLabels(FakeGitHub):
        def add_issue_labels(self, issue_number: int, labels: list[str]) -> list:
            raise GitHubApiError("SECRET_REMOTE_RESPONSE")

    github = FailedLabels()
    github.labels = ["sbom", "sbom-P1"]
    audit = WorkflowAudit()
    with pytest.raises(GitHubApiError):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run(
            audit=audit
        )
    assert github.updated == [11]
    with IssueJournal(workflow_journal, read_only=True) as journal:
        events = journal.events(audit.run_id)
    assert events == tuple(audit.events)
    assert {event.run_id for event in events} == {audit.run_id}
    assert [(event.event, event.operation) for event in events] == [
        ("run_started", None),
        ("operation_started", "update_body"),
        ("operation_confirmed", "update_body"),
        ("operation_started", "add_labels"),
        ("operation_unknown", "add_labels"),
        ("run_failed", None),
    ]
    assert "SECRET_REMOTE_RESPONSE" not in str(audit.as_dict())


@pytest.mark.parametrize("failure_at", ["operation_started", "operation_confirmed"])
def test_audit_disk_failure_stops_further_github_writes(
    workflow_journal: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_at: str,
) -> None:
    original = IssueJournal.append_event

    def failed(self: IssueJournal, event: WorkflowEvent) -> None:
        if event.event == failure_at:
            raise OSError("disk full")
        original(self, event)

    monkeypatch.setattr(IssueJournal, "append_event", failed)
    github = FakeGitHub()
    github.labels = ["sbom", "sbom-P1"]
    audit = WorkflowAudit()
    with pytest.raises(OSError, match="disk full"):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run(
            audit=audit
        )
    assert audit.persistence_failed
    assert github.updated == ([] if failure_at == "operation_started" else [11])
    assert github.created == github.label_changes == []
    with IssueJournal(workflow_journal, read_only=True) as journal:
        assert journal.events(audit.run_id)[-1].event == "run_failed"


@pytest.mark.parametrize("creating", [False, True])
def test_primary_failure_survives_failed_audit_of_the_failure(
    monkeypatch: pytest.MonkeyPatch,
    creating: bool,
) -> None:
    original = IssueJournal.append_event

    def fail_on_error(self: IssueJournal, event: WorkflowEvent) -> None:
        if event.event in {"operation_unknown", "run_failed"}:
            raise OSError("audit unavailable")
        original(self, event)

    class FailedGitHub(FakeGitHub):
        def list_issues(self) -> list[dict]:
            return [] if creating else super().list_issues()

        def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
            raise GitHubApiError("original API failure")

        def update_issue(self, issue_number: int, title: str | None, body: str) -> dict:
            raise GitHubApiError("original API failure")

    monkeypatch.setattr(IssueJournal, "append_event", fail_on_error)
    audit = WorkflowAudit()
    with pytest.raises(GitHubApiError, match="original API failure"):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), FailedGitHub()).run(
            audit=audit
        )
    assert audit.persistence_failed
    assert audit.events[-1].error_type == "GitHubApiError"


def test_create_intent_and_reconciliation_share_audit_operation_id(
    workflow_journal: Path,
) -> None:
    class LostCreate(FakeGitHub):
        row: dict | None = None

        def list_issues(self) -> list[dict]:
            return [] if self.row is None else [self.row]

        def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
            self.row = super().create_issue(title, body, labels)
            raise GitHubApiError("lost response")

    result = Orchestrator(
        config(), FakeDependencyTrack(), FakeKev(), LostCreate()
    ).run()
    with IssueJournal(workflow_journal, read_only=True) as journal:
        intent = journal.records()[0]
        events = journal.events(result.run_id)
    assert intent.run_id == result.run_id
    operations = [event for event in events if event.operation is not None]
    assert [event.event for event in operations] == [
        "operation_started",
        "operation_unknown",
        "operation_reconciled",
    ]
    assert {event.operation_id for event in operations} == {intent.intent_id}
    assert events[-1].event == "run_succeeded"


@pytest.mark.parametrize("disabled", [False, True])
def test_preview_and_disabled_github_do_not_persist_audit_events(
    workflow_journal: Path,
    disabled: bool,
) -> None:
    base = config()
    selected = replace(
        base,
        runtime=replace(base.runtime, dry_run=not disabled),
        github=replace(base.github, enabled=not disabled),
    )
    github = FakeGitHub()
    result = Orchestrator(selected, FakeDependencyTrack(), FakeKev(), github).run()
    assert [event.event for event in result.workflow_events] == [
        "run_started",
        "run_succeeded",
    ]
    assert github.created == github.updated == github.label_changes == []
    with IssueJournal(workflow_journal, read_only=True) as journal:
        assert journal.events() == ()


def test_cli_failure_json_log_and_sqlite_keep_the_same_run_id(
    workflow_journal: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    import json

    from sbom_ops import cli

    class FailedBody(FakeGitHub):
        def update_issue(self, issue_number: int, title: str | None, body: str) -> dict:
            raise GitHubApiError("SECRET_REMOTE_RESPONSE")

    base = config()
    log = workflow_journal.with_suffix(".jsonl")
    selected = replace(base, runtime=replace(base.runtime, sync_log_file=str(log)))
    runner = Orchestrator(selected, FakeDependencyTrack(), FakeKev(), FailedBody())
    monkeypatch.setattr(cli, "load_config", lambda args: selected)
    monkeypatch.setattr(cli, "Orchestrator", lambda **kwargs: runner)
    monkeypatch.setattr("sys.argv", ["sbom-ops", "sync", "--output", "json"])
    assert cli.main() == 2
    result = json.loads(capsys.readouterr().out)
    logged = json.loads(log.read_text())
    assert logged == result
    assert "SECRET_REMOTE_RESPONSE" not in log.read_text()
    assert result["status"] == "failed"
    assert "assessments" not in result
    with IssueJournal(workflow_journal, read_only=True) as journal:
        events = journal.events(result["run_id"])
    assert [event.as_dict() for event in events] == [
        {**event, "labels": tuple(event["labels"])}
        for event in result["workflow_events"]
    ]


def test_malformed_labels_stop_before_body_patch() -> None:
    class InvalidLabels(FakeGitHub):
        def get_issue(self, issue_number: int) -> dict:
            return {**super().get_issue(issue_number), "labels": None}

    github = InvalidLabels()
    with pytest.raises(IssueLabelError):
        Orchestrator(config(), FakeDependencyTrack(), FakeKev(), github).run()
    assert github.created == github.updated == github.label_changes == []


def test_label_namespace_uses_project_route() -> None:
    from sbom_ops.config import RoutingConfig
    from sbom_ops.domain.routing import ProjectRoute

    github = FakeGitHub()
    github.labels = ["ops-P2", "sbom-P1", "human"]
    routed = replace(
        config(),
        routing=RoutingConfig((ProjectRoute("project-1", "acme", "service-a", "ops"),)),
    )
    Orchestrator(routed, FakeDependencyTrack(), FakeKev(), github).run()
    assert github.label_changes == [("add", ["ops", "ops-P0"]), ("remove", "ops-P2")]
    assert set(github.labels) == {"ops", "ops-P0", "sbom-P1", "human"}


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
    run_config = replace(
        config(), runtime=RuntimeConfig(dry_run=dry_run, github_write=True)
    )
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
    run_config = replace(
        config(), runtime=RuntimeConfig(dry_run=dry_run, github_write=True)
    )
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
        runtime=RuntimeConfig(wait_for_analysis=True, github_write=True),
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
        runtime=RuntimeConfig(wait_for_analysis=True, github_write=True),
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
        runtime=RuntimeConfig(wait_for_analysis=True, github_write=True),
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
        runtime=RuntimeConfig(wait_for_analysis=True, github_write=True),
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
        runtime=RuntimeConfig(wait_for_analysis=True, github_write=True),
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
        config(),
        runtime=RuntimeConfig(wait_for_analysis=wait_for_analysis, github_write=True),
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
        runtime=RuntimeConfig(wait_for_analysis=True, github_write=True),
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
    run_config = replace(
        config(), runtime=RuntimeConfig(wait_for_analysis=True, github_write=True)
    )
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
        runtime=RuntimeConfig(wait_for_analysis=True, github_write=True),
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
