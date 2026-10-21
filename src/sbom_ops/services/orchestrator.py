from __future__ import annotations

import re
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, replace
from functools import partial
from typing import Protocol, TypeVar

from sbom_ops.clients.dependency_track import (
    DependencyTrackClient,
    DependencyTrackFinding,
    DependencyTrackProject,
)
from sbom_ops.clients.github import GitHubApiError, GitHubIssuesClient
from sbom_ops.clients.kev import KevClient
from sbom_ops.config import AppConfig
from sbom_ops.domain.advisory import (
    AdvisorySnapshot,
    AdvisorySnapshotStatus,
    ProjectExposureObservation,
)
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegistryDeploymentObservation,
    RegistryProjectObservation,
    RegistrySnapshotStatus,
)
from sbom_ops.domain.assets import (
    AssetDeployment,
    AssetInventorySnapshot,
    AssetInventoryStatus,
)
from sbom_ops.domain.issue_body import (
    IssueBodyError,
    mark_finding_active,
    merge_issue_body,
    new_issue_body,
    parse_issue_body,
)
from sbom_ops.domain.issue_catalog import IssueCatalog, IssueIdentityError
from sbom_ops.domain.issue_intent import IssueCreateIntent, IssueIntentError
from sbom_ops.domain.issue_labels import (
    IssueLabelError,
    IssueLabelPlan,
    label_names,
    plan_issue_labels,
)
from sbom_ops.domain.models import (
    AnalysisSnapshotStatus,
    AnalysisState,
    Enrichment,
    Finding,
    FindingAssessment,
    FindingState,
    PrioritizedFinding,
    Severity,
)
from sbom_ops.domain.priority import order_assessments_for_review, prioritize_finding
from sbom_ops.domain.review import FindingReview, build_review_queue
from sbom_ops.domain.routing import ProjectRouter
from sbom_ops.domain.workflow import decide_missing_finding
from sbom_ops.domain.workflow_audit import WorkflowAudit, WorkflowEvent
from sbom_ops.services.asset_registry import (
    observe_registry_deployments,
    observe_registry_projects,
)
from sbom_ops.storage.issue_journal import IssueJournal

_WriteResult = TypeVar("_WriteResult")


class DependencyTrackClientProtocol(Protocol):
    def list_projects(self) -> list[DependencyTrackProject]: ...

    def get_project_findings(
        self, project_uuid: str
    ) -> list[DependencyTrackFinding]: ...

    def wait_for_analysis(
        self, project_uuid: str, *, timeout: float, poll_interval: float
    ) -> list[DependencyTrackFinding]: ...


class KevClientProtocol(Protocol):
    def get_known_exploited_vulnerabilities(
        self, *, force_refresh: bool = False
    ) -> set[str]: ...


class ProjectSelectionError(ValueError):
    """Raised when a requested project is not in the accessible DT inventory."""


_CVE_IDENTIFIER = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _kev_match(
    vulnerability_id: str, aliases: tuple[str, ...], kev_ids: set[str]
) -> bool:
    """Match KEV against a primary CVE ID or explicit Dependency-Track CVE alias."""
    candidates = (vulnerability_id, *aliases)
    return any(
        isinstance(identifier, str)
        and _CVE_IDENTIFIER.fullmatch(identifier.strip()) is not None
        and identifier.strip().upper() in kev_ids
        for identifier in candidates
    )


class GitHubIssuesClientProtocol(Protocol):
    def get_issue(self, issue_number: int) -> dict: ...

    def list_issues(self) -> list[dict]: ...

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict: ...

    def update_issue(self, issue_number: int, title: str | None, body: str) -> dict: ...

    def close_issue(self, issue_number: int) -> dict: ...

    def add_issue_labels(self, issue_number: int, labels: list[str]) -> list: ...

    def remove_issue_label(self, issue_number: int, label: str) -> list: ...


@dataclass(frozen=True)
class RunResult:
    run_id: str
    duration_seconds: float
    kev_used_stale_cache: bool
    projects_processed: int
    findings_processed: int
    issues_created: int
    issues_updated: int
    issues_closed: int
    dry_run: bool
    registry_snapshot_status: RegistrySnapshotStatus = (
        RegistrySnapshotStatus.NOT_REQUESTED
    )
    registry_projects: tuple[RegistryProjectObservation, ...] = ()
    registry_deployments: tuple[RegistryDeploymentObservation, ...] = ()
    analysis_snapshot_status: AnalysisSnapshotStatus = (
        AnalysisSnapshotStatus.NOT_REQUESTED
    )
    asset_inventory_status: AssetInventoryStatus = AssetInventoryStatus.NOT_REQUESTED
    asset_inventory_id: str | None = None
    asset_inventory_generated_at: str | None = None
    asset_inventory_sha256: str | None = None
    asset_inventory_error: str | None = None
    asset_deployments: tuple[AssetDeployment, ...] = ()
    asset_unmapped_project_uuids: tuple[str, ...] = ()
    asset_unmatched_project_uuids: tuple[str, ...] = ()
    advisory_snapshot_status: AdvisorySnapshotStatus = (
        AdvisorySnapshotStatus.NOT_REQUESTED
    )
    advisory_snapshot_id: str | None = None
    advisory_snapshot_generated_at: str | None = None
    advisory_snapshot_sha256: str | None = None
    advisory_snapshot_error: str | None = None
    poc_identity_status: str = "not_requested"
    poc_identity_error: str | None = None
    project_exposure_observations: tuple[ProjectExposureObservation, ...] = ()
    actions: tuple[str, ...] = ()
    assessments: tuple[FindingAssessment, ...] = ()
    workflow_events: tuple[WorkflowEvent, ...] = ()

    def review_assessments(self) -> tuple[FindingAssessment, ...]:
        return order_assessments_for_review(self.assessments)

    def review_queue(self) -> tuple[FindingReview, ...]:
        return build_review_queue(
            self.assessments,
            self.registry_snapshot_status,
            self.registry_projects,
            self.registry_deployments,
        )

    def as_dict(self) -> dict[str, object]:
        """Return an enum-free payload for CLI and downstream adapters."""
        return {
            "status": "succeeded",
            "workflow_events": [event.as_dict() for event in self.workflow_events],
            "audit_persistence_failed": False,
            "absence_verification": decide_missing_finding().as_dict(),
            "run_id": self.run_id,
            "duration_seconds": self.duration_seconds,
            "kev_used_stale_cache": self.kev_used_stale_cache,
            "projects_processed": self.projects_processed,
            "findings_processed": self.findings_processed,
            "issues_created": self.issues_created,
            "issues_updated": self.issues_updated,
            "issues_closed": self.issues_closed,
            "dry_run": self.dry_run,
            "registry_snapshot_status": self.registry_snapshot_status.value,
            "registry_projects": [item.as_dict() for item in self.registry_projects],
            "registry_deployments": [
                item.as_dict() for item in self.registry_deployments
            ],
            "analysis_snapshot_status": self.analysis_snapshot_status.value,
            "asset_inventory_status": self.asset_inventory_status.value,
            "asset_inventory_id": self.asset_inventory_id,
            "asset_inventory_generated_at": self.asset_inventory_generated_at,
            "asset_inventory_sha256": self.asset_inventory_sha256,
            "asset_inventory_error": self.asset_inventory_error,
            "asset_deployments": [item.as_dict() for item in self.asset_deployments],
            "asset_unmapped_project_uuids": list(self.asset_unmapped_project_uuids),
            "asset_unmatched_project_uuids": list(self.asset_unmatched_project_uuids),
            "advisory_snapshot_status": self.advisory_snapshot_status.value,
            "advisory_snapshot_id": self.advisory_snapshot_id,
            "advisory_snapshot_generated_at": self.advisory_snapshot_generated_at,
            "advisory_snapshot_sha256": self.advisory_snapshot_sha256,
            "advisory_snapshot_error": self.advisory_snapshot_error,
            "poc_identity_status": self.poc_identity_status,
            "poc_identity_error": self.poc_identity_error,
            "project_exposure_observations": [
                observation.as_dict()
                for observation in self.project_exposure_observations
            ],
            "actions": list(self.actions),
            "review_queue": [item.as_dict() for item in self.review_queue()],
            "assessments": [
                {
                    "project_uuid": item.project_uuid,
                    "finding_key": item.finding_key,
                    "vulnerability_id": item.vulnerability_id,
                    "vulnerability_source": item.vulnerability_source,
                    "vulnerability_aliases": list(item.vulnerability_aliases),
                    "component_uuid": item.component_uuid,
                    "component_purl": item.component_purl,
                    "component_name": item.component_name,
                    "component_version": item.component_version,
                    "severity": item.severity.value,
                    "cvss_score": item.cvss_score,
                    "cvss_version": item.cvss_version,
                    "epss_score": item.epss_score,
                    "priority": item.priority.value,
                    "analysis_state": item.analysis_state.value,
                    "is_suppressed": item.is_suppressed,
                    "analysis_detail": item.analysis_detail,
                    "in_kev": item.in_kev,
                    "advisory_observations": [
                        observation.as_dict()
                        for observation in item.advisory_observations
                    ],
                    "poc_reports": item.poc_reports.as_dict(),
                    "poc_identity": (
                        item.poc_identity.as_dict() if item.poc_identity else None
                    ),
                    "rationale": list(item.rationale),
                }
                for item in self.review_assessments()
            ],
        }


class Orchestrator:
    def __init__(
        self,
        config: AppConfig,
        dependency_track: DependencyTrackClientProtocol | None = None,
        kev: KevClientProtocol | None = None,
        github: GitHubIssuesClientProtocol | None = None,
        *,
        force_refresh_kev: bool = False,
        advisory_snapshot: AdvisorySnapshot | None = None,
        asset_inventory: AssetInventorySnapshot | None = None,
        asset_registry: AssetRegistrySnapshot | None = None,
    ) -> None:
        self._config = config
        self._dependency_track = dependency_track or DependencyTrackClient(
            config.dependency_track.base_url,
            config.dependency_track.api_key,
            timeout=config.dependency_track.timeout_seconds,
            page_size=config.dependency_track.page_size,
            max_retries=config.dependency_track.max_retries,
            retry_backoff_seconds=config.dependency_track.retry_backoff_seconds,
        )
        self._kev = kev or KevClient(
            config.intelligence.kev_feed_url,
            timeout=config.intelligence.timeout_seconds,
            max_retries=config.intelligence.max_retries,
            retry_backoff_seconds=config.intelligence.retry_backoff_seconds,
            cache_path=config.intelligence.kev_cache_file,
            cache_ttl_seconds=config.intelligence.kev_cache_ttl_seconds,
            allow_stale_cache=config.intelligence.kev_cache_allow_stale,
        )
        self._github = github
        self._force_refresh_kev = force_refresh_kev
        self._advisory_snapshot = advisory_snapshot
        self._asset_inventory = asset_inventory
        self._asset_registry = asset_registry
        if config.github.enabled and self._github is None:
            self._github = GitHubIssuesClient(
                config.github.token,
                config.github.owner,
                config.github.repo,
                timeout=config.github.timeout_seconds,
                max_retries=config.github.max_retries,
                retry_backoff_seconds=config.github.retry_backoff_seconds,
            )
        self._project_router = ProjectRouter(config.routing.routes)
        self._github_cache: dict[tuple[str, str, str], GitHubIssuesClientProtocol] = {}
        self._injected_github = github is not None

    def _github_target(
        self, project_uuid: str
    ) -> tuple[GitHubIssuesClientProtocol, str, tuple[str, str, str]]:
        route = self._project_router.resolve(project_uuid)
        owner = route.owner if route else self._config.github.owner
        repo = route.repo if route else self._config.github.repo
        label = (
            route.issue_label_prefix or self._config.github.issue_label_prefix
            if route
            else self._config.github.issue_label_prefix
        )
        target_key = (owner.lower(), repo.lower(), label)
        if self._injected_github:
            assert self._github is not None
            return self._github, label, target_key
        client = self._github_cache.get(target_key)
        if client is None:
            client = GitHubIssuesClient(
                self._config.github.token,
                owner,
                repo,
                timeout=self._config.github.timeout_seconds,
                max_retries=self._config.github.max_retries,
                retry_backoff_seconds=self._config.github.retry_backoff_seconds,
            )
            self._github_cache[target_key] = client
        return client, label, target_key

    def run(self, *, audit: WorkflowAudit | None = None) -> RunResult:
        audit = audit or WorkflowAudit()
        with ExitStack() as stack:
            try:
                audit.start()
                journal = None
                if self._config.github.enabled:
                    path = self._config.workflow.issue_journal_file
                    if path is None and not self._config.runtime.dry_run:
                        raise IssueIntentError(
                            "GitHub writes require workflow.issue_journal_file; "
                            "initialize it explicitly with workflow init"
                        )
                    if path is not None:
                        journal = stack.enter_context(
                            IssueJournal(path, read_only=self._config.runtime.dry_run)
                        )
                        if not self._config.runtime.dry_run:
                            audit.attach(journal.append_event)
                result = self._run(journal, audit)
                audit.emit("run_succeeded")
                return replace(result, workflow_events=tuple(audit.events))
            except BaseException as exc:
                try:
                    audit.fail(exc)
                except BaseException:
                    # Preserve the original failure if the audit disk also fails.
                    audit.persistence_failed = True
                raise
            finally:
                audit.detach()

    def _run(self, journal: IssueJournal | None, audit: WorkflowAudit) -> RunResult:
        run_id = audit.run_id
        started_at = time.monotonic()
        all_projects = self._dependency_track.list_projects()
        available_project_uuids = {project.uuid for project in all_projects}
        projects = all_projects
        project_filter = set(self._config.runtime.project_uuids)
        if project_filter:
            unavailable = sorted(project_filter - available_project_uuids)
            if unavailable:
                raise ProjectSelectionError(
                    "requested Dependency-Track project UUID(s) are not accessible: "
                    + ", ".join(unavailable)
                )
            projects = [
                project for project in projects if project.uuid in project_filter
            ]
        registry_projects = (
            observe_registry_projects(self._asset_registry, all_projects, projects)
            if self._asset_registry is not None
            else ()
        )
        registry_deployments = (
            observe_registry_deployments(self._asset_registry, registry_projects)
            if self._asset_registry is not None
            else ()
        )
        if not self._config.runtime.wait_for_analysis:
            snapshot_status = AnalysisSnapshotStatus.NOT_REQUESTED
        elif not projects:
            snapshot_status = AnalysisSnapshotStatus.NO_PROJECTS
        else:
            # Every project must complete its stable-snapshot wait before the
            # run can reach result construction.
            snapshot_status = AnalysisSnapshotStatus.STABLE

        kev_ids = {
            identifier.strip().upper()
            for identifier in self._kev.get_known_exploited_vulnerabilities(
                force_refresh=self._force_refresh_kev
            )
            if isinstance(identifier, str) and identifier.strip()
        }
        kev_used_stale_cache = bool(getattr(self._kev, "used_stale_cache", False))
        current_keys: set[str] = set()
        created = updated = closed = findings_processed = 0
        actions: list[str] = []
        assessments: list[FindingAssessment] = []
        touched_issue_numbers: dict[tuple[str, str, str], set[int]] = {}
        target_clients: dict[tuple[str, str, str], GitHubIssuesClientProtocol] = {}
        target_projects: dict[tuple[str, str, str], set[str]] = {}
        catalogs: dict[tuple[str, str], IssueCatalog] = {}
        repository_issues: dict[tuple[str, str], list[dict]] = {}
        handled_keys: set[tuple[str, str, str]] = set()

        # Read every selected project before touching GitHub. A later DT read
        # failure must not leave earlier projects partially synchronized.
        # Even stable responses do not prove a complete or resolved inventory.
        findings_by_project: dict[str, list[DependencyTrackFinding]] = {}
        for project in projects:
            if self._config.runtime.wait_for_analysis:
                findings_by_project[project.uuid] = (
                    self._dependency_track.wait_for_analysis(
                        project.uuid,
                        timeout=self._config.dependency_track.analysis_wait_timeout_seconds,
                        poll_interval=(
                            self._config.dependency_track.analysis_poll_interval_seconds
                        ),
                    )
                )
            else:
                findings_by_project[project.uuid] = (
                    self._dependency_track.get_project_findings(project.uuid)
                )

        prioritized_by_project = {
            project.uuid: [
                self._prioritize(raw, kev_ids)
                for raw in findings_by_project[project.uuid]
            ]
            for project in projects
        }
        legacy_identities: dict[str, set[str]] = {}
        for items in prioritized_by_project.values():
            for item in items:
                legacy_identities.setdefault(
                    item.finding.legacy_finding_key(), set()
                ).add(item.finding.finding_key())

        if self._config.github.enabled:
            for project in projects:
                github, issue_label, target_key = self._github_target(project.uuid)
                target_clients[target_key] = github
                target_projects.setdefault(target_key, set()).add(project.uuid)
                repository = target_key[:2]
                if repository not in catalogs:
                    repository_issues[repository] = github.list_issues()
                    catalogs[repository] = IssueCatalog(repository_issues[repository])
                for item in prioritized_by_project[project.uuid]:
                    key, legacy = (
                        item.finding.finding_key(),
                        item.finding.legacy_finding_key(),
                    )
                    match = catalogs[repository].find(key, legacy)
                    if (
                        match is not None
                        and match.key == legacy
                        and len(legacy_identities[legacy]) > 1
                    ):
                        raise IssueIdentityError(
                            "legacy finding key maps to multiple current identities"
                        )

        # Reconcile every prior create in the selected repositories, including
        # findings absent from today's input. Absence never authorizes a resend.
        if journal is not None:
            by_repository = {
                "/".join(repo): catalog for repo, catalog in catalogs.items()
            }
            pending_confirmations: list[tuple[IssueCreateIntent, int]] = []
            for intent in journal.records():
                previous_catalog = by_repository.get(intent.repository)
                if previous_catalog is None:
                    continue
                match = previous_catalog.find(intent.finding_key, intent.finding_key)
                if match is None or (
                    intent.state == "confirmed" and match.number != intent.issue_number
                ):
                    raise IssueIntentError(
                        f"create intent {intent.intent_id} cannot be reconciled; "
                        "inspect GitHub and preserve the journal; no POST was retried"
                    )
                if intent.state == "pending":
                    pending_confirmations.append((intent, match.number))
            for intent, number in pending_confirmations:
                actions.append(f"reconcile-create {intent.finding_key} issue=#{number}")
                if not self._config.runtime.dry_run:
                    journal.confirm(intent, number, run_id)
                    audit.emit(
                        "operation_reconciled",
                        operation_id=intent.intent_id,
                        operation="create_issue",
                        repository=intent.repository,
                        finding_key=intent.finding_key,
                        issue_number=number,
                    )

        for project in projects:
            if self._config.github.enabled:
                github, issue_label, target_key = self._github_target(project.uuid)
                catalog = catalogs[target_key[:2]]
            raw_findings = findings_by_project[project.uuid]
            findings_processed += len(raw_findings)
            prioritized: list[PrioritizedFinding] = []
            for prioritized_finding in prioritized_by_project[project.uuid]:
                current_keys.add(prioritized_finding.finding.finding_key())
                current_keys.add(prioritized_finding.finding.legacy_finding_key())
                prioritized.append(prioritized_finding)
                assessments.append(
                    FindingAssessment(
                        project_uuid=project.uuid,
                        finding_key=prioritized_finding.finding.finding_key(),
                        vulnerability_id=prioritized_finding.finding.vulnerability_id,
                        vulnerability_source=(
                            prioritized_finding.finding.vulnerability_source
                        ),
                        severity=prioritized_finding.finding.severity,
                        cvss_score=prioritized_finding.finding.cvss_score,
                        epss_score=prioritized_finding.enrichment.epss_score,
                        priority=prioritized_finding.priority,
                        analysis_state=prioritized_finding.enrichment.analysis_state,
                        is_suppressed=prioritized_finding.enrichment.is_suppressed,
                        rationale=prioritized_finding.rationale,
                        analysis_detail=(
                            prioritized_finding.enrichment.analysis_detail
                        ),
                        in_kev=prioritized_finding.enrichment.in_kev,
                        component_uuid=(
                            prioritized_finding.finding.dependency_track_component_uuid
                        ),
                        component_purl=prioritized_finding.finding.component_purl,
                        component_name=prioritized_finding.finding.component_name,
                        component_version=prioritized_finding.finding.component_version,
                        vulnerability_aliases=(
                            prioritized_finding.finding.vulnerability_aliases
                        ),
                        cvss_version=prioritized_finding.finding.cvss_version,
                        advisory_observations=(
                            self._advisory_snapshot.observations_for(
                                prioritized_finding.finding.vulnerability_id,
                                prioritized_finding.finding.vulnerability_aliases,
                            )
                            if self._advisory_snapshot
                            else ()
                        ),
                    )
                )

            for item in prioritized:
                if self._excluded_by_analysis(item):
                    continue
                if not self._config.github.enabled:
                    continue
                title, body = self._issue_content(item)
                key = item.finding.finding_key()
                handling_key = (*target_key[:2], key)
                if handling_key in handled_keys:
                    continue
                handled_keys.add(handling_key)
                existing = catalog.find(key, item.finding.legacy_finding_key())
                if (
                    existing is None
                    and item.priority.value
                    not in self._config.priority.create_issues_for
                ):
                    continue
                if existing is not None and existing.state == "closed":
                    actions.append(f"review-closed {key} issue=#{existing.number}")
                    continue
                if existing is None:
                    actions.append(
                        f"create {key} priority={item.priority.value} "
                        f"analysis={item.enrichment.analysis_state.value}"
                    )
                    if not self._config.runtime.dry_run:
                        assert journal is not None
                        intent = journal.reserve("/".join(target_key[:2]), key, run_id)
                        operation = audit.begin(
                            "create_issue",
                            intent.repository,
                            key,
                            labels=(
                                issue_label,
                                f"{issue_label}-{item.priority.value}",
                            ),
                            operation_id=intent.intent_id,
                        )
                        reconciled = False
                        try:
                            response = github.create_issue(
                                title,
                                body,
                                [issue_label, f"{issue_label}-{item.priority.value}"],
                            )
                            confirmed = IssueCatalog([response]).find(key, key)
                            if confirmed is None or confirmed.state != "open":
                                raise IssueIdentityError(
                                    "create response did not confirm the finding"
                                )
                        except (GitHubApiError, IssueIdentityError) as exc:
                            try:
                                audit.outcome(
                                    operation,
                                    "operation_unknown",
                                    error_type=type(exc).__name__,
                                )
                            except BaseException:
                                audit.persistence_failed = True
                                raise exc from None
                            # Never retry POST. Re-read the repository to reconcile
                            # a response lost after the server accepted the write.
                            catalog = IssueCatalog(github.list_issues())
                            catalogs[target_key[:2]] = catalog
                            confirmed = catalog.find(
                                key, item.finding.legacy_finding_key()
                            )
                            if confirmed is None:
                                raise GitHubApiError(
                                    "GitHub create outcome is unknown; "
                                    "inspect the repository "
                                    "before another sync; no POST was retried"
                                ) from None
                            actions.append(
                                f"create-reconciled {key} issue=#{confirmed.number}"
                            )
                            reconciled = True
                        catalog.record(
                            confirmed.number, confirmed.state, confirmed.body
                        )
                        journal.confirm(intent, confirmed.number, run_id)
                        audit.outcome(
                            operation,
                            (
                                "operation_reconciled"
                                if reconciled
                                else "operation_confirmed"
                            ),
                            issue_number=confirmed.number,
                        )
                    created += 1
                else:
                    number = existing.number
                    latest = self._read_issue_for_update(github, number)
                    labels = plan_issue_labels(
                        label_names(latest.get("labels")),
                        issue_label,
                        item.priority,
                    )
                    body = merge_issue_body(
                        latest["body"],
                        body,
                        expected_keys=(key, item.finding.legacy_finding_key()),
                    )
                    actions.append(
                        f"update {key} issue=#{number} priority={item.priority.value}"
                    )
                    if labels.add or labels.remove:
                        actions.append(
                            f"labels {key} issue=#{number} "
                            f"add={list(labels.add)!r} remove={list(labels.remove)!r}"
                        )
                    if not self._config.runtime.dry_run:
                        self._audited_write(
                            audit,
                            "update_body",
                            "/".join(target_key[:2]),
                            key,
                            number,
                            partial(github.update_issue, number, None, body),
                        )
                        catalog.record(number, "open", body, previous_key=existing.key)
                        self._apply_issue_labels(
                            github, number, labels, audit, "/".join(target_key[:2]), key
                        )
                    touched_issue_numbers.setdefault(target_key, set()).add(int(number))
                    updated += 1

        for target_key, github in target_clients.items():
            issue_label = target_key[2]
            managed_for_target = target_projects[target_key]
            touched_for_target = touched_issue_numbers.get(target_key, set())
            for issue in repository_issues[target_key[:2]]:
                if issue.get("state") != "open":
                    continue
                key = self._finding_key_from_issue(issue)
                if key is None:
                    continue
                if self._project_uuid_from_finding_key(key) not in managed_for_target:
                    continue
                catalogs[target_key[:2]].find(key, key)
                number = issue.get("number")
                if key in current_keys:
                    if (
                        number is not None
                        and int(number) not in touched_for_target
                        and (
                            self._missing_count_from_issue(issue) > 0
                            or self._finding_state_from_issue(issue)
                            in {
                                FindingState.MISSING,
                                FindingState.RESOLVED,
                                FindingState.UNKNOWN,
                            }
                        )
                    ):
                        latest = self._read_issue_for_update(github, number)
                        body = mark_finding_active(latest["body"], expected_key=key)
                        actions.append(
                            f"mark-active {key} issue=#{number} reason=reappeared"
                        )
                        if not self._config.runtime.dry_run:
                            self._audited_write(
                                audit,
                                "update_body",
                                "/".join(target_key[:2]),
                                key,
                                int(number),
                                partial(github.update_issue, int(number), None, body),
                            )
                        updated += 1
                    continue
                if self._project_uuid_from_finding_key(key) not in managed_for_target:
                    continue
                if number is None:
                    continue
                decision = decide_missing_finding()
                actions.append(
                    f"keep-open {key} issue=#{number} reason={decision.reason}"
                )

        return RunResult(
            run_id=run_id,
            duration_seconds=round(time.monotonic() - started_at, 6),
            kev_used_stale_cache=kev_used_stale_cache,
            projects_processed=len(projects),
            findings_processed=findings_processed,
            issues_created=created,
            issues_updated=updated,
            issues_closed=closed,
            dry_run=self._config.runtime.dry_run,
            registry_snapshot_status=(
                RegistrySnapshotStatus.LOADED
                if self._asset_registry is not None
                else RegistrySnapshotStatus.NOT_REQUESTED
            ),
            registry_projects=registry_projects,
            registry_deployments=registry_deployments,
            analysis_snapshot_status=snapshot_status,
            asset_inventory_status=(
                AssetInventoryStatus.LOADED
                if self._asset_inventory
                else AssetInventoryStatus.NOT_REQUESTED
            ),
            asset_inventory_id=(
                self._asset_inventory.snapshot_id if self._asset_inventory else None
            ),
            asset_inventory_generated_at=(
                self._asset_inventory.generated_at if self._asset_inventory else None
            ),
            asset_inventory_sha256=(
                self._asset_inventory.sha256 if self._asset_inventory else None
            ),
            asset_deployments=(
                tuple(
                    deployment
                    for project in projects
                    for deployment in self._asset_inventory.for_project(project.uuid)
                )
                if self._asset_inventory
                else ()
            ),
            asset_unmapped_project_uuids=(
                tuple(
                    sorted(
                        project.uuid
                        for project in projects
                        if not self._asset_inventory.for_project(project.uuid)
                    )
                )
                if self._asset_inventory
                else ()
            ),
            asset_unmatched_project_uuids=(
                tuple(
                    sorted(
                        {
                            item.project_uuid
                            for item in self._asset_inventory.deployments
                            if item.project_uuid not in available_project_uuids
                        }
                    )
                )
                if self._asset_inventory
                else ()
            ),
            advisory_snapshot_status=(
                AdvisorySnapshotStatus.LOADED
                if self._advisory_snapshot
                else AdvisorySnapshotStatus.NOT_REQUESTED
            ),
            advisory_snapshot_id=(
                self._advisory_snapshot.snapshot_id if self._advisory_snapshot else None
            ),
            advisory_snapshot_generated_at=(
                self._advisory_snapshot.generated_at
                if self._advisory_snapshot
                else None
            ),
            advisory_snapshot_sha256=(
                self._advisory_snapshot.sha256 if self._advisory_snapshot else None
            ),
            project_exposure_observations=(
                tuple(
                    observation
                    for project in projects
                    for observation in self._advisory_snapshot.exposure_for_project(
                        project.uuid
                    )
                )
                if self._advisory_snapshot
                else ()
            ),
            actions=tuple(actions),
            assessments=tuple(assessments),
        )

    def _prioritize(
        self, raw: DependencyTrackFinding, kev_ids: set[str]
    ) -> PrioritizedFinding:
        finding = Finding(
            project_uuid=raw.project_uuid,
            project_name=raw.project_name,
            component_name=raw.component_name,
            component_version=raw.component_version,
            vulnerability_id=raw.vulnerability_id,
            severity=self._severity(raw.severity),
            cvss_score=raw.cvss_score,
            cwes=raw.cwes,
            description=raw.description,
            dependency_track_finding_id=raw.finding_id,
            dependency_track_vulnerability_uuid=raw.vulnerability_uuid,
            vulnerability_source=raw.vulnerability_source,
            dependency_track_component_uuid=raw.component_uuid,
            component_purl=raw.component_purl,
            vulnerability_aliases=raw.vulnerability_aliases,
            cvss_version=raw.cvss_version,
        )
        kev_match = _kev_match(raw.vulnerability_id, raw.vulnerability_aliases, kev_ids)
        enrichment = Enrichment(
            in_kev=kev_match,
            epss_score=raw.epss_score,
            has_known_active_exploitation=kev_match,
            analysis_state=self._analysis_state(raw.analysis_state),
            is_suppressed=raw.is_suppressed,
            analysis_detail=raw.analysis_detail,
        )
        return prioritize_finding(finding, enrichment, self._config.priority)

    @staticmethod
    def _severity(value: str) -> Severity:
        try:
            return Severity(value.upper())
        except ValueError:
            return Severity.UNKNOWN

    @staticmethod
    def _analysis_state(value: str | None) -> AnalysisState:
        if value is None:
            return AnalysisState.NOT_SET
        try:
            return AnalysisState(value.upper())
        except ValueError:
            return AnalysisState.UNKNOWN

    @staticmethod
    def _apply_issue_labels(
        github: GitHubIssuesClientProtocol,
        number: int,
        plan: IssueLabelPlan,
        audit: WorkflowAudit,
        repository: str,
        key: str,
    ) -> None:
        wanted = {name.casefold() for name in plan.desired}
        if plan.add:

            def add() -> None:
                added = label_names(github.add_issue_labels(number, list(plan.add)))
                if not wanted.issubset({name.casefold() for name in added}):
                    raise IssueLabelError(
                        "required labels were not confirmed; no removal attempted"
                    )

            Orchestrator._audited_write(
                audit, "add_labels", repository, key, number, add, labels=plan.add
            )
        for name in plan.remove:

            def remove(name: str = name) -> None:
                remaining = {
                    value.casefold()
                    for value in label_names(github.remove_issue_label(number, name))
                }
                if name.casefold() in remaining or not wanted.issubset(remaining):
                    raise IssueLabelError(
                        "label removal outcome was not confirmed; "
                        "inspect before retrying"
                    )

            Orchestrator._audited_write(
                audit, "remove_label", repository, key, number, remove, labels=(name,)
            )

    @staticmethod
    def _audited_write(
        audit: WorkflowAudit,
        kind: str,
        repository: str,
        key: str,
        number: int,
        call: Callable[[], _WriteResult],
        *,
        labels: tuple[str, ...] = (),
    ) -> _WriteResult:
        operation = audit.begin(kind, repository, key, number, labels)
        try:
            result = call()
            if kind == "update_body" and (
                not isinstance(result, dict)
                or type(result.get("number")) is not int
                or result["number"] != number
            ):
                raise IssueIdentityError(
                    "update response did not confirm the issue number"
                )
        except BaseException as exc:
            try:
                audit.outcome(
                    operation, "operation_unknown", error_type=type(exc).__name__
                )
            except BaseException:
                audit.persistence_failed = True
            raise
        audit.outcome(operation, "operation_confirmed")
        return result

    @staticmethod
    def _excluded_by_analysis(item: PrioritizedFinding) -> bool:
        return item.enrichment.is_suppressed or item.enrichment.analysis_state in {
            AnalysisState.NOT_AFFECTED,
            AnalysisState.FALSE_POSITIVE,
        }

    @staticmethod
    def _read_issue_for_update(
        github: GitHubIssuesClientProtocol, number: object
    ) -> dict:
        if type(number) is not int or number <= 0:
            raise IssueBodyError("invalid issue number for update")
        latest = github.get_issue(number)
        if (
            not isinstance(latest, dict)
            or type(latest.get("number")) is not int
            or latest["number"] != number
            or latest.get("state") != "open"
            or "pull_request" in latest
            or not isinstance(latest.get("body"), str)
            or not isinstance(latest.get("title"), str)
        ):
            raise IssueBodyError("issue changed or has an invalid update response")
        return latest

    @staticmethod
    def _finding_key_from_issue(issue: dict) -> str | None:
        return parse_issue_body(issue.get("body") or "").finding_key

    @staticmethod
    def _project_uuid_from_finding_key(finding_key: str) -> str:
        if finding_key.startswith("v2:"):
            parts = finding_key.split(":", 2)
            return parts[1] if len(parts) == 3 else ""
        return finding_key.split(":", 1)[0]

    @staticmethod
    def _missing_count_from_issue(issue: dict) -> int:
        return parse_issue_body(issue.get("body") or "").missing_count

    @staticmethod
    def _finding_state_from_issue(issue: dict) -> FindingState | None:
        return parse_issue_body(issue.get("body") or "").finding_state

    @staticmethod
    def _issue_content(item: PrioritizedFinding) -> tuple[str, str]:
        finding = item.finding
        enrichment = item.enrichment
        title = (
            f"[{item.priority.value}] {finding.vulnerability_id}: "
            f"{finding.component_name} {finding.component_version or ''}".strip()
        )
        rationale = ", ".join(item.rationale)
        body = f"""## Vulnerability

- Project: `{finding.project_name}` (`{finding.project_uuid}`)
- Component: `{finding.component_name}` `{finding.component_version or "unknown"}`
- Component UUID: `{finding.dependency_track_component_uuid or "unknown"}`
- Package URL: `{finding.component_purl or "unknown"}`
- Vulnerability: `{finding.vulnerability_id}`
- Vulnerability source: `{finding.vulnerability_source or "unknown"}`
- Priority: `{item.priority.value}`
- CVSS: `{finding.cvss_score if finding.cvss_score is not None else "unknown"}`
- CVSS version: `{finding.cvss_version or "unknown"}`
- EPSS: `{enrichment.epss_score if enrichment.epss_score is not None else "unknown"}`
- KEV: `{"yes" if enrichment.in_kev else "no"}`
- Dependency-Track analysis: `{enrichment.analysis_state.value}`
- Analysis detail: {enrichment.analysis_detail or "None"}

## Rationale

{rationale}

## Description

{finding.description or "No description provided by Dependency-Track."}

This issue is synchronized from Dependency-Track by sbom-ops.
"""
        return title, new_issue_body(finding.finding_key(), body)
