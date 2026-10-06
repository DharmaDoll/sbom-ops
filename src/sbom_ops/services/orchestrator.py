from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4

from sbom_ops.clients.dependency_track import (
    DependencyTrackClient,
    DependencyTrackFinding,
    DependencyTrackProject,
)
from sbom_ops.clients.github import GitHubIssuesClient
from sbom_ops.clients.kev import KevClient
from sbom_ops.config import AppConfig
from sbom_ops.domain.advisory import (
    AdvisorySnapshot,
    AdvisorySnapshotStatus,
    ProjectExposureObservation,
)
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegistryProjectObservation,
    RegistrySnapshotStatus,
)
from sbom_ops.domain.assets import (
    AssetDeployment,
    AssetInventorySnapshot,
    AssetInventoryStatus,
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
from sbom_ops.domain.priority import prioritize_finding
from sbom_ops.domain.routing import ProjectRouter
from sbom_ops.domain.workflow import MissingFindingAction, decide_missing_finding
from sbom_ops.services.asset_registry import observe_registry_projects


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
    def find_open_issue_by_finding_key(self, finding_key: str) -> dict | None: ...

    def list_open_issues(self, label: str) -> list[dict]: ...

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict: ...

    def update_issue(self, issue_number: int, title: str, body: str) -> dict: ...

    def close_issue(self, issue_number: int) -> dict: ...


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
    project_exposure_observations: tuple[ProjectExposureObservation, ...] = ()
    actions: tuple[str, ...] = ()
    assessments: tuple[FindingAssessment, ...] = ()

    def as_dict(self) -> dict[str, object]:
        """Return an enum-free payload for CLI and downstream adapters."""
        return {
            "status": "succeeded",
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
            "project_exposure_observations": [
                observation.as_dict()
                for observation in self.project_exposure_observations
            ],
            "actions": list(self.actions),
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
                    "rationale": list(item.rationale),
                }
                for item in self.assessments
            ],
        }


_FINDING_KEY_PATTERN = re.compile(r"<!-- sbom-ops:finding-key=(.*?) -->")
_MISSING_COUNT_PATTERN = re.compile(r"<!-- sbom-ops:missing-count=([^<>\n]*) -->")
_FINDING_STATE_PATTERN = re.compile(r"<!-- sbom-ops:finding-state=([^<>\n]*) -->")


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
        target_key = (owner, repo, label)
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

    def run(self) -> RunResult:
        run_id = str(uuid4())
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

        for project in projects:
            if self._config.github.enabled:
                github, issue_label, target_key = self._github_target(project.uuid)
                target_clients[target_key] = github
                target_projects.setdefault(target_key, set()).add(project.uuid)
            if self._config.runtime.wait_for_analysis:
                raw_findings = self._dependency_track.wait_for_analysis(
                    project.uuid,
                    timeout=self._config.dependency_track.analysis_wait_timeout_seconds,
                    poll_interval=(
                        self._config.dependency_track.analysis_poll_interval_seconds
                    ),
                )
            else:
                raw_findings = self._dependency_track.get_project_findings(project.uuid)
            findings_processed += len(raw_findings)
            prioritized: list[PrioritizedFinding] = []
            for raw in raw_findings:
                prioritized_finding = self._prioritize(raw, kev_ids)
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
                if item.priority.value not in self._config.priority.create_issues_for:
                    continue
                if not self._config.github.enabled:
                    continue
                title, body = self._issue_content(item)
                key = item.finding.finding_key()
                existing = github.find_open_issue_by_finding_key(key)
                if existing is None:
                    existing = github.find_open_issue_by_finding_key(
                        item.finding.legacy_finding_key()
                    )
                if existing is None:
                    actions.append(
                        f"create {key} priority={item.priority.value} "
                        f"analysis={item.enrichment.analysis_state.value}"
                    )
                    if not self._config.runtime.dry_run:
                        github.create_issue(
                            title,
                            body,
                            [
                                issue_label,
                                (f"{issue_label}-{item.priority.value}"),
                            ],
                        )
                    created += 1
                else:
                    number = existing.get("number")
                    if number is None:
                        continue
                    actions.append(
                        f"update {key} issue=#{number} priority={item.priority.value}"
                    )
                    if not self._config.runtime.dry_run:
                        github.update_issue(int(number), title, body)
                    touched_issue_numbers.setdefault(target_key, set()).add(int(number))
                    updated += 1

        for target_key, github in target_clients.items():
            issue_label = target_key[2]
            managed_for_target = target_projects[target_key]
            touched_for_target = touched_issue_numbers.get(target_key, set())
            for issue in github.list_open_issues(issue_label):
                key = self._finding_key_from_issue(issue)
                if key is None:
                    continue
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
                        actions.append(
                            f"mark-active {key} issue=#{number} reason=reappeared"
                        )
                        if not self._config.runtime.dry_run:
                            github.update_issue(
                                int(number),
                                str(issue.get("title") or "sbom-ops managed finding"),
                                self._with_active_observation(issue.get("body") or ""),
                            )
                        updated += 1
                    continue
                if self._project_uuid_from_finding_key(key) not in managed_for_target:
                    continue
                if number is None:
                    continue
                body = issue.get("body") or ""
                decision = decide_missing_finding(
                    self._missing_count_from_issue(issue),
                    previous_finding_state=self._finding_state_from_issue(issue),
                    automatic_closure_enabled=(
                        self._config.workflow.close_missing_findings
                    ),
                    scan_verified=self._config.runtime.wait_for_analysis,
                    confirmations_required=(
                        self._config.workflow.missing_confirmation_runs
                    ),
                )
                if decision.action == MissingFindingAction.NOOP:
                    actions.append(
                        f"keep-open {key} issue=#{number} reason={decision.reason}"
                    )
                    continue
                if decision.action == MissingFindingAction.MARK_MISSING:
                    actions.append(
                        f"mark-missing {key} issue=#{number} "
                        f"count={decision.missing_count} reason={decision.reason}"
                    )
                    if not self._config.runtime.dry_run:
                        github.update_issue(
                            int(number),
                            str(issue.get("title") or "sbom-ops managed finding"),
                            self._with_finding_observation(
                                body,
                                decision.finding_state,
                                decision.missing_count,
                            ),
                        )
                    updated += 1
                    continue
                actions.append(
                    f"close {key} issue=#{number} count={decision.missing_count} "
                    f"reason={decision.reason}"
                )
                if not self._config.runtime.dry_run:
                    github.update_issue(
                        int(number),
                        str(issue.get("title") or "sbom-ops managed finding"),
                        self._with_finding_observation(
                            body,
                            decision.finding_state,
                            decision.missing_count,
                        ),
                    )
                    github.close_issue(int(number))
                updated += 1
                closed += 1

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
    def _excluded_by_analysis(item: PrioritizedFinding) -> bool:
        return item.enrichment.is_suppressed or item.enrichment.analysis_state in {
            AnalysisState.NOT_AFFECTED,
            AnalysisState.FALSE_POSITIVE,
        }

    @staticmethod
    def _finding_key_from_issue(issue: dict) -> str | None:
        body = issue.get("body") or ""
        match = _FINDING_KEY_PATTERN.search(body)
        return match.group(1) if match else None

    @staticmethod
    def _project_uuid_from_finding_key(finding_key: str) -> str:
        if finding_key.startswith("v2:"):
            parts = finding_key.split(":", 2)
            return parts[1] if len(parts) == 3 else ""
        return finding_key.split(":", 1)[0]

    @staticmethod
    def _missing_count_from_issue(issue: dict) -> int:
        body = issue.get("body") or ""
        matches = _MISSING_COUNT_PATTERN.findall(body)
        if len(matches) != 1 or re.fullmatch(r"[0-9]{1,9}", matches[0]) is None:
            return 0
        return int(matches[0])

    @staticmethod
    def _finding_state_from_issue(issue: dict) -> FindingState | None:
        body = issue.get("body") or ""
        matches = _FINDING_STATE_PATTERN.findall(body)
        if len(matches) != 1:
            return None
        try:
            return FindingState(matches[0])
        except ValueError:
            return None

    @staticmethod
    def _with_finding_observation(
        body: str, finding_state: FindingState, missing_count: int
    ) -> str:
        state_marker = f"<!-- sbom-ops:finding-state={finding_state.value} -->"
        count_marker = f"<!-- sbom-ops:missing-count={missing_count} -->"
        body = _FINDING_STATE_PATTERN.sub("", body)
        body = _MISSING_COUNT_PATTERN.sub("", body)
        return f"{body.rstrip()}\n\n{state_marker}\n{count_marker}\n"

    @staticmethod
    def _with_active_observation(body: str) -> str:
        state_marker = f"<!-- sbom-ops:finding-state={FindingState.ACTIVE.value} -->"
        body = _FINDING_STATE_PATTERN.sub("", body)
        body = _MISSING_COUNT_PATTERN.sub("", body)
        return f"{body.rstrip()}\n\n{state_marker}\n"

    @staticmethod
    def _issue_content(item: PrioritizedFinding) -> tuple[str, str]:
        finding = item.finding
        enrichment = item.enrichment
        title = (
            f"[{item.priority.value}] {finding.vulnerability_id}: "
            f"{finding.component_name} {finding.component_version or ''}".strip()
        )
        rationale = ", ".join(item.rationale)
        body = f"""<!-- sbom-ops:finding-key={finding.finding_key()} -->
<!-- sbom-ops:finding-state={FindingState.ACTIVE.value} -->

## Vulnerability

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
        return title, body
