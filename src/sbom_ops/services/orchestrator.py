from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from sbom_ops.clients.dependency_track import (
    DependencyTrackClient,
    DependencyTrackFinding,
    DependencyTrackProject,
)
from sbom_ops.clients.github import GitHubIssuesClient
from sbom_ops.clients.kev import KevClient
from sbom_ops.config import AppConfig
from sbom_ops.domain.models import (
    Enrichment,
    Finding,
    PrioritizedFinding,
    Severity,
)
from sbom_ops.domain.priority import prioritize_finding


class DependencyTrackClientProtocol(Protocol):
    def list_projects(self) -> list[DependencyTrackProject]: ...

    def get_project_findings(
        self, project_uuid: str
    ) -> list[DependencyTrackFinding]: ...


class KevClientProtocol(Protocol):
    def get_known_exploited_vulnerabilities(self) -> set[str]: ...


class GitHubIssuesClientProtocol(Protocol):
    def find_open_issue_by_finding_key(self, finding_key: str) -> dict | None: ...

    def list_open_issues(self, label: str) -> list[dict]: ...

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict: ...

    def update_issue(self, issue_number: int, title: str, body: str) -> dict: ...

    def close_issue(self, issue_number: int) -> dict: ...


@dataclass(frozen=True)
class RunResult:
    projects_processed: int
    findings_processed: int
    issues_created: int
    issues_updated: int
    issues_closed: int
    dry_run: bool


_FINDING_KEY_PATTERN = re.compile(r"<!-- sbom-ops:finding-key=(.*?) -->")


class Orchestrator:
    def __init__(
        self,
        config: AppConfig,
        dependency_track: DependencyTrackClientProtocol | None = None,
        kev: KevClientProtocol | None = None,
        github: GitHubIssuesClientProtocol | None = None,
    ) -> None:
        self._config = config
        self._dependency_track = dependency_track or DependencyTrackClient(
            config.dependency_track.base_url,
            config.dependency_track.api_key,
        )
        self._kev = kev or KevClient(config.intelligence.kev_feed_url)
        self._github = github or GitHubIssuesClient(
            config.github.token,
            config.github.owner,
            config.github.repo,
        )

    def run(self) -> RunResult:
        projects = self._dependency_track.list_projects()
        project_filter = set(self._config.runtime.project_uuids)
        if project_filter:
            projects = [
                project for project in projects if project.uuid in project_filter
            ]

        kev_ids = self._kev.get_known_exploited_vulnerabilities()
        current_keys: set[str] = set()
        managed_project_uuids = {project.uuid for project in projects}
        created = updated = closed = findings_processed = 0

        for project in projects:
            raw_findings = self._dependency_track.get_project_findings(project.uuid)
            findings_processed += len(raw_findings)
            prioritized: list[PrioritizedFinding] = []
            for raw in raw_findings:
                prioritized_finding = self._prioritize(raw, kev_ids)
                current_keys.add(prioritized_finding.finding.finding_key())
                prioritized.append(prioritized_finding)

            for item in prioritized:
                if self._excluded_by_analysis(item):
                    continue
                if item.priority.value not in self._config.priority.create_issues_for:
                    continue
                title, body = self._issue_content(item)
                key = item.finding.finding_key()
                existing = self._github.find_open_issue_by_finding_key(key)
                if existing is None:
                    if not self._config.runtime.dry_run:
                        self._github.create_issue(
                            title,
                            body,
                            [
                                self._config.github.issue_label_prefix,
                                f"{self._config.github.issue_label_prefix}-{item.priority.value}",
                            ],
                        )
                    created += 1
                else:
                    number = existing.get("number")
                    if number is None:
                        continue
                    if not self._config.runtime.dry_run:
                        self._github.update_issue(int(number), title, body)
                    updated += 1

        for issue in self._github.list_open_issues(
            self._config.github.issue_label_prefix
        ):
            key = self._finding_key_from_issue(issue)
            if key is None or key in current_keys:
                continue
            if key.split(":", 1)[0] not in managed_project_uuids:
                continue
            number = issue.get("number")
            if number is None:
                continue
            if not self._config.runtime.dry_run:
                self._github.close_issue(int(number))
            closed += 1

        return RunResult(
            projects_processed=len(projects),
            findings_processed=findings_processed,
            issues_created=created,
            issues_updated=updated,
            issues_closed=closed,
            dry_run=self._config.runtime.dry_run,
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
        )
        enrichment = Enrichment(
            in_kev=raw.vulnerability_id in kev_ids,
            epss_score=raw.epss_score,
            has_known_active_exploitation=raw.vulnerability_id in kev_ids,
            analysis_state=raw.analysis_state,
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
    def _excluded_by_analysis(item: PrioritizedFinding) -> bool:
        return item.enrichment.is_suppressed or item.enrichment.analysis_state in {
            "NOT_AFFECTED",
            "FALSE_POSITIVE",
        }

    @staticmethod
    def _finding_key_from_issue(issue: dict) -> str | None:
        body = issue.get("body") or ""
        match = _FINDING_KEY_PATTERN.search(body)
        return match.group(1) if match else None

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

## Vulnerability

- Project: `{finding.project_name}` (`{finding.project_uuid}`)
- Component: `{finding.component_name}` `{finding.component_version or 'unknown'}`
- Vulnerability: `{finding.vulnerability_id}`
- Vulnerability source: `{finding.vulnerability_source or 'unknown'}`
- Priority: `{item.priority.value}`
- CVSS: `{finding.cvss_score if finding.cvss_score is not None else 'unknown'}`
- EPSS: `{enrichment.epss_score if enrichment.epss_score is not None else 'unknown'}`
- KEV: `{'yes' if enrichment.in_kev else 'no'}`
- Dependency-Track analysis: `{enrichment.analysis_state or 'NOT_SET'}`
- Analysis detail: {enrichment.analysis_detail or 'None'}

## Rationale

{rationale}

## Description

{finding.description or 'No description provided by Dependency-Track.'}

This issue is synchronized from Dependency-Track by sbom-ops.
"""
        return title, body
