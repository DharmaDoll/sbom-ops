from __future__ import annotations

from dataclasses import dataclass

from sbom_ops.config import AppConfig


@dataclass(frozen=True)
class RunResult:
    projects_processed: int
    findings_processed: int
    issues_created: int
    issues_updated: int
    issues_closed: int
    dry_run: bool


class Orchestrator:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def run(self) -> RunResult:
        return RunResult(
            projects_processed=len(self._config.runtime.project_uuids),
            findings_processed=0,
            issues_created=0,
            issues_updated=0,
            issues_closed=0,
            dry_run=self._config.runtime.dry_run,
        )
