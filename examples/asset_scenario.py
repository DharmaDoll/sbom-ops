"""Run a small, entirely fictional operations scenario without API access."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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
from sbom_ops.services.asset_inventory import load_asset_inventory
from sbom_ops.services.orchestrator import Orchestrator


class FictionalDependencyTrack:
    def __init__(self, path: Path) -> None:
        payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            raise ValueError("unsupported fictional DT sample schema")
        self._projects: list[DependencyTrackProject] = []
        self._findings: dict[str, list[DependencyTrackFinding]] = {}
        for entry in payload["projects"]:
            project = DependencyTrackProject(entry["uuid"], entry["name"])
            self._projects.append(project)
            self._findings[project.uuid] = [
                DependencyTrackFinding(
                    project_uuid=project.uuid,
                    project_name=project.name,
                    component_name=finding["component_name"],
                    component_version=finding["component_version"],
                    vulnerability_id=finding["vulnerability_id"],
                    severity=finding["severity"],
                    cvss_score=finding["cvss_score"],
                    cwes=(),
                    description="Fictional finding for the offline scenario",
                    epss_score=finding["epss_score"],
                    analysis_state=finding["analysis_state"],
                    is_suppressed=finding["is_suppressed"],
                    analysis_detail=None,
                    finding_id=f"finding-{project.uuid}-{index}",
                    vulnerability_uuid="fictional-vulnerability",
                    vulnerability_source=finding["vulnerability_source"],
                    component_uuid=f"component-{project.uuid}",
                    component_purl=finding["component_purl"],
                )
                for index, finding in enumerate(entry["findings"], start=1)
            ]

    def list_projects(self) -> list[DependencyTrackProject]:
        return list(self._projects)

    def get_project_findings(self, project_uuid: str) -> list[DependencyTrackFinding]:
        return list(self._findings[project_uuid])

    def wait_for_analysis(
        self, project_uuid: str, *, timeout: float, poll_interval: float
    ) -> list[DependencyTrackFinding]:
        return self.get_project_findings(project_uuid)


class FictionalKev:
    def get_known_exploited_vulnerabilities(
        self, *, force_refresh: bool = False
    ) -> set[str]:
        return set()


def main() -> int:
    inventory = load_asset_inventory(
        Path(__file__).with_name("asset-inventory.example.json")
    )
    dependency_track = FictionalDependencyTrack(
        Path(__file__).with_name("asset-scenario-dt.example.json")
    )
    config = AppConfig(
        dependency_track=DependencyTrackConfig("https://example.invalid", "fictional"),
        github=GitHubConfig("fictional", "example", "example", enabled=False),
        intelligence=IntelligenceConfig(),
        priority=PriorityConfig(),
        runtime=RuntimeConfig(dry_run=True),
    )
    baseline = Orchestrator(
        config, dependency_track=dependency_track, kev=FictionalKev()
    ).run()
    result = Orchestrator(
        config,
        dependency_track=dependency_track,
        kev=FictionalKev(),
        asset_inventory=inventory,
    ).run()
    assert [item.priority for item in result.assessments] == [
        item.priority for item in baseline.assessments
    ]
    assert result.actions == baseline.actions == ()

    print("Fictional asset scenario: same CVE, different deployment context")
    for deployment in result.asset_deployments:
        fact = deployment.as_dict()
        assessment = next(
            item
            for item in result.assessments
            if item.project_uuid == deployment.project_uuid
        )
        print(
            f"{deployment.service_id}/{deployment.environment}: "
            f"priority={assessment.priority.value} "
            f"deployment={fact['effective_deployment_status']} "
            f"version={fact['effective_deployed_version'] or 'unknown'} "
            f"exposure={fact['effective_exposure_status']} "
            f"criticality={fact['effective_criticality']} "
            f"owner={fact['effective_owner'] or 'unknown'} "
            f"freshness={fact['freshness']}"
        )
    for project_uuid in result.asset_unmapped_project_uuids:
        assessment = next(
            item for item in result.assessments if item.project_uuid == project_uuid
        )
        print(
            f"unmapped-service: priority={assessment.priority.value} "
            "asset-context=unknown"
        )
    print(f"Unmapped DT projects: {len(result.asset_unmapped_project_uuids)}")
    print(
        "Inventory projects absent from DT: "
        f"{len(result.asset_unmatched_project_uuids)}"
    )
    print("Priority and Issue actions: unchanged by asset context")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
