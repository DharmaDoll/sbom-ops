"""Offline operator review example, with simulated reviewed registry data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from asset_scenario import FictionalDependencyTrack, FictionalKev

from sbom_ops.cli import print_review_queue
from sbom_ops.config import (
    AppConfig,
    DependencyTrackConfig,
    GitHubConfig,
    IntelligenceConfig,
    PriorityConfig,
    RuntimeConfig,
)
from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegisteredService,
    ReportedDeployment,
    ReviewedProjectLink,
)
from sbom_ops.domain.assets import BusinessCriticality, DeploymentStatus
from sbom_ops.services.orchestrator import Orchestrator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", choices=("review", "json"), default="review")
    args = parser.parse_args()
    path = Path(__file__).with_name("review-scenario.example.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    snapshot = AssetRegistrySnapshot(
        services=tuple(
            RegisteredService(
                **{**item, "criticality": BusinessCriticality(item["criticality"])}
            )
            for item in data["services"]
        ),
        links=tuple(ReviewedProjectLink(**item) for item in data["links"]),
        deployment_reports=tuple(
            ReportedDeployment(
                **{
                    **item,
                    "deployment_status": DeploymentStatus(item["deployment_status"]),
                    "exposure_status": ExposureStatus(item["exposure_status"]),
                }
            )
            for item in data["deployment_reports"]
        ),
    )
    config = AppConfig(
        dependency_track=DependencyTrackConfig("https://example.invalid", "fictional"),
        github=GitHubConfig("fictional", "example", "example", enabled=False),
        intelligence=IntelligenceConfig(),
        priority=PriorityConfig(),
        runtime=RuntimeConfig(dry_run=True),
    )
    dependency_track = FictionalDependencyTrack(path)
    baseline = Orchestrator(config, dependency_track, FictionalKev()).run()
    result = Orchestrator(
        config, dependency_track, FictionalKev(), asset_registry=snapshot
    ).run()
    assert result.assessments == baseline.assessments
    assert result.actions == baseline.actions == ()
    if args.output == "json":
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
    else:
        print("架空シナリオ: 外部通信・DB保存なし。紐付け承認済みの入力を模擬。")
        print_review_queue(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
