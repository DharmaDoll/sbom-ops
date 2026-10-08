from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_fictional_dt_sample_matches_asset_scenario() -> None:
    examples = Path(__file__).parents[2] / "examples"
    dt_sample = json.loads(
        (examples / "asset-scenario-dt.example.json").read_text(encoding="utf-8")
    )
    asset_sample = json.loads(
        (examples / "asset-inventory.example.json").read_text(encoding="utf-8")
    )

    assert dt_sample["schema_version"] == asset_sample["schema_version"] == 1
    assert len(dt_sample["projects"]) == 4
    assert {
        finding["vulnerability_id"]
        for project in dt_sample["projects"]
        for finding in project["findings"]
    } == {"CVE-2026-1000"}
    assert len({project["uuid"] for project in dt_sample["projects"]}) == 4
    assert (
        len(
            {entry["project_uuid"] for entry in asset_sample["deployments"]}
            & {project["uuid"] for project in dt_sample["projects"]}
        )
        == 3
    )


def test_fictional_operations_scenario_runs_without_external_services() -> None:
    scenario = Path(__file__).parents[2] / "examples" / "asset_scenario.py"

    completed = subprocess.run(
        [sys.executable, str(scenario)],
        check=True,
        capture_output=True,
        text=True,
    )

    lines = completed.stdout.splitlines()
    assert (
        "checkout-api/production: priority=P2 deployment=deployed "
        "version=checkout-api@2026.10.04 "
        "exposure=confirmed" in lines[1]
    )
    assert (
        "checkout-api/development: priority=P2 deployment=deployed "
        "version=checkout-api@2026.10.03-dev "
        "exposure=rejected" in lines[2]
    )
    assert (
        "internal-reporting/production: priority=P2 deployment=unknown "
        "version=unknown "
        "exposure=unknown" in lines[3]
    )
    assert "freshness=expired" in lines[3]
    assert lines[4] == "unmapped-service: priority=P2 asset-context=unknown"
    assert "Unmapped DT projects: 1" in lines
    assert "Inventory projects absent from DT: 1" in lines
    assert lines[-1] == "Priority and Issue actions: unchanged by asset context"
    assert completed.stderr == ""
