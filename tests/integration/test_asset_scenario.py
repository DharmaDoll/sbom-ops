from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_asset_update_example_exercises_preview_apply_and_history() -> None:
    scenario = Path(__file__).parents[2] / "examples" / "asset_update_scenario.py"
    completed = subprocess.run(
        [sys.executable, str(scenario)], check=True, capture_output=True, text=True
    )
    for expected in (
        '"status": "preview"',
        '"status": "applied"',
        '"change_id": 1',
        '"owner": "team-checkout"',
        '"owner": "team-payments"',
        "一時DBは削除済み",
        "Projectの資産対応=revoked 担当=不明",
        "Projectの資産対応=retired 担当=不明",
        '"action": "retire_service"',
        '"action": "retire_deployable"',
    ):
        assert expected in completed.stdout
    assert completed.stderr == ""


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


def test_review_scenario_joins_fictional_registry_without_external_services() -> None:
    scenario = Path(__file__).parents[2] / "examples" / "review_scenario.py"
    completed = subprocess.run(
        [sys.executable, str(scenario), "--output", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    rows = result["review_queue"]
    assert len(rows) == result["findings_processed"] == 4
    assert [row["priority"] for row in rows] == ["P1", "P2", "P2", "P2"]
    assert rows[0]["vulnerability_id"].startswith("GHSA-")
    assert rows[0]["is_suppressed"] is True
    assert rows[0]["environments"][0]["status"] == "expired"
    assert rows[1]["asset"]["owner"] == "team-checkout"
    assert {env["status"] for env in rows[1]["environments"]} == {
        "reported",
        "conflict",
    }
    assert rows[2]["asset_status"] == "unlinked"
    assert rows[2]["asset"] is None
    groups = result["remediation_groups"]
    assert len(groups) == 3
    checkout = next(group for group in groups if group["service_id"] == "checkout-api")
    assert checkout["finding_count"] == 2
    assert len(checkout["project_uuids"]) == 2
    assert {key for group in groups for key in group["finding_keys"]} == {
        row["finding_key"] for row in rows
    }
    assert result["issues_created"] == result["issues_updated"] == 0
    assert result["actions"] == []
    assert completed.stderr == ""
    text_output = subprocess.run(
        [sys.executable, str(scenario)], check=True, capture_output=True, text=True
    ).stdout
    for expected in (
        "確認用一覧: 4件",
        "修正作業の候補: 3組",
        "Finding数=2",
        "同期先・DT分析によりIssue操作は異なります",
        "担当=team-checkout",
        "期限切れ",
        "申告が矛盾",
        "未紐付け",
    ):
        assert expected in text_output
