"""Five fictional notification views, without credentials, network, or persistence."""

import argparse
import json
from dataclasses import replace
from datetime import UTC, datetime

from sbom_ops.domain.asset_registry import (
    RegistryDeploymentObservation,
    RegistryDeploymentStatus,
    RegistryProjectObservation,
    RegistryProjectStatus,
    RegistrySnapshotStatus,
)
from sbom_ops.domain.models import AnalysisState, FindingAssessment, Priority, Severity
from sbom_ops.domain.slack import Delivery, SlackPolicy, selection
from sbom_ops.services.orchestrator import RunResult
from sbom_ops.services.slack_input import notifications


def sample(case: str) -> dict[str, object]:
    urgent = case == "urgent"
    item = FindingAssessment(
        "fictional-build-a",
        "fictional-finding-a",
        "CVE-2099-1000",
        "NVD",
        Severity.CRITICAL,
        9.5,
        None if case == "missing" else 0.8,
        Priority.P0 if urgent else Priority.P1,
        AnalysisState.NOT_SET,
        False,
        ("KEV (架空)",) if urgent else ("Critical severity (架空)",),
        in_kev=urgent,
        component_purl="pkg:npm/fictional-library@1.0",
        component_name="fictional-library",
        component_version="1.0",
    )
    asset = RegistryProjectObservation(
        "fictional-build-a",
        "fictional-shop/web",
        "v1",
        RegistryProjectStatus.MATCHED,
        service_id="fictional-shop",
        deployable_id="web",
        owner="team-fictional",
    )
    unassigned = case == "unassigned"
    result = RunResult(
        run_id="fictional-slack-example",
        duration_seconds=0,
        kev_used_stale_cache=False,
        projects_processed=2,
        findings_processed=2,
        issues_created=0,
        issues_updated=0,
        issues_closed=0,
        dry_run=True,
        assessments=(
            item,
            replace(
                item,
                project_uuid="fictional-build-b",
                finding_key="fictional-finding-b",
            ),
        ),
        registry_snapshot_status=RegistrySnapshotStatus.LOADED,
        registry_projects=(
            ()
            if unassigned
            else (
                asset,
                replace(asset, project_uuid="fictional-build-b", dt_version="v2"),
            )
        ),
        registry_deployments=(
            ()
            if unassigned
            else (
                RegistryDeploymentObservation(
                    "fictional-build-a",
                    "production",
                    "v1",
                    RegistryDeploymentStatus.EXPIRED,
                ),
            )
        ),
    )
    return result.as_dict()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--case",
        choices=("normal", "urgent", "unassigned", "missing", "reminder"),
        default="normal",
    )
    parser.add_argument(
        "--output", choices=("text", "json", "sync-json"), default="text"
    )
    args = parser.parse_args()
    document = sample(args.case)
    if args.output == "sync-json":
        print(json.dumps(document, ensure_ascii=False))
        return 0
    now = datetime.now(UTC)
    policy = SlackPolicy(min_interval_seconds=0, reminder_seconds=3600)
    result = []
    for item in notifications(document, policy, observed_at=now.isoformat(), now=now):
        history = ()
        if args.case == "reminder":
            history = (
                Delivery(
                    "fictional-intent",
                    policy.channel,
                    item.key,
                    item.fingerprint,
                    "new",
                    "fictional-earlier-run",
                    "confirmed",
                    now.timestamp() - 7200,
                    now.timestamp() - 7200,
                    1,
                    0,
                    "100.001",
                    None,
                    "fictional-body-hash",
                ),
            )
        reason = selection(item, history, policy, now.timestamp())
        result.append(
            {
                "reason": reason,
                "channel": policy.channel,
                "thread_ts": "100.001" if history else None,
                "text": f"通知種別: {reason}\n{item.text}",
            }
        )
    if args.output == "json":
        print(
            json.dumps(
                {"mode": "preview", "fictional": True, "notifications": result},
                ensure_ascii=False,
            )
        )
    else:
        for row in result:
            print(row["text"] + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
