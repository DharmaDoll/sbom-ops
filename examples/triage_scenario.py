"""Offline, fixed-time exercise; the saved inputs are entirely fictional."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path

from sbom_ops.cli import print_triage_contexts
from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegisteredService,
    RegistryProjectObservation,
    RegistryProjectStatus,
    ReportedDeployment,
    ReviewedProjectLink,
)
from sbom_ops.domain.assets import BusinessCriticality, DeploymentStatus
from sbom_ops.domain.kev import KevSnapshot
from sbom_ops.domain.models import Finding, Severity
from sbom_ops.domain.triage_input import SelectedCisaSnapshot, TriageInput
from sbom_ops.domain.vulnrichment_snapshot import VulnrichmentSnapshot
from sbom_ops.services.orchestrator import RunResult
from sbom_ops.services.triage_sync import SyncTriageContext, build_sync_triage


def scenario_contexts() -> tuple[tuple[str, str, SyncTriageContext], ...]:
    """Use product joins/evaluation; do not instantiate clients or access a DB."""
    data = json.loads(
        Path(__file__).with_name("triage-scenario.example.json").read_text()
    )
    now = datetime.fromisoformat(data["evaluated_at"])
    service, deployable, artifact = (
        data[key] for key in ("service_id", "deployable_id", "artifact_id")
    )
    project_id, project_name = "fictional-project", f"{service}/{deployable}"
    finding = Finding(
        project_id,
        project_name,
        "fictional-library",
        "1.0",
        data["cve"],
        Severity.HIGH,
        8.0,
        (),
        None,
    )
    project = RegistryProjectObservation(
        project_id,
        project_name,
        artifact,
        RegistryProjectStatus.MATCHED,
        service_id=service,
        deployable_id=deployable,
    )
    link = ReviewedProjectLink(
        project_id,
        project_name,
        artifact,
        service,
        deployable,
        "fictional-operator",
        "2026-10-20T00:00:00Z",
    )
    kev = KevSnapshot(
        "https://example.invalid/fictional-kev",
        frozenset({data["cve"]}),
        now - timedelta(hours=1),
        now + timedelta(hours=1),
        "fetched",
        "fictional-kev-v1",
        now - timedelta(days=1),
        True,
    )
    # Synthetic format identifiers are not a claim of actual CISA publication.
    cisa = SelectedCisaSnapshot(
        1,
        VulnrichmentSnapshot.capture(
            data["cisa_record"],
            cve=data["cve"],
            revision="a" * 40,
            retrieved_at=now,
            max_age=timedelta(days=3),
        ),
    )
    results = []
    for case in data["cases"]:
        services = (
            (
                RegisteredService(
                    service,
                    data["owner"],
                    BusinessCriticality.HIGH,
                    "架空の決済サービス",
                ),
            )
            if case["owner_registered"]
            else ()
        )
        report = ReportedDeployment(
            service,
            deployable,
            case["environment"],
            artifact,
            DeploymentStatus.DEPLOYED,
            ExposureStatus(case["exposure"]),
            "fictional-operator",
            "架空の申告",
            "2026-10-22T00:00:00Z",
            case["expires_at"],
            report_id=1,
        )
        context = build_sync_triage(
            finding,
            AssetRegistrySnapshot(services, (link,), (report,)),
            project,
            TriageInput(case["environment"], (cisa,)),
            kev=kev,
            now=now,
        )
        results.append((case["name"], case["label"], context))
    return tuple(results)


def run_scenario() -> dict[str, object]:
    return {
        "fictional": True,
        "scope": "offline_reference_exercise_not_live_sync",
        "cases": [
            {"name": name, "label": label, "context": context.as_dict()}
            for name, label, context in scenario_contexts()
        ],
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", choices=("review", "json"), default="review")
    args = parser.parse_args(argv)
    if args.output == "json":
        print(json.dumps(run_scenario(), ensure_ascii=False, indent=2))
        return
    print("架空のBOD参照演習（固定時刻・外部通信なし・DB書込なし）")
    print("実際のCISA発表や資産ではありません。優先度計算・実期限確定は行いません。")
    for name, label, context in scenario_contexts():
        print(f"\n--- {label} ({name}) ---")
        print_triage_contexts(
            RunResult(
                run_id="fictional-triage-exercise",
                duration_seconds=0,
                kev_used_stale_cache=False,
                projects_processed=1,
                findings_processed=1,
                issues_created=0,
                issues_updated=0,
                issues_closed=0,
                dry_run=True,
                triage_context_status="evaluated",
                triage_contexts=(context,),
            )
        )


if __name__ == "__main__":
    main()
