from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import replace
from uuid import uuid4

from sbom_ops.clients.dependency_track import (
    DependencyTrackApiError,
    DependencyTrackClient,
)
from sbom_ops.clients.github import GitHubApiError
from sbom_ops.clients.kev import KevApiError
from sbom_ops.config import AppConfig, load_config
from sbom_ops.domain.advisory import AdvisorySnapshotStatus
from sbom_ops.domain.assets import AssetInventoryStatus
from sbom_ops.services.advisory_snapshot import load_advisory_snapshot
from sbom_ops.services.asset_inventory import load_asset_inventory
from sbom_ops.services.orchestrator import Orchestrator
from sbom_ops.services.sync_log import append_sync_event


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sbom-ops")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sync_parser = subparsers.add_parser("sync")
    sync_parser.add_argument("--config")
    sync_parser.add_argument("--project", dest="project_uuid")
    sync_parser.add_argument("--dry-run", action="store_true")
    sync_parser.add_argument("--log-level")
    sync_parser.add_argument("--wait-for-analysis", action="store_true")
    sync_parser.add_argument(
        "--refresh-kev",
        action="store_true",
        help="contact the CISA KEV feed even when the local cache is fresh",
    )
    sync_parser.add_argument(
        "--advisory-snapshot",
        help="attach a precomputed advisory evidence JSON snapshot (no fetching)",
    )
    sync_parser.add_argument(
        "--asset-inventory",
        help="attach a reviewed Project/service/environment inventory JSON file",
    )
    sync_parser.add_argument(
        "--no-github", action="store_true", help="skip all GitHub Issue operations"
    )
    sync_parser.add_argument(
        "--output",
        choices=("text", "json"),
        default="text",
        help="select human-readable or machine-readable output",
    )
    sync_parser.add_argument("--sync-log-file")

    upload_parser = subparsers.add_parser("upload")
    upload_parser.add_argument("bom_path")
    upload_parser.add_argument("--project", dest="project_uuid")
    upload_parser.add_argument("--no-wait", action="store_true")

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--config")
    plan_parser.add_argument("--project", dest="project_uuid")
    plan_parser.add_argument("--dry-run", action="store_true")
    plan_parser.add_argument("--log-level")
    plan_parser.add_argument(
        "--no-github",
        action="store_true",
        help="show the plan without GitHub Issue operations",
    )
    plan_parser.add_argument("--sync-log-file")
    return parser


def run_plan(config: AppConfig) -> int:
    print("sbom-ops runtime plan")
    print(f"Dependency-Track: {config.dependency_track.base_url}")
    print(f"GitHub repository: {config.github.owner}/{config.github.repo}")
    print(f"GitHub Issue sync: {config.github.enabled}")
    print(
        f"EPSS source: Dependency-Track (fallback: {config.intelligence.epss_api_url})"
    )
    print(f"KEV feed: {config.intelligence.kev_feed_url}")
    print(f"P1 EPSS threshold: {config.priority.p1_epss_threshold}")
    print(f"P2 CVSS threshold: {config.priority.p2_cvss_threshold}")
    print(f"Create issues for: {', '.join(config.priority.create_issues_for)}")
    print(f"Projects: {', '.join(config.runtime.project_uuids) or 'all accessible'}")
    print(f"Project routes: {len(config.routing.routes)}")
    print(f"Dry run: {config.runtime.dry_run}")
    print(f"Wait for analysis: {config.runtime.wait_for_analysis}")
    print(f"Close missing findings: {config.workflow.close_missing_findings}")
    print(
        f"Missing confirmations required: {config.workflow.missing_confirmation_runs}"
    )
    return 0


def _append_sync_event_with_warning(path: str, payload: dict[str, object]) -> None:
    if not append_sync_event(path, payload):
        print(
            "warning: sync log could not be written; primary sync result is unchanged",
            file=sys.stderr,
        )


def run_sync(
    config: AppConfig,
    output_format: str = "text",
    *,
    force_refresh_kev: bool = False,
    advisory_snapshot_path: str | None = None,
    asset_inventory_path: str | None = None,
) -> int:
    snapshot = None
    snapshot_error = None
    if advisory_snapshot_path:
        try:
            snapshot = load_advisory_snapshot(advisory_snapshot_path)
        except (OSError, ValueError) as exc:
            snapshot_error = str(exc)
            print(
                f"warning: advisory snapshot ignored: {snapshot_error}",
                file=sys.stderr,
            )
    asset_inventory = None
    asset_inventory_error = None
    if asset_inventory_path:
        try:
            asset_inventory = load_asset_inventory(asset_inventory_path)
        except (OSError, ValueError) as exc:
            asset_inventory_error = str(exc)
            print(
                f"warning: asset inventory ignored: {asset_inventory_error}",
                file=sys.stderr,
            )
    orchestrator_kwargs = {"force_refresh_kev": force_refresh_kev}
    if snapshot is not None:
        orchestrator_kwargs["advisory_snapshot"] = snapshot
    if asset_inventory is not None:
        orchestrator_kwargs["asset_inventory"] = asset_inventory
    orchestrator = Orchestrator(config=config, **orchestrator_kwargs)
    result = orchestrator.run()
    if snapshot_error is not None:
        result = replace(
            result,
            advisory_snapshot_status=AdvisorySnapshotStatus.INVALID,
            advisory_snapshot_error=snapshot_error,
        )
    if asset_inventory_error is not None:
        result = replace(
            result,
            asset_inventory_status=AssetInventoryStatus.INVALID,
            asset_inventory_error=asset_inventory_error,
        )
    if config.runtime.sync_log_file:
        _append_sync_event_with_warning(config.runtime.sync_log_file, result.as_dict())
    if output_format == "json":
        print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
        return 0
    print(
        "sync result: "
        f"run_id={result.run_id} "
        f"duration_seconds={result.duration_seconds:.6f} "
        f"projects={result.projects_processed} "
        f"findings={result.findings_processed} "
        f"created={result.issues_created} "
        f"updated={result.issues_updated} "
        f"closed={result.issues_closed} "
        f"kev_used_stale_cache={str(result.kev_used_stale_cache).lower()} "
        f"analysis_snapshot_status={result.analysis_snapshot_status.value} "
        f"asset_inventory_status={result.asset_inventory_status.value} "
        f"advisory_snapshot_status={result.advisory_snapshot_status.value} "
        f"dry_run={result.dry_run}"
    )
    for assessment in result.assessments:
        rationale = ", ".join(assessment.rationale)
        advisory = (
            ",".join(
                f"{item.source}/{item.signal}:{item.outcome.value}"
                for item in assessment.advisory_observations
            )
            or "none"
        )
        component = assessment.component_name or "unknown"
        if assessment.component_version:
            component = f"{component}@{assessment.component_version}"
        cvss = (
            f"{assessment.cvss_score:.1f}"
            if assessment.cvss_score is not None
            else "unavailable"
        )
        epss = (
            f"{assessment.epss_score:.4f}"
            if assessment.epss_score is not None
            else "unavailable"
        )
        print(
            f"finding {assessment.finding_key} priority={assessment.priority.value} "
            f"component={component} "
            f"purl={assessment.component_purl or 'unavailable'} "
            f"source={assessment.vulnerability_source or 'UNKNOWN'} "
            f"dt_aliases={','.join(assessment.vulnerability_aliases) or 'none'} "
            f"severity={assessment.severity.value} cvss={cvss} "
            f"cvss_version={assessment.cvss_version or 'unavailable'} epss={epss} "
            f"in_kev={str(assessment.in_kev).lower()} "
            f"advisory={advisory} "
            f"analysis={assessment.analysis_state.value} "
            f"suppressed={str(assessment.is_suppressed).lower()} "
            f"rationale={rationale}"
        )
    for action in result.actions:
        prefix = "DRY-RUN " if config.runtime.dry_run else ""
        print(f"{prefix}{action}")
    for exposure in result.project_exposure_observations:
        print(
            "project-exposure "
            f"project={exposure.project_uuid} environment={exposure.environment} "
            f"status={exposure.effective_status().value} source={exposure.source} "
            f"expires_at={exposure.expires_at}"
        )
    for deployment in result.asset_deployments:
        item = deployment.as_dict()
        print(
            "asset-deployment "
            f"project={deployment.project_uuid} service={deployment.service_id} "
            f"environment={deployment.environment} "
            f"deployment={item['effective_deployment_status']} "
            f"version={item['effective_deployed_version'] or 'unknown'} "
            f"exposure={item['effective_exposure_status']} "
            f"criticality={item['effective_criticality']} "
            f"owner={item['effective_owner'] or 'unknown'} "
            f"freshness={item['freshness']}"
        )
    for project_uuid in result.asset_unmapped_project_uuids:
        print(f"asset-unmapped project={project_uuid}")
    for project_uuid in result.asset_unmatched_project_uuids:
        print(f"asset-unmatched project={project_uuid}")
    return 0


def run_upload(args: argparse.Namespace) -> int:
    base_url = os.getenv("SBOM_OPS_DT_BASE_URL")
    api_key = os.getenv("SBOM_OPS_SBOM_UPLOAD_API_KEY")
    project_uuid = args.project_uuid or os.getenv("SBOM_OPS_DT_PROJECT_UUID")
    if not base_url or not api_key or not project_uuid:
        raise ValueError(
            "upload requires SBOM_OPS_DT_BASE_URL, "
            "SBOM_OPS_SBOM_UPLOAD_API_KEY, and a project UUID"
        )
    client = DependencyTrackClient(
        base_url,
        api_key,
        timeout=float(os.getenv("SBOM_OPS_DT_TIMEOUT_SECONDS", "30")),
        max_retries=int(os.getenv("SBOM_OPS_DT_MAX_RETRIES", "3")),
        retry_backoff_seconds=float(
            os.getenv("SBOM_OPS_DT_RETRY_BACKOFF_SECONDS", "1")
        ),
    )
    upload = client.upload_bom(project_uuid, args.bom_path)
    if not args.no_wait:
        client.wait_for_bom_processing(
            upload.token,
            timeout=float(
                os.getenv("SBOM_OPS_DT_ANALYSIS_WAIT_TIMEOUT_SECONDS", "120")
            ),
            poll_interval=float(
                os.getenv("SBOM_OPS_DT_ANALYSIS_POLL_INTERVAL_SECONDS", "5")
            ),
        )
    if args.no_wait:
        print("SBOM upload accepted; Dependency-Track processing is still asynchronous")
    else:
        print("SBOM upload accepted and Dependency-Track processing completed")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    active_config: AppConfig | None = None
    try:
        if args.command == "upload":
            return run_upload(args)
        config = load_config(args)
        active_config = config
        if args.command == "plan":
            return run_plan(config)
        if args.command == "sync":
            return run_sync(
                config,
                args.output,
                force_refresh_kev=args.refresh_kev,
                advisory_snapshot_path=args.advisory_snapshot,
                asset_inventory_path=args.asset_inventory,
            )
        parser.error(f"unsupported command: {args.command}")
    except (
        DependencyTrackApiError,
        GitHubApiError,
        KevApiError,
        OSError,
        ValueError,
    ) as exc:
        if (
            args.command == "sync"
            and active_config is not None
            and active_config.runtime.sync_log_file
        ):
            _append_sync_event_with_warning(
                active_config.runtime.sync_log_file,
                {
                    "run_id": str(uuid4()),
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
