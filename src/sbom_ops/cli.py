from __future__ import annotations

import argparse
import json
import os
import sqlite3
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
from sbom_ops.domain.advisory import AdvisorySnapshotStatus, ExposureStatus
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    ProjectLinkAuditStatus,
    RegisteredDeployable,
    RegisteredService,
    ReportedDeployment,
)
from sbom_ops.domain.assets import (
    AssetInventoryStatus,
    BusinessCriticality,
    DeploymentStatus,
)
from sbom_ops.services.advisory_snapshot import load_advisory_snapshot
from sbom_ops.services.asset_inventory import load_asset_inventory
from sbom_ops.services.asset_registry import (
    approve_project_link,
    audit_reviewed_project_links,
    discover_project_candidates,
)
from sbom_ops.services.orchestrator import Orchestrator
from sbom_ops.services.sync_log import append_sync_event
from sbom_ops.storage.asset_registry import AssetRegistry


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
        "--asset-db",
        help="show reviewed SQLite Project links without changing priority or Issues",
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

    assets_parser = subparsers.add_parser("assets")
    assets_parser.add_argument("--db", required=True, help="local SQLite asset DB")
    asset_commands = assets_parser.add_subparsers(dest="asset_command", required=True)
    service_parser = asset_commands.add_parser("register-service")
    service_parser.add_argument("--service", required=True)
    service_parser.add_argument("--owner", required=True)
    service_parser.add_argument(
        "--criticality",
        choices=tuple(item.value for item in BusinessCriticality),
        required=True,
    )
    service_parser.add_argument("--reason", required=True)
    deployable_parser = asset_commands.add_parser("register-deployable")
    deployable_parser.add_argument("--service", required=True)
    deployable_parser.add_argument("--deployable", required=True)
    deployment_parser = asset_commands.add_parser("report-deployment")
    deployment_parser.add_argument("--service", required=True)
    deployment_parser.add_argument("--deployable", required=True)
    deployment_parser.add_argument("--environment", required=True)
    deployment_parser.add_argument("--artifact", required=True)
    deployment_parser.add_argument(
        "--status",
        choices=tuple(item.value for item in DeploymentStatus),
        required=True,
    )
    deployment_parser.add_argument(
        "--exposure",
        choices=tuple(item.value for item in ExposureStatus),
        required=True,
    )
    deployment_parser.add_argument("--reviewer", required=True)
    deployment_parser.add_argument("--evidence", required=True)
    deployment_parser.add_argument("--observed-at", required=True)
    deployment_parser.add_argument("--expires-at", required=True)
    asset_commands.add_parser("list")
    asset_commands.add_parser("check")
    backup_parser = asset_commands.add_parser("backup")
    backup_parser.add_argument("--output", required=True)
    migrate_parser = asset_commands.add_parser("migrate")
    migrate_parser.add_argument("--backup", required=True)
    asset_commands.add_parser("candidates")
    asset_commands.add_parser("audit-links")
    approve_parser = asset_commands.add_parser("approve")
    approve_parser.add_argument("--service", required=True)
    approve_parser.add_argument("--deployable", required=True)
    approve_parser.add_argument("--project", required=True)
    approve_parser.add_argument("--reviewer", required=True)

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
    asset_db_path: str | None = None,
) -> int:
    asset_registry = None
    if asset_db_path:
        with AssetRegistry(asset_db_path, read_only=True) as registry:
            registry.check_integrity()
            asset_registry = AssetRegistrySnapshot(
                services=registry.list_services(),
                links=registry.list_links(),
                deployment_reports=registry.list_deployment_reports(),
            )
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
    if asset_registry is not None:
        orchestrator_kwargs["asset_registry"] = asset_registry
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
        f"registry_snapshot_status={result.registry_snapshot_status.value} "
        f"analysis_snapshot_status={result.analysis_snapshot_status.value} "
        f"asset_inventory_status={result.asset_inventory_status.value} "
        f"advisory_snapshot_status={result.advisory_snapshot_status.value} "
        f"dry_run={result.dry_run}"
    )
    for item in result.registry_projects:
        service = (
            f"{item.service_id}/{item.deployable_id}"
            if item.service_id and item.deployable_id
            else "unavailable"
        )
        print(
            f"registry-project project={item.project_uuid} "
            f"status={item.status.value} "
            f"dt_name={item.dt_name} "
            f"dt_version={item.dt_version or 'unknown'} "
            f"reviewed_name={item.reviewed_name or 'none'} "
            f"reviewed_version={item.reviewed_version or 'none'} "
            f"service={service} owner={item.owner or 'unknown'} "
            f"criticality={item.criticality.value if item.criticality else 'unknown'} "
            f"reviewer={item.reviewer or 'none'}"
        )
    for item in result.registry_deployments:
        deployment = (
            item.deployment_status.value if item.deployment_status else "unknown"
        )
        exposure = item.exposure_status.value if item.exposure_status else "unknown"
        print(
            f"registry-deployment project={item.project_uuid} "
            f"environment={item.environment or 'unreported'} "
            f"artifact={item.artifact_id or 'unknown'} "
            f"status={item.status.value} "
            f"deployment={deployment} exposure={exposure} "
            f"report_ids={','.join(str(value) for value in item.report_ids) or 'none'} "
            f"other_artifacts={','.join(item.other_artifact_ids) or 'none'}"
        )
    for assessment in result.review_assessments():
        rationale = ", ".join(assessment.rationale)
        poc_sources = (
            ",".join(
                f"{item.vulnerability_id}/{item.source}:"
                f"{item.record_count if item.record_count is not None else 'unknown'}"
                for item in assessment.poc_reports.sources
            )
            or "none"
        )
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
            f"vulnerability={assessment.vulnerability_id} "
            f"source={assessment.vulnerability_source or 'UNKNOWN'} "
            f"dt_aliases={','.join(assessment.vulnerability_aliases) or 'none'} "
            f"severity={assessment.severity.value} cvss={cvss} "
            f"cvss_version={assessment.cvss_version or 'unavailable'} epss={epss} "
            f"in_kev={str(assessment.in_kev).lower()} "
            f"poc_reported={assessment.poc_reports.status.value} "
            f"poc_sources={poc_sources} "
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


def _asset_dt_client() -> DependencyTrackClient:
    base_url = os.getenv("SBOM_OPS_DT_BASE_URL")
    api_key = os.getenv("SBOM_OPS_DT_API_KEY")
    if not base_url or not api_key:
        raise ValueError(
            "asset discovery requires SBOM_OPS_DT_BASE_URL and SBOM_OPS_DT_API_KEY"
        )
    return DependencyTrackClient(base_url, api_key)


def run_assets(args: argparse.Namespace) -> int:
    with AssetRegistry(
        args.db, create_if_missing=args.asset_command == "register-service"
    ) as registry:
        if args.asset_command == "register-service":
            service = RegisteredService(
                service_id=args.service,
                owner=args.owner,
                criticality=BusinessCriticality(args.criticality),
                impact_reason=args.reason,
            )
            registry.register_service(service)
            print(f"registered service {service.service_id}")
        elif args.asset_command == "register-deployable":
            deployable = RegisteredDeployable(args.service, args.deployable)
            registry.register_deployable(deployable)
            print(f"registered deployable {deployable.project_name}")
        elif args.asset_command == "report-deployment":
            report = registry.register_deployment(
                ReportedDeployment(
                    service_id=args.service,
                    deployable_id=args.deployable,
                    environment=args.environment,
                    artifact_id=args.artifact,
                    deployment_status=DeploymentStatus(args.status),
                    exposure_status=ExposureStatus(args.exposure),
                    reviewer=args.reviewer,
                    evidence=args.evidence,
                    observed_at=args.observed_at,
                    expires_at=args.expires_at,
                )
            )
            print(f"recorded human deployment report={report.report_id}")
        elif args.asset_command == "list":
            for service in registry.list_services():
                print(
                    f"service={service.service_id} owner={service.owner} "
                    f"criticality={service.criticality.value} "
                    f"reason={service.impact_reason}"
                )
            for deployable in registry.list_deployables():
                print(f"deployable={deployable.project_name}")
            for link in registry.list_links():
                print(
                    f"link={link.project_uuid} name={link.project_name} "
                    f"version={link.project_version} reviewer={link.reviewer} "
                    f"reviewed_at={link.reviewed_at}"
                )
            for report in registry.list_deployment_reports():
                if report.is_future():
                    freshness = "future"
                elif report.is_current():
                    freshness = "current"
                else:
                    freshness = "expired"
                print(
                    f"deployment_report={report.report_id} "
                    f"service={report.service_id} deployable={report.deployable_id} "
                    f"environment={report.environment} artifact={report.artifact_id} "
                    f"status={report.deployment_status.value} "
                    f"exposure={report.exposure_status.value} "
                    f"freshness={freshness} "
                    f"reviewer={report.reviewer} evidence={report.evidence} "
                    f"observed_at={report.observed_at} expires_at={report.expires_at}"
                )
        elif args.asset_command == "check":
            registry.check_integrity()
            print(f"asset DB integrity OK: {args.db}")
        elif args.asset_command == "backup":
            output = registry.backup_to(args.output)
            print(f"asset DB backup created: {output}")
        elif args.asset_command == "migrate":
            if registry.schema_version == 2:
                print("asset DB already uses schema v2")
            else:
                output = registry.backup_to(args.backup)
                registry.migrate()
                print(f"asset DB upgraded to schema v2; v1 backup: {output}")
        elif args.asset_command == "candidates":
            for item in discover_project_candidates(
                registry, _asset_dt_client().list_projects()
            ):
                print(
                    f"status={item.status} project={item.project_uuid} "
                    f"name={item.project_name} version={item.project_version} "
                    f"service={item.service_id} deployable={item.deployable_id}"
                )
        elif args.asset_command == "audit-links":
            audits = audit_reviewed_project_links(
                registry, _asset_dt_client().list_projects()
            )
            if not audits:
                print("no reviewed Project links")
                return 1
            for item in audits:
                dt_version = (
                    "not_visible"
                    if item.current_name is None
                    else item.current_version or "missing_version"
                )
                print(
                    f"status={item.status.value} project={item.link.project_uuid} "
                    f"reviewed_name={item.link.project_name} "
                    f"reviewed_version={item.link.project_version} "
                    f"dt_name={item.current_name or 'not_visible'} "
                    f"dt_version={dt_version} "
                    f"reviewer={item.link.reviewer} "
                    f"reviewed_at={item.link.reviewed_at}"
                )
            if any(
                item.status is not ProjectLinkAuditStatus.MATCHED for item in audits
            ):
                return 1
        elif args.asset_command == "approve":
            link = approve_project_link(
                registry,
                _asset_dt_client().list_projects(),
                service_id=args.service,
                deployable_id=args.deployable,
                project_uuid=args.project,
                reviewer=args.reviewer,
            )
            print(
                f"reviewed project={link.project_uuid} "
                f"name={link.project_name} version={link.project_version}"
            )
        else:
            raise ValueError(f"unsupported assets command: {args.asset_command}")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    active_config: AppConfig | None = None
    try:
        if args.command == "upload":
            return run_upload(args)
        if args.command == "assets":
            return run_assets(args)
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
                asset_db_path=args.asset_db,
            )
        parser.error(f"unsupported command: {args.command}")
    except (
        DependencyTrackApiError,
        GitHubApiError,
        KevApiError,
        OSError,
        sqlite3.Error,
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
