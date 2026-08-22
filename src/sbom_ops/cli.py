from __future__ import annotations

import argparse
import json
import os
import sys
from uuid import uuid4

from sbom_ops.clients.dependency_track import (
    DependencyTrackApiError,
    DependencyTrackClient,
)
from sbom_ops.clients.github import GitHubApiError
from sbom_ops.clients.kev import KevApiError
from sbom_ops.config import AppConfig, load_config
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


def run_sync(config: AppConfig, output_format: str = "text") -> int:
    orchestrator = Orchestrator(config=config)
    result = orchestrator.run()
    if config.runtime.sync_log_file:
        append_sync_event(config.runtime.sync_log_file, result.as_dict())
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
        f"dry_run={result.dry_run}"
    )
    for assessment in result.assessments:
        rationale = ", ".join(assessment.rationale)
        print(
            f"finding {assessment.finding_key} priority={assessment.priority.value} "
            f"analysis={assessment.analysis_state.value} rationale={rationale}"
        )
    for action in result.actions:
        prefix = "DRY-RUN " if config.runtime.dry_run else ""
        print(f"{prefix}{action}")
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
            return run_sync(config, args.output)
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
            append_sync_event(
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
