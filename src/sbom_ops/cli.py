from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from contextlib import ExitStack
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from sbom_ops.clients.dependency_track import (
    DependencyTrackApiError,
    DependencyTrackClient,
)
from sbom_ops.clients.github import GitHubApiError
from sbom_ops.clients.kev import KevApiError
from sbom_ops.clients.osv import OsvClient
from sbom_ops.clients.vulnerability_lookup import (
    DEFAULT_BASE_URL,
    VulnerabilityLookupClient,
    validate_base_url,
)
from sbom_ops.config import AppConfig, load_config
from sbom_ops.domain.advisory import AdvisorySnapshotStatus, ExposureStatus
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    LifecycleAction,
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
from sbom_ops.domain.identifier_candidates import select_identifier_targets
from sbom_ops.domain.poc import PocRunBusy, select_poc_targets
from sbom_ops.domain.poc_retry import PocRetryPolicy
from sbom_ops.domain.workflow import decide_missing_finding
from sbom_ops.services.advisory_snapshot import load_advisory_snapshot
from sbom_ops.services.asset_import import load_asset_registration
from sbom_ops.services.asset_inventory import load_asset_inventory
from sbom_ops.services.asset_registry import (
    approve_project_link,
    audit_reviewed_project_links,
    discover_project_candidates,
)
from sbom_ops.services.asset_updates import plan_lifecycle_change, plan_service_update
from sbom_ops.services.identifier_candidates import collect_identifier_candidates
from sbom_ops.services.identifier_review import (
    list_identifier_reviews,
    review_identifier,
)
from sbom_ops.services.orchestrator import Orchestrator, RunResult
from sbom_ops.services.poc_identity import (
    attach_reviewed_poc,
    reviewed_target_is_current,
    select_reviewed_poc_targets,
)
from sbom_ops.services.poc_refresh import collect_poc_snapshot
from sbom_ops.services.sync_log import append_sync_event
from sbom_ops.storage.asset_registry import CURRENT_SCHEMA_VERSION, AssetRegistry
from sbom_ops.storage.identifier_candidates import IdentifierStore
from sbom_ops.storage.poc import PocStore
from sbom_ops.storage.poc_snapshot import save_poc_snapshot
from sbom_ops.storage.run_lock import exclusive_run, poc_lock_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sbom-ops")
    subparsers = parser.add_subparsers(dest="command", required=True)

    review = subparsers.add_parser("id-review")
    review.add_argument("--db", default="var/assets.sqlite3")
    actions = review.add_subparsers(dest="review_action", required=True)
    show = actions.add_parser("show")
    show.add_argument("--limit", type=int, default=100)
    for action in ("approve", "revoke"):
        change = actions.add_parser(action)
        change.add_argument("--observation", required=True, type=int)
        change.add_argument("--dt-source", required=True)
        change.add_argument("--cve", required=True)
        change.add_argument("--actor", required=True)
        change.add_argument("--reason", required=True)
        change.add_argument("--execute", action="store_true")
        if action == "approve":
            change.add_argument("--expires-at", required=True)
            change.add_argument("--max-age-hours", type=float, default=24)

    identifiers = subparsers.add_parser("id-candidates")
    inputs = identifiers.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--findings", help="successful sync JSON; default is preview")
    inputs.add_argument(
        "--show", action="store_true", help="read saved observations only"
    )
    identifiers.add_argument("--db", default="var/assets.sqlite3")
    identifiers.add_argument("--max-ids", type=int, default=25)
    identifiers.add_argument(
        "--id",
        action="append",
        dest="identifiers",
        default=[],
        help="select an exact unresolved input ID; repeatable",
    )
    identifiers.add_argument("--limit", type=int, default=100)
    identifiers.add_argument(
        "--execute",
        action="store_true",
        help="query OSV and save unapproved candidates",
    )

    poc_parser = subparsers.add_parser("poc-fetch")
    poc_parser.add_argument(
        "--findings", required=True, help="successful sync JSON file"
    )
    poc_parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    poc_parser.add_argument("--max-cves", type=int, default=25)
    poc_parser.add_argument(
        "--use-reviewed-identifiers",
        action="store_true",
        help="use current reviewed CVE mappings from --db (schema v9), PoC only",
    )
    poc_parser.add_argument("--ttl-seconds", type=int, default=21600)
    poc_parser.add_argument("--pacing-seconds", type=float, default=3.1)
    poc_parser.add_argument(
        "--db", default="var/assets.sqlite3", help="shared local SQLite DB"
    )
    poc_parser.add_argument("--refresh-seconds", type=int, default=3600)
    poc_parser.add_argument("--retry-base-seconds", type=int, default=60)
    poc_parser.add_argument("--retry-max-seconds", type=int, default=3600)
    poc_parser.add_argument(
        "--output", help="optional JSON export in addition to SQLite; never overwrite"
    )
    poc_parser.add_argument(
        "--execute",
        action="store_true",
        help="send CVEs to the provider; default is preview",
    )

    sync_parser = subparsers.add_parser("sync")
    sync_parser.add_argument("--config")
    sync_parser.add_argument("--project", dest="project_uuid")
    sync_parser.add_argument("--dry-run", action="store_true")
    sync_parser.add_argument(
        "--use-reviewed-identifiers",
        action="store_true",
        help="attach reviewed PoC mappings from the PoC DB after workflow processing",
    )
    sync_parser.add_argument("--log-level")
    sync_parser.add_argument("--wait-for-analysis", action="store_true")
    sync_parser.add_argument(
        "--refresh-kev",
        action="store_true",
        help="contact the CISA KEV feed even when the local cache is fresh",
    )
    poc_input = sync_parser.add_mutually_exclusive_group()
    poc_input.add_argument(
        "--poc-db", help="SQLite PoC input; defaults to --asset-db when v6"
    )
    poc_input.add_argument(
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
        choices=("text", "json", "review"),
        default="text",
        help="select detailed text, JSON, or a Japanese operator review queue",
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
    update_parser = asset_commands.add_parser("update-service")
    update_parser.add_argument("--service", required=True)
    update_parser.add_argument("--owner")
    update_parser.add_argument(
        "--criticality", choices=tuple(item.value for item in BusinessCriticality)
    )
    update_parser.add_argument(
        "--impact-reason", help="new business impact explanation"
    )
    update_parser.add_argument("--actor", required=True)
    update_parser.add_argument("--reason", required=True, help="reason for this change")
    update_parser.add_argument(
        "--apply", action="store_true", help="save the change; default is preview only"
    )
    history_parser = asset_commands.add_parser("history")
    history_parser.add_argument("--service", required=True)
    for command in ("retire-service", "retire-deployable", "revoke-link"):
        lifecycle_parser = asset_commands.add_parser(command)
        if command == "revoke-link":
            lifecycle_parser.add_argument("--project", required=True)
        else:
            lifecycle_parser.add_argument("--service", required=True)
            if command == "retire-deployable":
                lifecycle_parser.add_argument("--deployable", required=True)
        lifecycle_parser.add_argument("--actor", required=True)
        lifecycle_parser.add_argument("--reason", required=True)
        lifecycle_parser.add_argument("--apply", action="store_true")
    deployable_parser = asset_commands.add_parser("register-deployable")
    deployable_parser.add_argument("--service", required=True)
    deployable_parser.add_argument("--deployable", required=True)
    import_parser = asset_commands.add_parser("import")
    import_parser.add_argument("--file", required=True)
    import_parser.add_argument(
        "--apply",
        action="store_true",
        help="write the reviewed registration; default is preview only",
    )
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
    deployment_parser.add_argument(
        "--supersedes-report",
        type=int,
        help="replace an earlier report for the same artifact and environment",
    )
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
    print("Close missing findings: False (resolution verification not implemented)")
    print(
        "Legacy missing confirmations (unused): "
        f"{config.workflow.missing_confirmation_runs}"
    )
    return 0


def _append_sync_event_with_warning(path: str, payload: dict[str, object]) -> None:
    if not append_sync_event(path, payload):
        print(
            "warning: sync log could not be written; primary sync result is unchanged",
            file=sys.stderr,
        )


def print_review_queue(result: RunResult) -> None:
    """Present existing assessments and human claims without making decisions."""
    queue = result.review_queue()
    print(
        f"確認用一覧: {len(queue)}件（1件 = 1 Finding、環境は内訳） "
        f"run_id={result.run_id}"
    )
    print("P0→P3順。資産・PoCは参考情報。稼働申告は実稼働の証明ではありません。")
    print("解決確認=未確認（同一応答・0件は修正完了の根拠になりません）")
    print(
        f"台帳={result.registry_snapshot_status.value} "
        f"PoC入力={result.advisory_snapshot_status.value} "
        f"CVE対応入力={result.poc_identity_status} "
        f"解析待機={result.analysis_snapshot_status.value} "
        f"KEV旧キャッシュ={result.kev_used_stale_cache}"
    )
    asset_labels = {
        "matched": "紐付け確認済み",
        "not_requested": "台帳未指定",
        "unlinked": "未紐付け",
        "identity_changed": "Project情報変更・再確認が必要",
        "ambiguous": "紐付けが複数候補",
        "retired": "台帳上で廃止（実停止は未確認）",
        "revoked": "紐付け撤回済み",
    }
    poc_labels = {
        "reported": "報告あり（有効性は未評価）",
        "not_observed": "有効な観測で未検出（不存在の保証なし）",
        "unknown": "不明",
    }
    deployment_labels = {
        "unverified_link": "紐付け未確認",
        "unreported": "未申告",
        "other_artifact": "別の成果物の申告",
        "expired": "期限切れ",
        "future_observation": "未来日時",
        "conflict": "申告が矛盾",
        "reported": "期限内の申告",
    }
    for row in queue:
        item = row.assessment
        asset = row.asset
        criticality = asset.criticality.value if asset and asset.criticality else "不明"
        print(
            f"\n[{item.priority.value}] {item.vulnerability_id} "
            f"({item.vulnerability_source}) "
            f"部品={item.component_name or '不明'}@{item.component_version or '不明'}"
        )
        print(f"  Project={item.project_uuid} Finding={item.finding_key}")
        print(
            f"  資産={asset_labels[row.asset_status]} "
            f"サービス={asset.service_id if asset else '不明'} "
            f"配布単位={asset.deployable_id if asset else '不明'} "
            f"担当={asset.owner if asset and asset.owner else '不明'} "
            f"重要度={criticality}"
        )
        if not row.environments:
            print("  環境・稼働・外部公開=不明（確認済みの紐付け・申告が必要）")
        for environment in row.environments:
            fact = environment.as_dict()
            print(
                f"  環境={environment.environment or '不明'} "
                f"確認状態={deployment_labels[environment.status.value]} "
                f"成果物={environment.artifact_id or '不明'} "
                f"稼働申告={fact['deployment_status'] or '不明'} "
                f"外部公開申告={fact['exposure_status'] or '不明'} "
                f"申告ID={','.join(map(str, environment.report_ids)) or 'なし'}"
            )
        poc = item.poc_reports
        print(f"  PoC={poc_labels[poc.status.value]}")
        if item.poc_identity:
            mapping = item.poc_identity
            print(
                f"    PoC用CVE対応={mapping.status} 元ID={mapping.original_id} "
                f"DT情報源={mapping.dt_source} CVE={mapping.cve or '不明'} "
                f"採用ID={mapping.review_id or 'なし'} "
                f"観測ID={mapping.observation_id or 'なし'} "
                f"出典={mapping.source or '不明'} "
                f"採用者={json.dumps(mapping.actor, ensure_ascii=False)} "
                f"理由={json.dumps(mapping.reason, ensure_ascii=False)} "
                f"期限={mapping.expires_at or '不明'}"
            )
        for source in poc.sources:
            count = source.record_count if source.record_count is not None else "不明"
            print(
                f"    情報源={source.source} ID={source.vulnerability_id} "
                f"件数={count} "
                f"取得状態={source.outcome.value} "
                f"鮮度判定={source.effective_freshness().value} "
                f"観測日時={source.observed_at} "
                f"期限={source.expires_at or '不明'} "
                f"最終取得試行={source.last_attempt_at or '不明'} "
                f"取得エラー={source.last_error or 'なし'}"
            )
        print(
            f"  DT分析={item.analysis_state.value} 抑制={item.is_suppressed} "
            "（既存判断を維持）"
        )
        print(f"  優先度の理由={'; '.join(item.rationale)}")
    print(
        f"\nIssue操作: 作成={result.issues_created} 更新={result.issues_updated} "
        f"終了={result.issues_closed} dry_run={result.dry_run}"
    )
    for action in result.actions:
        print(f"  {action}")


def run_sync(
    config: AppConfig,
    output_format: str = "text",
    *,
    force_refresh_kev: bool = False,
    advisory_snapshot_path: str | None = None,
    asset_inventory_path: str | None = None,
    asset_db_path: str | None = None,
    poc_db_path: str | None = None,
    use_reviewed_identifiers: bool = False,
) -> int:
    if advisory_snapshot_path and poc_db_path:
        raise ValueError("choose either advisory snapshot or PoC DB")
    asset_registry = None
    if asset_db_path:
        with AssetRegistry(asset_db_path, read_only=True) as registry:
            registry.check_integrity()
            asset_registry = AssetRegistrySnapshot(
                services=registry.list_services(),
                links=registry.list_links(),
                deployment_reports=registry.list_deployment_reports(),
                **registry.lifecycle_state(),
            )
            if registry.schema_version >= 6 and not advisory_snapshot_path:
                poc_db_path = poc_db_path or asset_db_path
    if use_reviewed_identifiers and (not poc_db_path or advisory_snapshot_path):
        raise ValueError("reviewed identifiers require a PoC DB, not a JSON snapshot")
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
    elif poc_db_path:
        try:
            with PocStore(poc_db_path, read_only=True) as store:
                snapshot = store.snapshot()
        except (OSError, ValueError, sqlite3.Error) as exc:
            snapshot_error = str(exc)
            print(f"warning: PoC DB ignored: {snapshot_error}", file=sys.stderr)
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
    if use_reviewed_identifiers:
        try:
            if snapshot is None:
                raise ValueError("PoC snapshot unavailable")
            with IdentifierStore(poc_db_path, read_only=True) as identifiers:
                assessments = attach_reviewed_poc(
                    result.assessments, snapshot, identifiers, now=datetime.now(UTC)
                )
            result = replace(
                result, assessments=assessments, poc_identity_status="loaded"
            )
        except (OSError, ValueError, sqlite3.Error, KeyError, TypeError) as exc:
            print("warning: reviewed PoC identifiers unavailable", file=sys.stderr)
            result = replace(
                result,
                poc_identity_status="invalid",
                poc_identity_error=type(exc).__name__,
            )
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
    if output_format == "review":
        print_review_queue(result)
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
    print("解決確認=未確認（同一応答・0件は修正完了の根拠になりません）")
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
        if assessment.poc_identity:
            print(
                "  poc_identity="
                + json.dumps(assessment.poc_identity.as_dict(), ensure_ascii=False)
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
    if args.asset_command in ("retire-service", "retire-deployable", "revoke-link"):
        with AssetRegistry(args.db, read_only=not args.apply) as registry:
            registry.check_integrity()
            change = plan_lifecycle_change(
                registry,
                action=LifecycleAction(args.asset_command.replace("-", "_")),
                service_id=getattr(args, "service", None),
                deployable_id=getattr(args, "deployable", None),
                project_uuid=getattr(args, "project", None),
                actor=args.actor,
                reason=args.reason,
            )
            result = (
                registry.apply_lifecycle_change(change)
                if args.apply
                else change.as_dict()
            )
            print(
                json.dumps(
                    {"status": "applied" if args.apply else "preview", **result},
                    ensure_ascii=False,
                    indent=2,
                )
            )
            if not args.apply:
                print("確認のみ。保存する場合は --apply を追加してください。")
                if registry.schema_version < 5:
                    print(
                        "保存前に assets migrate --backup PATH による移行が必要です。"
                    )
        return 0
    if args.asset_command in ("update-service", "history"):
        read_only = args.asset_command == "history" or not args.apply
        with AssetRegistry(args.db, read_only=read_only) as registry:
            registry.check_integrity()
            if args.asset_command == "history":
                print(
                    json.dumps(
                        {
                            "service_id": args.service,
                            "schema_version": registry.schema_version,
                            "changes": [
                                item.as_dict()
                                for item in registry.list_service_changes(args.service)
                            ],
                            "lifecycle_events": list(
                                registry.list_lifecycle_events(args.service)
                            ),
                            "note": (
                                "更新はv4、廃止・撤回はv5以降。"
                                "過去の履歴は補完しません。"
                            ),
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                )
                return 0
            update = plan_service_update(
                registry,
                service_id=args.service,
                owner=args.owner,
                criticality=(
                    BusinessCriticality(args.criticality) if args.criticality else None
                ),
                impact_reason=args.impact_reason,
                actor=args.actor,
                reason=args.reason,
            )
            if args.apply:
                change = registry.update_service(update)
                print(
                    json.dumps(
                        {"status": "applied", **change.as_dict()},
                        ensure_ascii=False,
                        indent=2,
                    )
                )
            else:
                print(
                    json.dumps(
                        {"status": "preview", **update.as_dict()},
                        ensure_ascii=False,
                        indent=2,
                    )
                )
                print("確認のみ。保存する場合は --apply を追加してください。")
                if registry.schema_version < 4:
                    print(
                        "保存前に assets migrate --backup PATH による移行が必要です。"
                    )
        return 0
    if args.asset_command == "import":
        batch = load_asset_registration(args.file)
        print(
            f"asset registration: {len(batch.services)} services, "
            f"{len(batch.deployables)} deployables"
        )
        for service in batch.services:
            print(
                f"service={service.service_id} owner={service.owner} "
                f"criticality={service.criticality.value} "
                f"reason={service.impact_reason}"
            )
        for deployable in batch.deployables:
            print(f"deployable={deployable.project_name}")
        if not args.apply:
            print("preview only; rerun with --apply after review")
            return 0
        with AssetRegistry(args.db, create_if_missing=True) as registry:
            registry.register_batch(batch)
        print("asset registration applied")
        return 0
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
                    supersedes_report_id=args.supersedes_report,
                )
            )
            print(f"recorded human deployment report={report.report_id}")
        elif args.asset_command == "list":
            for service in registry.list_services():
                status = (
                    "retired" if registry.is_retired(service.service_id) else "active"
                )
                print(
                    f"service={service.service_id} owner={service.owner} "
                    f"criticality={service.criticality.value} "
                    f"reason={service.impact_reason}"
                    f" status={status}"
                )
            for deployable in registry.list_deployables():
                status = (
                    "retired"
                    if registry.is_retired(
                        deployable.service_id, deployable.deployable_id
                    )
                    else "active"
                )
                print(f"deployable={deployable.project_name} status={status}")
            for link in registry.list_links():
                print(
                    f"link={link.project_uuid} name={link.project_name} "
                    f"version={link.project_version} reviewer={link.reviewer} "
                    f"reviewed_at={link.reviewed_at}"
                )
            reports = registry.list_deployment_reports()
            successors = {
                report.supersedes_report_id: report
                for report in reports
                if report.supersedes_report_id is not None
            }
            for report in reports:
                successor = successors.get(report.report_id)
                if successor is not None and not successor.is_future():
                    freshness = "superseded"
                elif report.is_future():
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
                    f"observed_at={report.observed_at} expires_at={report.expires_at} "
                    f"supersedes_report={report.supersedes_report_id or '-'} "
                    f"superseded_by={successor.report_id if successor else '-'}"
                )
        elif args.asset_command == "check":
            registry.check_integrity()
            print(f"asset DB integrity OK: {args.db}")
        elif args.asset_command == "backup":
            output = registry.backup_to(args.output)
            print(f"asset DB backup created: {output}")
        elif args.asset_command == "migrate":
            if registry.schema_version == CURRENT_SCHEMA_VERSION:
                print(f"asset DB already uses schema v{CURRENT_SCHEMA_VERSION}")
            else:
                output = registry.backup_to(args.backup)
                registry.migrate()
                print(
                    f"asset DB upgraded to schema v{CURRENT_SCHEMA_VERSION}; "
                    f"backup: {output}"
                )
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


def run_identifier_review(args: argparse.Namespace) -> int:
    execute = getattr(args, "execute", False)
    with IdentifierStore(args.db, read_only=not execute) as store:
        if args.review_action == "show":
            result = {"reviews": list_identifier_reviews(store, limit=args.limit)}
        else:
            result = review_identifier(
                store,
                observation_id=args.observation,
                dt_source=args.dt_source,
                cve=args.cve,
                action=args.review_action,
                actor=args.actor,
                reason=args.reason,
                expires_at=getattr(args, "expires_at", None),
                max_age_hours=getattr(args, "max_age_hours", 24),
                execute=execute,
            )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def run_identifier_candidates(args: argparse.Namespace) -> int:
    if args.show:
        if args.execute:
            raise ValueError("--show cannot be combined with --execute")
        with IdentifierStore(args.db, read_only=True) as store:
            print(
                json.dumps(
                    {"observations": store.recent(limit=args.limit)},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        return 0
    with Path(args.findings).open("rb") as stream:
        raw = stream.read(20 * 1024 * 1024 + 1)
    if len(raw) > 20 * 1024 * 1024:
        raise ValueError("sync input exceeds 20 MiB")
    targets, unsupported = select_identifier_targets(
        json.loads(raw), max_ids=args.max_ids, only_ids=tuple(args.identifiers)
    )
    if Path(args.db).resolve() == Path(args.findings).resolve():
        raise ValueError("candidate DB must not be the findings input")
    if not args.execute:
        print(
            json.dumps(
                {
                    "status": "preview",
                    "source": "https://api.osv.dev",
                    "ids": [t.original_id for t in targets],
                    "unsupported_ids": unsupported,
                    "automatic_approval": False,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    with exclusive_run(Path(f"{Path(args.db).resolve()}.identifiers.lock")):
        with AssetRegistry(args.db, create_if_missing=True) as registry:
            if registry.schema_version < 8:
                raise ValueError(
                    "identifier candidates require schema v8; back up and migrate"
                )
        with IdentifierStore(args.db) as store:
            results, skipped = collect_identifier_candidates(
                targets, OsvClient(), store
            )
    partial = bool(
        unsupported or skipped or any(r["status"] == "error" for r in results)
    )
    print(
        json.dumps(
            {
                "status": "partial" if partial else "succeeded",
                "observations": results,
                "unsupported_ids": unsupported,
                "not_attempted_ids": skipped,
                "automatic_approval": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 1 if partial else 0


def run_poc_fetch(args: argparse.Namespace) -> int:
    if not args.execute:
        return _run_poc_fetch(args)
    with exclusive_run(poc_lock_path(args.db)):
        return _run_poc_fetch(args)


def _run_poc_fetch(args: argparse.Namespace) -> int:
    retry_policy = PocRetryPolicy(args.retry_base_seconds, args.retry_max_seconds)
    base_url = validate_base_url(args.base_url)
    if not 1 <= args.ttl_seconds <= 604800:
        raise ValueError("ttl-seconds must be between 1 and 604800")
    if not 3.1 <= args.pacing_seconds <= 3600:
        raise ValueError("pacing-seconds must be between 3.1 and 3600")
    if not 1 <= args.refresh_seconds <= 604800:
        raise ValueError("refresh-seconds must be between 1 and 604800")
    with Path(args.findings).open("rb") as stream:
        raw = stream.read(20 * 1024 * 1024 + 1)
    if len(raw) > 20 * 1024 * 1024:
        raise ValueError("sync input exceeds 20 MiB")
    payload = json.loads(raw)
    targets = select_poc_targets(payload, max_cves=args.max_cves)
    direct_cves = targets.cves
    mappings = ()
    selected_at = datetime.now(UTC)
    if args.use_reviewed_identifiers:
        with IdentifierStore(args.db, read_only=True) as identifiers:
            targets, mappings = select_reviewed_poc_targets(
                payload, identifiers, max_cves=args.max_cves, now=selected_at
            )
    db_path = Path(args.db)
    if db_path.resolve() == Path(args.findings).resolve():
        raise ValueError("PoC DB must not be the findings input")
    if not args.execute:
        due = list(targets.cves)
        source_state = None
        if db_path.exists():
            with PocStore(db_path, read_only=True) as store:
                state = store.source_state(f"vulnerability-lookup:{base_url}")
                source_state = state.as_dict()
                due = [
                    cve
                    for cve in targets.cves
                    if (record := store.get(cve, f"vulnerability-lookup:{base_url}"))
                    is None
                    or record.needs_refresh(
                        datetime.now(UTC), timedelta(seconds=args.refresh_seconds)
                    )
                ]
                if state.blocked(datetime.now(UTC)):
                    due = []
        print(
            json.dumps(
                {
                    "status": "preview",
                    "base_url": base_url,
                    "cves": targets.cves,
                    "selection": targets.summary(),
                    "identifier_selection": [item.as_dict() for item in mappings],
                    "identifier_selection_at": selected_at.isoformat(),
                    "update_cves": due,
                    "db": str(db_path),
                    "refresh_seconds": args.refresh_seconds,
                    "source_state": source_state,
                    "unresolved_ids": targets.unresolved,
                    "ttl_seconds": args.ttl_seconds,
                    "pacing_seconds": args.pacing_seconds,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    output = Path(args.output) if args.output else None
    if output and (
        output.exists()
        or output.is_symlink()
        or not output.parent.is_dir()
        or output.resolve() == db_path.resolve()
    ):
        raise ValueError("output must be a new file in an existing directory")
    with AssetRegistry(db_path, create_if_missing=True) as registry:
        if registry.schema_version < 7:
            raise ValueError(
                "PoC updates require schema v7; back up and migrate the DB"
            )
    client = VulnerabilityLookupClient(
        base_url, api_key=os.environ.get("SBOM_OPS_VULNERABILITY_LOOKUP_API_KEY")
    )
    with ExitStack() as stack:
        store = stack.enter_context(PocStore(db_path))
        target_is_current = None
        if args.use_reviewed_identifiers:
            identifiers = stack.enter_context(IdentifierStore(db_path, read_only=True))

            def target_is_current(cve: str, now: datetime) -> bool:
                return reviewed_target_is_current(
                    identifiers, cve, direct_cves, mappings, now=now
                )

        snapshot = collect_poc_snapshot(
            targets,
            client,
            ttl_seconds=args.ttl_seconds,
            pacing_seconds=args.pacing_seconds,
            refresh_seconds=args.refresh_seconds,
            repository=store,
            retry_policy=retry_policy,
            target_is_current=target_is_current,
        )
    snapshot["collection"]["identifier_selection"] = [
        item.as_dict() for item in mappings
    ]
    snapshot["collection"]["identifier_selection_at"] = selected_at.isoformat()
    if output:
        save_poc_snapshot(output, snapshot)
    print(json.dumps(snapshot["collection"], ensure_ascii=False, indent=2))
    return 0 if snapshot["collection"]["status"] == "succeeded" else 1


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    active_config: AppConfig | None = None
    try:
        if args.command == "id-review":
            return run_identifier_review(args)
        if args.command == "id-candidates":
            return run_identifier_candidates(args)
        if args.command == "poc-fetch":
            return run_poc_fetch(args)
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
                poc_db_path=args.poc_db,
                use_reviewed_identifiers=args.use_reviewed_identifiers,
            )
        parser.error(f"unsupported command: {args.command}")
    except PocRunBusy:
        error = (
            "identifier_update_already_running"
            if args.command == "id-candidates"
            else "poc_update_already_running"
        )
        print(json.dumps({"status": "busy", "error": error}))
        return 3
    except (
        DependencyTrackApiError,
        GitHubApiError,
        KevApiError,
        OSError,
        sqlite3.Error,
        ValueError,
    ) as exc:
        failure = {
            "run_id": str(uuid4()),
            "status": "failed",
            "error_type": type(exc).__name__,
            "analysis_snapshot_status": "unknown",
            "absence_verification": decide_missing_finding().as_dict(),
        }
        if (
            args.command == "sync"
            and active_config is not None
            and active_config.runtime.sync_log_file
        ):
            _append_sync_event_with_warning(
                active_config.runtime.sync_log_file,
                {**failure, "error": str(exc)},
            )
        if args.command == "sync" and args.output == "json":
            # A failure is not an empty successful inventory. Do not emit zero
            # counts, partial assessments, or external response bodies here.
            print(json.dumps(failure, ensure_ascii=False, sort_keys=True))
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
