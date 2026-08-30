from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from dt_lab.cleanup import cleanup_lab_run
from dt_lab.client import DependencyTrackLabApiError, DependencyTrackLabClient
from dt_lab.domain import (
    LabCleanupError,
    LabCleanupResult,
    LabManifestError,
    ScenarioStatus,
)
from dt_lab.service import (
    RELEVANT_OPENAPI_TAGS,
    build_corpus_lab_manifest,
    build_openapi_inventory,
    inspect_corpus_catalog,
    load_corpus_catalog,
    load_lab_manifest,
    openapi_inventory_dict,
    run_lab_scenarios,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dt-lab",
        description="Run isolated Dependency-Track behavior experiments safely.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate-manifest")
    validate_parser.add_argument(
        "--manifest", default="lab/dependency_track/scenarios/scenarios.yaml"
    )

    inventory_parser = subparsers.add_parser("openapi-inventory")
    inventory_parser.add_argument("openapi_path")
    inventory_parser.add_argument("--output")
    inventory_parser.add_argument(
        "--all-tags",
        action="store_true",
        help="include every operation instead of the sbom-ops-relevant tags",
    )

    run_parser = subparsers.add_parser("run-scenarios")
    run_parser.add_argument(
        "--manifest", default="lab/dependency_track/scenarios/scenarios.yaml"
    )
    run_parser.add_argument("--output-dir", default="var/dt-lab/runs")
    run_parser.add_argument("--scenario", action="append", default=[])
    run_parser.add_argument(
        "--openapi-inventory", default="var/dt-lab/openapi-inventory.json"
    )
    run_parser.add_argument(
        "--processing-timeout",
        type=float,
        default=float(os.getenv("SBOM_OPS_DT_ANALYSIS_WAIT_TIMEOUT_SECONDS", "120")),
    )
    run_parser.add_argument(
        "--poll-interval",
        type=float,
        default=float(os.getenv("SBOM_OPS_DT_ANALYSIS_POLL_INTERVAL_SECONDS", "5")),
    )
    run_parser.add_argument(
        "--allow-analysis-mutation",
        action="store_true",
        help=(
            "allow selected analysis_actions on disposable lab Projects using "
            "SBOM_OPS_DT_ANALYSIS_API_KEY"
        ),
    )

    cleanup_parser = subparsers.add_parser("cleanup-run")
    cleanup_parser.add_argument("--run-id", required=True)
    cleanup_parser.add_argument("--output-dir", default="var/dt-lab/runs")
    cleanup_parser.add_argument(
        "--execute",
        action="store_true",
        help="perform verified Project deletion; otherwise only write a plan",
    )

    corpus_validate_parser = subparsers.add_parser("validate-corpus")
    corpus_validate_parser.add_argument(
        "--catalog", default="lab/dependency_track/corpus/corpus.yaml"
    )
    corpus_validate_parser.add_argument("--artifact-dir", default="var/dt-lab/corpus")
    corpus_validate_parser.add_argument(
        "--require-local",
        action="store_true",
        help="verify every local artifact hash and CycloneDX envelope",
    )

    corpus_run_parser = subparsers.add_parser("run-corpus")
    corpus_run_parser.add_argument(
        "--catalog", default="lab/dependency_track/corpus/corpus.yaml"
    )
    corpus_run_parser.add_argument("--artifact-dir", default="var/dt-lab/corpus")
    corpus_run_parser.add_argument(
        "--artifact",
        action="append",
        required=True,
        help="explicit corpus artifact ID; repeat to select more than one",
    )
    corpus_run_parser.add_argument("--output-dir", default="var/dt-lab/runs")
    corpus_run_parser.add_argument(
        "--openapi-inventory", default="var/dt-lab/openapi-inventory.json"
    )
    corpus_run_parser.add_argument(
        "--processing-timeout",
        type=float,
        default=float(os.getenv("SBOM_OPS_DT_ANALYSIS_WAIT_TIMEOUT_SECONDS", "120")),
    )
    corpus_run_parser.add_argument(
        "--poll-interval",
        type=float,
        default=float(os.getenv("SBOM_OPS_DT_ANALYSIS_POLL_INTERVAL_SECONDS", "5")),
    )
    return parser


def _load_openapi(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("OpenAPI document must be a JSON object")
    return payload


def _write_json(payload: dict[str, Any], output: str | None) -> None:
    serialized = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output is None:
        print(serialized)
        return
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(f"{serialized}\n", encoding="utf-8")
    print(f"wrote {output_path}")


def _run_validate_manifest(manifest_path: str) -> int:
    manifest = load_lab_manifest(manifest_path)
    implemented = sum(
        scenario.status is ScenarioStatus.IMPLEMENTED for scenario in manifest.scenarios
    )
    planned = len(manifest.scenarios) - implemented
    steps = sum(len(scenario.steps) for scenario in manifest.scenarios)
    print(
        "DT lab manifest valid: "
        f"target={manifest.target.dependency_track_version} "
        f"scenarios={len(manifest.scenarios)} "
        f"implemented={implemented} planned={planned} steps={steps}"
    )
    return 0


def _run_openapi_inventory(
    openapi_path: str, output: str | None, all_tags: bool
) -> int:
    inventory = build_openapi_inventory(
        _load_openapi(openapi_path),
        selected_tags=None if all_tags else RELEVANT_OPENAPI_TAGS,
    )
    _write_json(openapi_inventory_dict(inventory), output)
    if output is not None:
        print(
            "OpenAPI inventory: "
            f"paths={inventory.path_count} operations={inventory.operation_count} "
            f"selected={len(inventory.operations)} tags={inventory.tag_count}"
        )
    return 0


def _openapi_hash(path: str | None) -> str | None:
    if not path:
        return None
    inventory_path = Path(path)
    if not inventory_path.is_file():
        return None
    payload = _load_openapi(inventory_path)
    source = payload.get("source")
    if not isinstance(source, dict):
        return None
    value = source.get("contract_sha256")
    return str(value) if value else None


def _dependency_track_client(api_key: str) -> DependencyTrackLabClient:
    base_url = os.getenv("SBOM_OPS_DT_BASE_URL")
    if not base_url:
        raise ValueError("Dependency-Track access requires SBOM_OPS_DT_BASE_URL")
    return DependencyTrackLabClient(
        base_url,
        api_key,
        timeout=float(os.getenv("SBOM_OPS_DT_TIMEOUT_SECONDS", "30")),
        max_retries=int(os.getenv("SBOM_OPS_DT_MAX_RETRIES", "3")),
        retry_backoff_seconds=float(
            os.getenv("SBOM_OPS_DT_RETRY_BACKOFF_SECONDS", "1")
        ),
    )


def _run_scenarios(args: argparse.Namespace) -> int:
    upload_key = os.getenv("SBOM_OPS_SBOM_UPLOAD_API_KEY")
    read_key = os.getenv("SBOM_OPS_DT_API_KEY")
    if not upload_key or not read_key:
        raise ValueError(
            "run-scenarios requires SBOM_OPS_SBOM_UPLOAD_API_KEY and "
            "SBOM_OPS_DT_API_KEY"
        )
    analysis_key = os.getenv("SBOM_OPS_DT_ANALYSIS_API_KEY")
    if args.allow_analysis_mutation and not analysis_key:
        raise ValueError(
            "--allow-analysis-mutation requires SBOM_OPS_DT_ANALYSIS_API_KEY"
        )
    manifest = load_lab_manifest(args.manifest)
    result = run_lab_scenarios(
        manifest,
        manifest_path=args.manifest,
        upload_client=_dependency_track_client(upload_key),
        read_client=_dependency_track_client(read_key),
        analysis_client=(
            _dependency_track_client(str(analysis_key))
            if args.allow_analysis_mutation
            else None
        ),
        output_directory=args.output_dir,
        scenario_ids=tuple(args.scenario),
        processing_timeout=args.processing_timeout,
        poll_interval=args.poll_interval,
        openapi_contract_sha256=_openapi_hash(args.openapi_inventory),
        allow_analysis_mutation=args.allow_analysis_mutation,
    )
    print(
        f"DT lab run completed: run_id={result.run_id} "
        f"steps={len(result.steps)} output={result.output_directory}"
    )
    for step in result.steps:
        print(
            f"{step.scenario_id}/{step.step_id}: project={step.project_uuid} "
            f"observations={step.observation_count}"
        )
    return 0


def _print_cleanup_result(result: LabCleanupResult) -> None:
    if not result.executed:
        print(
            f"DT lab cleanup plan: run_id={result.run_id} "
            f"targets={len(result.targets)} audit={result.audit_path}"
        )
        return
    print(
        f"DT lab cleanup completed: run_id={result.run_id} "
        f"deleted={len(result.deleted_project_uuids)} "
        f"already_absent={len(result.already_absent_projects)} "
        f"audit={result.audit_path}"
    )


def _run_cleanup(args: argparse.Namespace) -> int:
    cleanup_key = os.getenv("SBOM_OPS_DT_CLEANUP_API_KEY")
    if args.execute and not cleanup_key:
        raise ValueError("--execute requires SBOM_OPS_DT_CLEANUP_API_KEY")
    result = cleanup_lab_run(
        output_directory=args.output_dir,
        run_id=args.run_id,
        execute=args.execute,
        client=(_dependency_track_client(str(cleanup_key)) if args.execute else None),
    )
    _print_cleanup_result(result)
    return 0


def _run_validate_corpus(args: argparse.Namespace) -> int:
    catalog = load_corpus_catalog(args.catalog)
    if not args.require_local:
        print(
            "DT lab corpus catalog valid: "
            f"target={catalog.target.dependency_track_version} "
            f"artifacts={len(catalog.artifacts)}"
        )
        return 0
    inspections = inspect_corpus_catalog(catalog, args.artifact_dir)
    print(
        "DT lab corpus integrity valid (full schema not checked): "
        f"artifacts={len(inspections)} "
        f"bytes={sum(item.byte_count for item in inspections)} "
        f"components={sum(item.component_count for item in inspections)}"
    )
    for item in inspections:
        print(
            f"{item.artifact_id}: bytes={item.byte_count} "
            f"components={item.component_count} "
            f"dependencies={item.dependency_count} "
            f"services={item.service_count} "
            f"vulnerabilities={item.vulnerability_count}"
        )
    return 0


def _run_corpus(args: argparse.Namespace) -> int:
    upload_key = os.getenv("SBOM_OPS_SBOM_UPLOAD_API_KEY")
    read_key = os.getenv("SBOM_OPS_DT_API_KEY")
    if not upload_key or not read_key:
        raise ValueError(
            "run-corpus requires SBOM_OPS_SBOM_UPLOAD_API_KEY and SBOM_OPS_DT_API_KEY"
        )
    catalog = load_corpus_catalog(args.catalog)
    manifest = build_corpus_lab_manifest(
        catalog, args.artifact_dir, tuple(args.artifact)
    )
    result = run_lab_scenarios(
        manifest,
        manifest_path=args.catalog,
        upload_client=_dependency_track_client(upload_key),
        read_client=_dependency_track_client(read_key),
        output_directory=args.output_dir,
        processing_timeout=args.processing_timeout,
        poll_interval=args.poll_interval,
        openapi_contract_sha256=_openapi_hash(args.openapi_inventory),
    )
    print(
        f"DT lab corpus run completed: run_id={result.run_id} "
        f"steps={len(result.steps)} output={result.output_directory}"
    )
    for step in result.steps:
        print(
            f"{step.scenario_id}/{step.step_id}: project={step.project_uuid} "
            f"observations={step.observation_count}"
        )
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "validate-manifest":
            return _run_validate_manifest(args.manifest)
        if args.command == "openapi-inventory":
            return _run_openapi_inventory(args.openapi_path, args.output, args.all_tags)
        if args.command == "run-scenarios":
            return _run_scenarios(args)
        if args.command == "cleanup-run":
            return _run_cleanup(args)
        if args.command == "validate-corpus":
            return _run_validate_corpus(args)
        if args.command == "run-corpus":
            return _run_corpus(args)
        parser.error(f"unsupported command: {args.command}")
    except (
        DependencyTrackLabApiError,
        LabCleanupError,
        json.JSONDecodeError,
        LabManifestError,
        OSError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
