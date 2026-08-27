from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sbom_ops.domain.dt_lab import LabManifestError, ScenarioStatus
from sbom_ops.services.dt_lab import (
    RELEVANT_OPENAPI_TAGS,
    build_openapi_inventory,
    load_lab_manifest,
    openapi_inventory_dict,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-ops-dt-lab",
        description=(
            "Validate the DT lab corpus and inspect a captured OpenAPI contract."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate-manifest")
    validate_parser.add_argument("--manifest", default="examples/sboms/scenarios.yaml")

    inventory_parser = subparsers.add_parser("openapi-inventory")
    inventory_parser.add_argument("openapi_path")
    inventory_parser.add_argument("--output")
    inventory_parser.add_argument(
        "--all-tags",
        action="store_true",
        help="include every operation instead of the sbom-ops-relevant tags",
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


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "validate-manifest":
            return _run_validate_manifest(args.manifest)
        if args.command == "openapi-inventory":
            return _run_openapi_inventory(args.openapi_path, args.output, args.all_tags)
        parser.error(f"unsupported command: {args.command}")
    except (json.JSONDecodeError, LabManifestError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
