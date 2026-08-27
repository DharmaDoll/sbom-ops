from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbom_ops.domain.dt_lab import LabManifestError, ScenarioStatus
from sbom_ops.dt_lab_cli import main
from sbom_ops.services.dt_lab import (
    build_openapi_inventory,
    load_lab_manifest,
    openapi_inventory_dict,
)

REPOSITORY_ROOT = Path(__file__).parents[2]


def test_repository_lab_manifest_is_valid() -> None:
    manifest = load_lab_manifest(
        REPOSITORY_ROOT / "examples" / "sboms" / "scenarios.yaml"
    )

    assert manifest.target.dependency_track_version == "4.14.3"
    assert len(manifest.scenarios) == 16
    implemented = [
        scenario
        for scenario in manifest.scenarios
        if scenario.status is ScenarioStatus.IMPLEMENTED
    ]
    assert [scenario.id for scenario in implemented] == [
        "lifecycle-vulnerable-to-updated"
    ]
    assert [step.id for step in implemented[0].steps] == ["vulnerable", "updated"]


def test_lab_manifest_rejects_missing_implemented_bom(tmp_path: Path) -> None:
    manifest_path = tmp_path / "scenarios.yaml"
    manifest_path.write_text(
        """
schema_version: 1
target:
  dependency_track_version: 4.14.3
  cyclonedx_versions: ["1.5"]
scenarios:
  - id: missing-bom
    category: robustness
    status: implemented
    purpose: Reject missing scenario files.
    project: {name: missing, version: 1.0.0}
    steps:
      - id: upload
        bom: absent.cdx.json
        observe: [project]
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(LabManifestError, match="BOM does not exist"):
        load_lab_manifest(manifest_path)


def test_openapi_inventory_extracts_contract_details() -> None:
    payload = json.loads(
        (
            REPOSITORY_ROOT / "tests" / "fixtures" / "dependency-track-openapi.json"
        ).read_text(encoding="utf-8")
    )

    inventory = build_openapi_inventory(payload)
    rendered = openapi_inventory_dict(inventory)

    assert inventory.path_count == 3
    assert inventory.operation_count == 3
    assert inventory.tag_count == 3
    assert len(inventory.operations) == 2
    finding = next(
        operation
        for operation in inventory.operations
        if operation.tags == ("finding",)
    )
    assert finding.method == "GET"
    assert finding.path == "/v1/finding/project/{uuid}"
    assert finding.permissions == ("VIEW_VULNERABILITY",)
    assert finding.query_parameters == ("source", "suppressed")
    assert finding.response_statuses == ("200", "403")
    assert finding.response_headers == ("X-Total-Count",)
    assert finding.response_media_types == (
        "application/json",
        "application/sarif+json",
    )
    assert rendered["summary"]["selected_operation_count"] == 2
    assert len(rendered["source"]["contract_sha256"]) == 64


def test_openapi_inventory_can_include_all_tags() -> None:
    payload = json.loads(
        (
            REPOSITORY_ROOT / "tests" / "fixtures" / "dependency-track-openapi.json"
        ).read_text(encoding="utf-8")
    )

    inventory = build_openapi_inventory(payload, selected_tags=None)

    assert len(inventory.operations) == 3
    assert inventory.selected_tags == ("analysis", "finding", "user")


def test_lab_cli_validates_repository_manifest(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "sbom-ops-dt-lab",
            "validate-manifest",
            "--manifest",
            str(REPOSITORY_ROOT / "examples" / "sboms" / "scenarios.yaml"),
        ],
    )

    assert main() == 0
    assert "scenarios=16 implemented=1 planned=15 steps=2" in capsys.readouterr().out


def test_lab_cli_writes_openapi_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_path = tmp_path / "inventory.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "sbom-ops-dt-lab",
            "openapi-inventory",
            str(
                REPOSITORY_ROOT / "tests" / "fixtures" / "dependency-track-openapi.json"
            ),
            "--output",
            str(output_path),
        ],
    )

    assert main() == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["summary"] == {
        "operation_count": 3,
        "path_count": 3,
        "selected_operation_count": 2,
        "selected_tags": [
            "analysis",
            "bom",
            "component",
            "dependencyGraph",
            "event",
            "finding",
            "metrics",
            "project",
            "search",
            "service",
            "vex",
            "violation",
            "violationanalysis",
            "vulnerability",
        ],
        "tag_count": 3,
    }
    assert "OpenAPI inventory: paths=3 operations=3 selected=2 tags=3" in (
        capsys.readouterr().out
    )
