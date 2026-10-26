"""Reject incomplete sync envelopes before a lookup can produce empty results."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from sbom_ops.domain.asset_registry import (
    RegistryDeploymentObservation,
    RegistryDeploymentStatus,
    RegistryProjectObservation,
    RegistryProjectStatus,
    RegistrySnapshotStatus,
)
from sbom_ops.domain.models import AnalysisState, FindingAssessment, Priority, Severity
from sbom_ops.services.lookup_input import read_lookup_document
from sbom_ops.services.orchestrator import RunResult


def empty_run() -> dict[str, object]:
    return RunResult(
        run_id="example-run",
        duration_seconds=0,
        kev_used_stale_cache=False,
        projects_processed=0,
        findings_processed=0,
        issues_created=0,
        issues_updated=0,
        issues_closed=0,
        dry_run=True,
    ).as_dict()


def context_run() -> dict[str, object]:
    finding = FindingAssessment(
        project_uuid="project",
        finding_key="finding",
        vulnerability_id="CVE-2026-1234",
        vulnerability_source="NVD",
        severity=Severity.HIGH,
        cvss_score=8.0,
        epss_score=None,
        priority=Priority.P2,
        analysis_state=AnalysisState.NOT_SET,
        is_suppressed=False,
        rationale=(),
    )
    return RunResult(
        run_id="example-run",
        duration_seconds=0,
        kev_used_stale_cache=False,
        projects_processed=1,
        findings_processed=1,
        issues_created=0,
        issues_updated=0,
        issues_closed=0,
        dry_run=True,
        assessments=(finding,),
        registry_snapshot_status=RegistrySnapshotStatus.LOADED,
        registry_projects=(
            RegistryProjectObservation(
                "project",
                "shop/web",
                "build-a",
                RegistryProjectStatus.MATCHED,
                service_id="shop",
                deployable_id="web",
                owner="team-shop",
            ),
        ),
        registry_deployments=(
            RegistryDeploymentObservation(
                "project",
                "production",
                "build-a",
                RegistryDeploymentStatus.EXPIRED,
                report_ids=(1,),
            ),
        ),
    ).as_dict()


def evidence_run() -> dict[str, object]:
    payload = context_run()
    item = json.loads(
        (Path(__file__).parents[2] / "examples/lifecycle/build-a.json").read_text()
    )
    item.update(service_id="shop", deployable_id="web")
    payload["lifecycle_evidence_status"] = "loaded"
    payload["lifecycle_evidence"] = [
        {
            "project_uuid": "project",
            "project_status": "matched",
            "records": [
                {
                    "record_id": 1,
                    "recorded_at": "2026-10-01T00:00:00Z",
                    "status": "matched",
                    "evidence": item,
                }
            ],
        }
    ]
    return payload


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "wrong_asset",
        "wrong_artifact",
        "duplicate",
        "naive",
        "orphan",
        "bad_state",
    ],
)
def test_evidence_identity_and_history_boundaries(tmp_path: Path, case: str) -> None:
    payload = evidence_run()
    records = payload["lifecycle_evidence"][0]["records"]
    record = records[0]
    if case == "wrong_asset":
        record["evidence"]["service_id"] = "other"
    elif case == "wrong_artifact":
        record["evidence"]["artifact_id"] = "build-b"
    elif case == "duplicate":
        records.append(deepcopy(record))
    elif case == "naive":
        record["recorded_at"] = "2026-10-01"
    elif case == "orphan":
        record["evidence"].update(supersedes_id=99, reason="correction")
    elif case == "bad_state":
        record["status"] = "verified"
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    if case == "valid":
        assert read_lookup_document(path) == payload
    else:
        with pytest.raises(ValueError):
            read_lookup_document(path)


def test_context_is_preserved_without_reinterpreting_expiry(tmp_path: Path) -> None:
    payload = context_run()
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    assert read_lookup_document(path) == payload


def test_other_artifact_cannot_be_displayed_as_this_project(tmp_path: Path) -> None:
    payload = context_run()
    payload["registry_deployments"][0]["artifact_id"] = "build-b"
    payload["review_queue"][0]["environments"][0]["artifact_id"] = "build-b"
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="deployment_artifact"):
        read_lookup_document(path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("priority", "P0"),
        ("analysis_state", "RESOLVED"),
        ("is_suppressed", True),
        ("rationale", ["changed"]),
    ],
)
def test_review_evaluation_must_match_original(
    tmp_path: Path, field: str, value: object
) -> None:
    payload = context_run()
    payload["review_queue"][0][field] = value
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="evaluation"):
        read_lookup_document(path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("priority", "P9"),
        ("severity", "bad"),
        ("is_suppressed", 1),
        ("in_kev", "false"),
        ("cvss_score", float("inf")),
        ("epss_score", True),
        ("rationale", "not-a-list"),
    ],
)
def test_invalid_evaluation_is_rejected_even_when_both_copies_match(
    tmp_path: Path, field: str, value: object
) -> None:
    payload = context_run()
    for key in ("review_queue", "assessments"):
        payload[key][0][field] = value
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload).replace("Infinity", "1e999"))
    with pytest.raises(ValueError):
        read_lookup_document(path)


@pytest.mark.parametrize(
    "case", ["unknown_state", "unexpected_records", "missing_project", "bad_record"]
)
def test_lifecycle_evidence_must_not_silently_disappear(
    tmp_path: Path, case: str
) -> None:
    payload = context_run()
    if case == "unknown_state":
        payload["lifecycle_evidence_status"] = "complete"
    elif case == "unexpected_records":
        payload["lifecycle_evidence"] = [{"project_uuid": "project"}]
    else:
        payload["lifecycle_evidence_status"] = "loaded"
        payload["lifecycle_evidence"] = (
            []
            if case == "missing_project"
            else [
                {
                    "project_uuid": "project",
                    "project_status": "matched",
                    "records": [{}],
                }
            ]
        )
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        read_lookup_document(path)


def test_reported_claim_keeps_saved_status_even_after_its_expiry(
    tmp_path: Path,
) -> None:
    payload = context_run()
    deployment = payload["registry_deployments"][0]
    deployment.update(
        status="reported",
        deployment_status="deployed",
        exposure_status="unknown",
        reviewer="operator",
        observed_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-02T00:00:00Z",
    )
    payload["review_queue"][0]["environments"] = [dict(deployment)]
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    assert read_lookup_document(path) == payload


@pytest.mark.parametrize(
    "field,value",
    [
        ("report_ids", [True]),
        ("report_ids", []),
        ("source", None),
        ("deployment_status", "bad"),
        ("observed_at", "2026-10-01"),
        ("expires_at", "2026-09-01T00:00:00Z"),
    ],
)
def test_reported_claim_requires_valid_metadata(
    tmp_path: Path, field: str, value: object
) -> None:
    payload = context_run()
    deployment = payload["registry_deployments"][0]
    deployment.update(
        status="reported",
        deployment_status="deployed",
        exposure_status="unknown",
        reviewer="operator",
        observed_at="2026-10-01T00:00:00Z",
        expires_at="2026-11-01T00:00:00Z",
    )
    deployment[field] = value
    payload["review_queue"][0]["environments"] = [dict(deployment)]
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        read_lookup_document(path)


@pytest.mark.parametrize(
    "case", ["owner", "environment", "unlinked", "status", "invented_deployment"]
)
def test_inconsistent_context_is_rejected(tmp_path: Path, case: str) -> None:
    payload = context_run()
    row = payload["review_queue"][0]
    if case == "owner":
        row["asset"]["owner"] = "other-team"
    elif case == "environment":
        row["environments"][0]["environment"] = "staging"
    elif case == "unlinked":
        row["asset_status"] = "unlinked"
    elif case == "status":
        payload["registry_snapshot_status"] = "bad"
    else:
        row["environments"][0]["deployment_status"] = "deployed"
        payload["registry_deployments"][0]["deployment_status"] = "deployed"
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        read_lookup_document(path)


def test_valid_empty_run_is_read_without_modifying_file(tmp_path: Path) -> None:
    path = tmp_path / "sync.json"
    raw = json.dumps(empty_run()).encode()
    path.write_bytes(raw)
    result = read_lookup_document(path)
    assert result["review_queue"] == []
    assert result["run_id"] == "example-run"
    assert path.read_bytes() == raw


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "failed"),
        ("findings_processed", True),
        ("findings_processed", 1),
        ("projects_processed", -1),
        ("review_queue", None),
        ("assessments", None),
        ("run_id", ""),
        ("run_id", "bad\nvalue"),
    ],
)
def test_incomplete_envelope_is_not_empty_success(
    tmp_path: Path, field: str, value: object
) -> None:
    payload = empty_run()
    payload[field] = value
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        read_lookup_document(path)


@pytest.mark.parametrize(
    "raw", [b'{"status":1,"status":2}', b'{"x":NaN}', b"\xff", b"{"]
)
def test_bad_json_is_rejected(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "sync.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        read_lookup_document(path)


def test_file_size_and_depth_limits(tmp_path: Path) -> None:
    path = tmp_path / "sync.json"
    path.write_bytes(b" " * (8 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="byte_limit"):
        read_lookup_document(path)
    path.write_text("[" * 65 + "0" + "]" * 65)
    with pytest.raises(ValueError, match="depth_limit"):
        read_lookup_document(path)


def test_missing_file_is_not_created(tmp_path: Path) -> None:
    path = tmp_path / "absent.json"
    with pytest.raises(ValueError):
        read_lookup_document(path)
    assert not path.exists()


@pytest.mark.parametrize(
    "field", ["project_uuid", "component_purl", "vulnerability_source"]
)
def test_same_count_different_identity_is_rejected(tmp_path: Path, field: str) -> None:
    payload = empty_run()
    row = {
        "finding_key": "finding",
        "project_uuid": "project",
        "vulnerability_id": "CVE-2026-1234",
        "vulnerability_source": "NVD",
        "component_uuid": None,
        "component_purl": "pkg:pypi/example@1",
        "component_name": "example",
        "component_version": "1",
    }
    payload.update(
        findings_processed=1,
        projects_processed=1,
        assessments=[row],
        review_queue=[{**row, field: "different"}],
    )
    path = tmp_path / "sync.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="identity_mismatch"):
        read_lookup_document(path)
