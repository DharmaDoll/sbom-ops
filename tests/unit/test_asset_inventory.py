from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sbom_ops.services.asset_inventory import load_asset_inventory


def _payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "snapshot_id": "asset-test",
        "generated_at": "2026-10-04T00:00:00Z",
        "deployments": [
            {
                "project_uuid": "project-1",
                "service_id": "checkout",
                "environment": "production",
                "owner": "team-checkout",
                "deployed_version": "checkout@1.2.3",
                "deployment_status": "deployed",
                "exposure_status": "confirmed",
                "criticality": "critical",
                "source": "reviewed-inventory",
                "observed_at": "2026-10-03T00:00:00Z",
                "expires_at": "2026-10-10T00:00:00Z",
                "reviewer": "example-reviewer",
            }
        ],
    }


def _write(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "assets.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_asset_inventory_preserves_provenance_and_expires_context(tmp_path) -> None:
    path = _write(tmp_path, _payload())
    snapshot = load_asset_inventory(path)
    deployment = snapshot.for_project("project-1")[0]
    current = deployment.as_dict(now=datetime(2026, 10, 4, tzinfo=UTC))
    expired = deployment.as_dict(now=datetime(2026, 10, 11, tzinfo=UTC))

    assert snapshot.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert snapshot.for_project("project-2") == ()
    assert current["effective_owner"] == "team-checkout"
    assert current["effective_deployed_version"] == "checkout@1.2.3"
    assert current["effective_exposure_status"] == "confirmed"
    assert expired["reported_exposure_status"] == "confirmed"
    assert expired["effective_exposure_status"] == "unknown"
    assert expired["effective_deployment_status"] == "unknown"
    assert expired["effective_criticality"] == "unknown"
    assert expired["effective_owner"] is None
    assert expired["effective_deployed_version"] is None
    assert expired["freshness"] == "expired"


def test_documented_fictional_inventory_loads() -> None:
    path = Path(__file__).parents[2] / "examples" / "asset-inventory.example.json"

    snapshot = load_asset_inventory(path)

    assert snapshot.snapshot_id == "synthetic-asset-scenario-v1"
    assert len(snapshot.deployments) == 4


def test_duplicate_project_service_environment_is_rejected(tmp_path) -> None:
    payload = _payload()
    deployments = payload["deployments"]
    assert isinstance(deployments, list)
    deployments.append({**deployments[0], "environment": "Production"})

    with pytest.raises(ValueError, match="duplicate asset deployment"):
        load_asset_inventory(_write(tmp_path, payload))


def test_one_project_can_be_deployed_in_multiple_environments(tmp_path) -> None:
    payload = _payload()
    deployments = payload["deployments"]
    assert isinstance(deployments, list)
    deployments.append({**deployments[0], "environment": "development"})

    snapshot = load_asset_inventory(_write(tmp_path, payload))

    assert [item.environment for item in snapshot.for_project("project-1")] == [
        "production",
        "development",
    ]


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("deployment_status", "running", "deployment_status must be one of"),
        ("exposure_status", "public", "exposure_status must be one of"),
        ("observed_at", "2026-10-03", "observed_at must include a timezone"),
        ("expires_at", "2026-10-02T00:00:00Z", "expires_at must be later"),
    ],
)
def test_invalid_asset_facts_are_rejected(tmp_path, key, value, message) -> None:
    payload = _payload()
    deployments = payload["deployments"]
    assert isinstance(deployments, list)
    deployment = deployments[0]
    assert isinstance(deployment, dict)
    deployment[key] = value

    with pytest.raises(ValueError, match=message):
        load_asset_inventory(_write(tmp_path, payload))


def test_unknown_asset_field_is_rejected(tmp_path) -> None:
    payload = _payload()
    deployments = payload["deployments"]
    assert isinstance(deployments, list)
    deployment = deployments[0]
    assert isinstance(deployment, dict)
    deployment["internet_facing"] = True

    with pytest.raises(ValueError, match="unknown key"):
        load_asset_inventory(_write(tmp_path, payload))


def test_not_deployed_cannot_claim_a_current_version(tmp_path) -> None:
    payload = _payload()
    deployments = payload["deployments"]
    assert isinstance(deployments, list)
    deployment = deployments[0]
    assert isinstance(deployment, dict)
    deployment["deployment_status"] = "not_deployed"

    with pytest.raises(ValueError, match="must be null when not_deployed"):
        load_asset_inventory(_write(tmp_path, payload))
