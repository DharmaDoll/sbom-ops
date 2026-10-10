from __future__ import annotations

import json

import pytest

from sbom_ops import cli
from sbom_ops.domain.asset_import import parse_asset_registration
from sbom_ops.services.asset_import import load_asset_registration
from sbom_ops.storage.asset_registry import AssetRegistry


def registration() -> dict[str, object]:
    return {
        "schema_version": 1,
        "services": [
            {
                "service_id": "checkout-api",
                "owner": "team-checkout",
                "criticality": "high",
                "impact_reason": "handles checkout",
            }
        ],
        "deployables": [{"service_id": "checkout-api", "deployable_id": "web"}],
    }


def test_registration_document_uses_domain_validation() -> None:
    batch = parse_asset_registration(registration())
    assert batch.deployables[0].project_name == "checkout-api/web"

    invalid = registration()
    invalid["services"] = [
        {
            "service_id": "Checkout API",
            "owner": "team-checkout",
            "criticality": "high",
            "impact_reason": "handles checkout",
        }
    ]
    with pytest.raises(ValueError, match="lowercase identifier"):
        parse_asset_registration(invalid)


@pytest.mark.parametrize(
    "change, error",
    [
        ({"schema_version": True}, "schema_version must be 1"),
        ({"deployment_reports": []}, "must contain exactly"),
        ({"services": []}, "provide 1-1000 services"),
        (
            {"deployables": [{"service_id": "unknown", "deployable_id": "web"}]},
            "outside this batch",
        ),
    ],
)
def test_registration_rejects_unsupported_or_incomplete_input(
    change: dict[str, object], error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        parse_asset_registration(registration() | change)


def test_loader_rejects_duplicate_json_keys_and_oversize(tmp_path) -> None:
    source = tmp_path / "registration.json"
    source.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_asset_registration(source)
    source.write_bytes(b" " * (1_048_576 + 1))
    with pytest.raises(ValueError, match="exceeds 1 MiB"):
        load_asset_registration(source)


def test_cli_preview_apply_and_atomic_rollback(tmp_path, capsys) -> None:
    source = tmp_path / "registration.json"
    source.write_text(json.dumps(registration()), encoding="utf-8")
    db_path = tmp_path / "assets.sqlite3"
    parser = cli.build_parser()

    def run(*tokens: str) -> str:
        args = parser.parse_args(
            ["assets", "--db", str(db_path), "import", "--file", str(source), *tokens]
        )
        assert cli.run_assets(args) == 0
        return capsys.readouterr().out

    assert "preview only" in run()
    assert not db_path.exists()
    assert "asset registration applied" in run("--apply")
    with AssetRegistry(db_path, read_only=True) as registry:
        assert [item.service_id for item in registry.list_services()] == [
            "checkout-api"
        ]
        assert [item.project_name for item in registry.list_deployables()] == [
            "checkout-api/web"
        ]

    second = registration()
    second["services"] = [
        {
            "service_id": "new-service",
            "owner": "team-new",
            "criticality": "standard",
            "impact_reason": "test",
        },
        registration()["services"][0],
    ]
    second["deployables"] = [{"service_id": "new-service", "deployable_id": "worker"}]
    source.write_text(json.dumps(second), encoding="utf-8")
    args = parser.parse_args(
        [
            "assets",
            "--db",
            str(db_path),
            "import",
            "--file",
            str(source),
            "--apply",
        ]
    )
    with pytest.raises(ValueError, match="conflicts with existing"):
        cli.run_assets(args)
    with AssetRegistry(db_path, read_only=True) as registry:
        assert [item.service_id for item in registry.list_services()] == [
            "checkout-api"
        ]
        assert [item.project_name for item in registry.list_deployables()] == [
            "checkout-api/web"
        ]
