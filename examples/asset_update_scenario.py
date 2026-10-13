"""Exercise the real local asset CLI in a disposable DB, without network access."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from asset_scenario import FictionalDependencyTrack

from sbom_ops.cli import build_parser, run_assets
from sbom_ops.domain.asset_registry import AssetRegistrySnapshot
from sbom_ops.services.asset_registry import (
    approve_project_link,
    observe_registry_projects,
)
from sbom_ops.storage.asset_registry import AssetRegistry


def main() -> int:
    parser = build_parser()
    with TemporaryDirectory(prefix="sbom-ops-asset-update-") as directory:
        path = Path(directory) / "assets.sqlite3"

        def run(*arguments: str) -> None:
            args = parser.parse_args(["assets", "--db", str(path), *arguments])
            if run_assets(args) != 0:
                raise RuntimeError("asset update example failed")

        print("架空の担当変更演習: 外部通信なし。一時DBだけを使います。")
        run(
            "import",
            "--file",
            str(Path(__file__).with_name("asset-registration.example.json")),
            "--apply",
        )
        arguments = (
            "update-service",
            "--service",
            "checkout-api",
            "--owner",
            "team-payments",
            "--criticality",
            "critical",
            "--impact-reason",
            "決済停止が全店舗に影響",
            "--actor",
            "fictional-operator",
            "--reason",
            "架空の組織変更・影響範囲の見直し",
        )
        print("\n1. 変更前後を確認（まだ保存しない）")
        run(*arguments)
        with AssetRegistry(path, read_only=True) as registry:
            assert registry.get_service("checkout-api").owner == "team-checkout"
            assert registry.list_service_changes("checkout-api") == ()
        print("\n2. 確認した変更を保存")
        run(*arguments, "--apply")
        print("\n3. 履歴で変更者・理由・変更前後を確認")
        run("history", "--service", "checkout-api")
        with AssetRegistry(path, read_only=True) as registry:
            assert registry.get_service("checkout-api").owner == "team-payments"
            assert len(registry.list_service_changes("checkout-api")) == 1
        projects = FictionalDependencyTrack(
            Path(__file__).with_name("review-scenario.example.json")
        ).list_projects()
        project = projects[0]

        def approve() -> None:
            with AssetRegistry(path) as registry:
                approve_project_link(
                    registry,
                    projects,
                    service_id="checkout-api",
                    deployable_id="web",
                    project_uuid=project.uuid,
                    reviewer="fictional-operator",
                )

        def show_context(expected: str) -> None:
            with AssetRegistry(path, read_only=True) as registry:
                data = AssetRegistrySnapshot(
                    registry.list_services(),
                    registry.list_links(),
                    registry.list_deployment_reports(),
                    **registry.lifecycle_state(),
                )
                observed = observe_registry_projects(data, projects, (project,))[0]
                assert observed.status.value == expected
                print(
                    f"Projectの資産対応={observed.status.value} "
                    f"担当={observed.owner or '不明'}"
                )

        print("\n4. 架空のDTデータを使って紐付け承認 → 撤回 → 再承認")
        approve()
        show_context("matched")
        revoke = (
            "revoke-link",
            "--project",
            project.uuid,
            "--actor",
            "fictional-operator",
            "--reason",
            "架空の誤紐付けを見直し",
        )
        run(*revoke)
        show_context("matched")
        run(*revoke, "--apply")
        show_context("revoked")
        approve()
        show_context("matched")
        print("\n5. 配布単位・サービスを廃止（実停止や脆弱性解消ではない）")
        for command, extra in (
            ("retire-deployable", ("--deployable", "web")),
            ("retire-service", ()),
        ):
            arguments = (
                command,
                "--service",
                "checkout-api",
                *extra,
                "--actor",
                "fictional-operator",
                "--reason",
                "架空の台帳廃止",
            )
            run(*arguments)
            run(*arguments, "--apply")
            show_context("retired")
        run("history", "--service", "checkout-api")
    print("演習完了。一時DBは削除済み。既存の台帳・DT・GitHubは変更していません。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
