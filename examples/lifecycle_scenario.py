"""Offline lifecycle exercise using saved fictional evidence and a disposable DB."""

from __future__ import annotations

import argparse
import io
import json
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from sbom_ops.cli import build_parser, run_assets
from sbom_ops.clients.dependency_track import DependencyTrackProject
from sbom_ops.domain.asset_registry import AssetRegistrySnapshot
from sbom_ops.services.asset_registry import (
    approve_project_link,
    observe_registry_deployments,
    observe_registry_projects,
)
from sbom_ops.services.lifecycle_evidence import (
    evidence_history,
    project_evidence_views,
)
from sbom_ops.storage.asset_registry import AssetRegistry


def run_scenario() -> dict[str, Any]:
    """Use product CLI/storage/joins; never instantiate an external API client."""
    examples = Path(__file__).parent
    parser = build_parser()
    stages: list[dict[str, Any]] = []
    projects = tuple(
        DependencyTrackProject(f"fictional-{version}", "checkout-api/web", version)
        for version in ("build-a", "build-b")
    )
    clock = datetime.now(UTC)
    with TemporaryDirectory(prefix="sbom-ops-lifecycle-") as directory:
        db = Path(directory) / "assets.sqlite3"

        def run(*arguments: str) -> None:
            args = parser.parse_args(["assets", "--db", str(db), *arguments])
            with redirect_stdout(io.StringIO()):
                if run_assets(args) != 0:
                    raise RuntimeError("local lifecycle exercise failed")

        def show(name: str, *, expired: bool = False) -> None:
            now = datetime.now(UTC) + (timedelta(days=3) if expired else timedelta())
            with AssetRegistry(db, read_only=True) as registry:
                snapshot = AssetRegistrySnapshot(
                    registry.list_services(),
                    registry.list_links(),
                    registry.list_deployment_reports(),
                    **registry.lifecycle_state(),
                )
            observed = observe_registry_projects(snapshot, projects, projects)
            status, views = project_evidence_views(db, observed, now=now)
            stages.append(
                {
                    "name": name,
                    "projects": [item.as_dict() for item in observed],
                    "deployments": [
                        item.as_dict()
                        for item in observe_registry_deployments(
                            snapshot, observed, now=now
                        )
                    ],
                    "evidence_status": status,
                    "evidence": views,
                }
            )

        def report(
            artifact: str,
            environment: str,
            status: str = "deployed",
            *,
            supersedes: int | None = None,
        ) -> None:
            run(
                "report-deployment",
                "--service",
                "checkout-api",
                "--deployable",
                "web",
                "--artifact",
                artifact,
                "--environment",
                environment,
                "--status",
                status,
                "--exposure",
                "unknown",
                "--reviewer",
                "fictional-operator",
                "--evidence",
                "架空の配置申告。実稼働を観測していません。",
                "--observed-at",
                (clock - timedelta(minutes=30 if supersedes else 60)).isoformat(),
                "--expires-at",
                (clock + timedelta(days=1)).isoformat(),
                *(["--supersedes-report", str(supersedes)] if supersedes else []),
            )

        run(
            "import",
            "--file",
            str(examples / "asset-registration.example.json"),
            "--apply",
        )
        for filename in ("source", "build-a", "build-b", "build-a-corrected"):
            args = (
                "evidence-register",
                "--file",
                str(examples / "lifecycle" / f"{filename}.json"),
            )
            before = db.read_bytes()
            run(*args)
            if db.read_bytes() != before:
                raise RuntimeError("preview changed the disposable DB")
            run(*args, "--apply")
        show("unapproved")
        with AssetRegistry(db) as registry:
            for project in projects:
                approve_project_link(
                    registry,
                    projects,
                    service_id="checkout-api",
                    deployable_id="web",
                    project_uuid=project.uuid,
                    reviewer="fictional-operator",
                )
        report("build-a", "production")
        show("old")
        report("build-b", "production")
        show("parallel")
        report("build-a", "staging")
        show("redeployed")
        report("build-a", "production", "not_deployed", supersedes=1)
        show("stopped")
        report("build-b", "production", "not_deployed")
        show("conflict")
        show("expired", expired=True)
        count = len(evidence_history(db, "checkout-api", "web"))
    return {
        "fictional": True,
        "preview_unchanged": True,
        "history_count": count,
        "temporary_db_removed": not db.exists(),
        "stages": stages,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", choices=("review", "json"), default="review")
    args = parser.parse_args()
    result = run_scenario()
    if args.output == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(
            "架空の切替演習: 外部通信なし。一時DBのみ。"
            "実稼働・署名の証明ではありません。"
        )
        labels = {
            "unapproved": "未承認のため配置と結合しない",
            "old": "旧版Aの本番配置",
            "parallel": "新版Bを投入してもAは停止しない（新旧並存）",
            "redeployed": "Aをstagingにも配置（SBOMは複製しない）",
            "stopped": "本番Aの停止を明示。BとstagingのAは稼働申告のまま",
            "conflict": "Bの停止と稼働の申告が矛盾（自動選択しない）",
            "expired": "3日後の読取を模擬。有効期限切れは未確認",
        }
        for stage in result["stages"]:
            print(f"\n{labels[stage['name']]}")
            for row in stage["deployments"]:
                print(
                    f"  {row['artifact_id']}/{row['environment'] or '不明'}: "
                    f"{row['status']} / {row['deployment_status'] or '不明'}"
                )
        print("\n根拠履歴は4件を保持。停止は脆弱性の修正完了ではありません。")
        print("一時DBは削除済み。既存台帳・DT・GitHubは変更していません。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
