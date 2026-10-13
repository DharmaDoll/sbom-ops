"""Offline PoC acquisition example. All responses below are fictional."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from sbom_ops.domain.advisory import summarize_poc_reports
from sbom_ops.domain.poc import PocFetchError, select_poc_targets
from sbom_ops.services.advisory_snapshot import load_advisory_snapshot
from sbom_ops.services.poc_refresh import collect_poc_snapshot
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.poc import PocStore
from sbom_ops.storage.poc_snapshot import save_poc_snapshot

NOW = datetime(2026, 10, 13, tzinfo=UTC)


class FictionalPocSource:
    source = "fictional-poc-source:not-live-evidence"

    def get_poc_sightings(self, cve: str) -> object:
        if cve == "CVE-2026-10003":
            raise PocFetchError("transport_error")
        count = 2 if cve == "CVE-2026-10001" else 0
        return {
            "metadata": {"count": count, "page": 1, "per_page": 1},
            "data": (
                [
                    {
                        "vulnerability": cve,
                        "type": "published-proof-of-concept",
                        "creation_timestamp": NOW.isoformat(),
                    }
                ]
                if count
                else []
            ),
        }


def main() -> int:
    targets = select_poc_targets(
        {
            "status": "succeeded",
            "assessments": [
                {"vulnerability_id": identifier, "vulnerability_aliases": []}
                for identifier in (
                    "CVE-2026-10001",
                    "CVE-2026-10002",
                    "CVE-2026-10003",
                    "GHSA-unresolved",
                )
            ],
        },
        max_cves=25,
    )
    print("架空のPoC取得演習: 外部通信なし。一時ファイルだけを使います。")
    with TemporaryDirectory(prefix="sbom-ops-poc-") as directory:
        db_path = Path(directory) / "assets.sqlite3"
        with AssetRegistry(db_path, create_if_missing=True):
            pass
        with PocStore(db_path) as store:
            snapshot = collect_poc_snapshot(
                targets,
                FictionalPocSource(),
                clock=lambda: NOW,
                sleep=lambda _: None,
                repository=store,
            )
        # JSON is an optional export; the ordinary read path below uses SQLite.
        path = Path(directory) / "poc.json"
        save_poc_snapshot(path, snapshot)
        with PocStore(db_path, read_only=True) as store:
            loaded = store.snapshot()
        assert (
            loaded.vulnerability_observations
            == load_advisory_snapshot(path).vulnerability_observations
        )
        for observation in loaded.vulnerability_observations:
            fresh = summarize_poc_reports((observation,), now=NOW)
            expired = summarize_poc_reports(
                (observation,), now=NOW + timedelta(hours=6)
            )
            print(
                f"{observation.vulnerability_id}: 取得時={fresh.status.value} "
                f"件数={observation.record_count} 6時間後={expired.status.value}"
            )
        assert [o.outcome.value for o in loaded.vulnerability_observations] == [
            "available",
            "not_observed",
            "unknown",
        ]
        with PocStore(db_path) as store:
            resumed = collect_poc_snapshot(
                targets,
                FictionalPocSource(),
                clock=lambda: NOW + timedelta(minutes=1),
                sleep=lambda _: None,
                repository=store,
            )
        assert sum(row["cached"] for row in resumed["collection"]["results"]) == 2
        print("SQLiteから再読込済み。再実行で成功済み2件の取得を省略。")
    print("未解決ID:", ", ".join(targets.unresolved))
    print("取得失敗と期限切れは不明。PoCの有効性は評価しません。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
