"""Offline PoC acquisition example. All responses below are fictional."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from sbom_ops.domain.advisory import summarize_poc_reports
from sbom_ops.domain.identifier_candidates import (
    IdentifierTarget,
    interpret_osv_candidates,
)
from sbom_ops.domain.models import AnalysisState, FindingAssessment, Priority, Severity
from sbom_ops.domain.poc import PocFetchError, select_poc_targets
from sbom_ops.services.advisory_snapshot import load_advisory_snapshot
from sbom_ops.services.identifier_review import (
    list_identifier_reviews,
    review_identifier,
)
from sbom_ops.services.poc_identity import (
    attach_reviewed_poc,
    select_reviewed_poc_targets,
)
from sbom_ops.services.poc_refresh import collect_poc_snapshot
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.identifier_candidates import IdentifierStore
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
    unresolved = select_poc_targets(
        {
            "status": "succeeded",
            "assessments": [
                {"vulnerability_id": "GO-2026-10001", "vulnerability_aliases": []}
            ],
        },
        max_cves=25,
    )
    assert unresolved.summary()["status"] == "no_resolvable_cves"
    print("CVE対応なし: 脆弱性は1件、取得対象CVEは0件。PoCなしとは判断しません。")
    with TemporaryDirectory(prefix="sbom-ops-poc-") as directory:
        db_path = Path(directory) / "assets.sqlite3"
        with AssetRegistry(db_path, create_if_missing=True):
            pass
        candidate = interpret_osv_candidates(
            IdentifierTarget("GO-2026-10001", ("OSV",)),
            {
                "id": "GO-2026-10001",
                "modified": NOW.isoformat(),
                "aliases": ["CVE-2026-10001"],
            },
            observed_at=NOW,
        )
        with IdentifierStore(db_path) as candidates:
            candidates.save(candidate)
            assert candidates.recent()[0]["approved"] is False
        print(
            "架空のCVE候補をSQLiteへ保存。未採用のためPoC紐付け・優先度は変更しません。"
        )
        with IdentifierStore(db_path) as candidates:
            decision = dict(
                observation_id=1,
                dt_source="OSV",
                cve="CVE-2026-10001",
                actor="fictional-operator",
                reason="架空の操作演習",
                now=NOW,
            )
            review_identifier(
                candidates,
                **decision,
                action="approve",
                expires_at=(NOW + timedelta(hours=1)).isoformat(),
                execute=True,
            )
            assert (
                list_identifier_reviews(candidates, now=NOW)[0]["effective_status"]
                == "active"
            )
            assert (
                list_identifier_reviews(candidates, now=NOW + timedelta(hours=1))[0][
                    "effective_status"
                ]
                == "expired"
            )
            mapped_targets, mappings = select_reviewed_poc_targets(
                {
                    "status": "succeeded",
                    "assessments": [
                        {
                            "vulnerability_id": "GO-2026-10001",
                            "vulnerability_source": "OSV",
                        }
                    ],
                },
                candidates,
                max_cves=25,
                now=NOW,
            )
            assert mapped_targets.cves == ("CVE-2026-10001",)
            with PocStore(db_path) as pocs:
                collect_poc_snapshot(
                    mapped_targets,
                    FictionalPocSource(),
                    repository=pocs,
                    clock=lambda: NOW,
                )
                mapped_snapshot = pocs.snapshot()
            finding = FindingAssessment(
                "fictional-project",
                "fictional-finding",
                "GO-2026-10001",
                "OSV",
                Severity.HIGH,
                8.0,
                None,
                Priority.P2,
                AnalysisState.NOT_SET,
                False,
                ("架空の評価理由",),
            )
            projected = attach_reviewed_poc(
                (finding,), mapped_snapshot, candidates, now=NOW
            )[0]
            assert (
                summarize_poc_reports(
                    projected.reviewed_poc_observations, now=NOW
                ).status.value
                == "reported"
            )
            assert (
                projected.vulnerability_aliases == ()
                and projected.priority == Priority.P2
            )
            expired = attach_reviewed_poc(
                (finding,), mapped_snapshot, candidates, now=NOW + timedelta(hours=1)
            )[0]
            assert expired.reviewed_poc_observations == ()
            review_identifier(
                candidates, **decision, action="revoke", expires_at=None, execute=True
            )
            assert (
                list_identifier_reviews(candidates, now=NOW)[0]["effective_status"]
                == "revoked"
            )
            revoked = attach_reviewed_poc(
                (finding,), mapped_snapshot, candidates, now=NOW
            )[0]
            assert revoked.poc_reports.status.value == "unknown"
        print(
            "架空の対応を期限付き採用→PoC報告2件を表示→期限切れ・取消後は不明。優先度は不変。"
        )
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
        with PocStore(db_path) as store:
            waiting = collect_poc_snapshot(
                targets,
                FictionalPocSource(),
                clock=lambda: NOW + timedelta(seconds=61),
                sleep=lambda _: None,
                repository=store,
            )
        assert not any(row["attempted"] for row in waiting["collection"]["results"])
        assert waiting["collection"]["results"][-1]["error"] == "source_cooldown"
        print(
            "再試行の待機中は通信なし。次回可能時刻:",
            waiting["collection"]["source_state"]["retry_at"],
        )
    print("未解決ID:", ", ".join(targets.unresolved))
    print("取得失敗と期限切れは不明。PoCの有効性は評価しません。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
