"""CLI presentation for lifecycle evidence."""

import argparse
import json
import sqlite3
import sys

from sbom_ops.domain.lifecycle_evidence import RecordedEvidence, serialize_evidence
from sbom_ops.services.lifecycle_evidence import (
    evidence_history,
    load_evidence,
    register_evidence,
)


def _record(record: RecordedEvidence) -> dict[str, object]:
    return {
        "record_id": record.record_id,
        "recorded_at": record.recorded_at.isoformat(),
        "evidence": json.loads(serialize_evidence(record.evidence)),
    }


def run_evidence(args: argparse.Namespace) -> int:
    try:
        result: dict[str, object]
        if args.asset_command == "evidence-register":
            item = load_evidence(args.file)
            saved = register_evidence(args.db, item, apply=args.apply)
            result = {
                "status": "applied" if saved else "preview",
                "evidence": json.loads(serialize_evidence(item)),
            }
            if saved is not None:
                result.update(_record(saved))
        else:
            records = evidence_history(args.db, args.service, args.deployable)
            result = {
                "service_id": args.service,
                "deployable_id": args.deployable,
                "records": [_record(record) for record in records],
            }
    except (OSError, ValueError, sqlite3.Error, TypeError):
        print(
            "根拠情報の処理に失敗しました。入力・資産登録・DB版・履歴を確認してください。",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def print_evidence_review(status: str, views: tuple[dict[str, object], ...]) -> None:
    labels = {
        "not_requested": "台帳未指定",
        "migration_required": "台帳の明示移行が必要",
        "invalid": "読取・整合性確認に失敗（根拠なしとは判断できません）",
        "loaded": "読取済み",
    }
    states = {
        "matched": "成果物との対応が一致",
        "asset_link_unverified": "資産との紐付け未確認",
        "different_asset": "別の資産",
        "different_artifact": "別の成果物",
        "not_build": "Build根拠ではありません",
        "future": "未来日時・確認が必要",
        "observation_unknown": "観測日時不明・確認が必要",
        "superseded": "訂正前の履歴",
        "multiple_candidates": "独立した候補が複数・自動選択しません",
    }
    print(f"\nSBOM根拠: {labels.get(status, '不明')}")
    if status != "loaded":
        return
    print("成果物との対応だけを示し、実稼働・署名・完全性を保証しません。")
    for view in views:
        print(f"  Project={view['project_uuid']} 紐付け状態={view['project_status']}")
        if not view["records"]:
            print("    表示できる根拠記録なし（影響なしの意味ではありません）")
        for record in view["records"]:
            item = record["evidence"]
            print(
                f"    根拠ID={record['record_id']} "
                f"状態={states.get(record['status'], '不明')} "
                f"種別={item['kind']} 成果物={item.get('artifact_id') or '不明'}"
            )
            print(f"      元SBOM={item['sbom_ref']}")
