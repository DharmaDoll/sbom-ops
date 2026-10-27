"""Explicit advisory commands; offline review never fetches or writes."""

import argparse
import json
import sqlite3
import sys
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sbom_ops.clients.advisory_feed import AdvisoryFeedClient
from sbom_ops.domain.advisory_poll import poll_view
from sbom_ops.domain.poc import PocRunBusy
from sbom_ops.services.advisory_feed_parser import parse_advisory_feed
from sbom_ops.services.advisory_history import advisory_history
from sbom_ops.services.advisory_refresh import refresh_advisories
from sbom_ops.services.advisory_review import review_advisories, review_saved_advisories
from sbom_ops.storage.advisory_feed import AdvisoryFeedStore
from sbom_ops.storage.run_lock import exclusive_run


def add_advisory_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("advisories", help="速報から関連資産を確認")
    commands = parser.add_subparsers(dest="advisory_command", required=True)
    review = commands.add_parser("review-file", help="保存したRSSを通信なしで照合")
    review.add_argument("--feed", required=True)
    review.add_argument("--source", choices=("jpcert", "ubuntu"), required=True)
    review.add_argument("--findings", required=True)
    review.add_argument("--output", choices=("review", "json"), default="review")
    refresh = commands.add_parser("refresh", help="公式RSSを明示取得して既存DBへ保存")
    refresh.add_argument("--db", required=True)
    refresh.add_argument("--source", choices=("jpcert", "ubuntu"), required=True)
    refresh.add_argument("--interval-seconds", type=int, default=3600)
    refresh.add_argument("--execute", action="store_true")
    refresh.add_argument("--output", choices=("review", "json"), default="review")
    listing = commands.add_parser("list", help="保存済み速報の最新の版を読む")
    listing.add_argument("--db", required=True)
    listing.add_argument("--source", choices=("jpcert", "ubuntu"), required=True)
    listing.add_argument("--after-id", type=int, default=0)
    listing.add_argument("--limit", type=int, default=100)
    listing.add_argument("--max-age-seconds", type=int, default=3600)
    listing.add_argument("--output", choices=("review", "json"), default="review")
    saved = commands.add_parser("review", help="SQLiteに保存済みの速報を資産へ照合")
    saved.add_argument("--db", required=True)
    saved.add_argument("--source", choices=("jpcert", "ubuntu"), required=True)
    saved.add_argument("--findings", required=True)
    saved.add_argument("--after-id", type=int, default=0)
    saved.add_argument("--limit", type=int, default=100)
    saved.add_argument("--max-age-seconds", type=int, default=3600)
    saved.add_argument("--output", choices=("review", "json"), default="review")
    history = commands.add_parser("history", help="記事の保存履歴と変更項目を確認")
    history.add_argument("--db", required=True)
    history.add_argument("--source", choices=("jpcert", "ubuntu"), required=True)
    history.add_argument("--item-key", required=True)
    history.add_argument("--output", choices=("review", "json"), default="review")


def run_advisories(args: argparse.Namespace) -> int:
    if args.advisory_command == "refresh":
        return _run_refresh(args)
    if args.advisory_command == "list":
        return _run_list(args)
    if args.advisory_command == "history":
        return _run_history(args)
    try:
        if args.advisory_command == "review":
            result = review_saved_advisories(
                Path(args.db),
                Path(args.findings),
                source_id=args.source,
                after_id=args.after_id,
                limit=args.limit,
                max_age=timedelta(seconds=args.max_age_seconds),
            )
        else:
            path = Path(args.feed)
            if not path.is_file():
                raise ValueError("feed must be a regular file")
            with path.open("rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            items = parse_advisory_feed(raw, source_id=args.source)
            result = review_advisories(items, Path(args.findings))
    except (ValueError, TypeError, KeyError, OSError, sqlite3.Error, OverflowError):
        print(
            "速報の照合に失敗しました。RSS/DBと成功したsyncのJSONを確認してください。",
            file=sys.stderr,
        )
        return 2
    if args.output == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("速報の確認（外部通信・DB書込なし）")
        print("元run: " + json.dumps(result["source_run_id"], ensure_ascii=False))
        if "poll" in result:
            print("取得状態・鮮度: " + json.dumps(result["poll"], ensure_ascii=False))
        for warning in result["warnings"]:
            print(warning)
        for entry in result["articles"]:
            article = entry["article"]
            print(
                "\n記事: "
                + json.dumps(
                    {key: article[key] for key in ("source_id", "title", "url")},
                    ensure_ascii=False,
                )
            )
            if not entry["cves"]:
                print("CVE未取得: 原文を確認してください。")
            if "record_id" in entry:
                print(
                    "保存記録: "
                    + json.dumps(
                        {
                            key: entry[key]
                            for key in ("record_id", "first_seen_at", "last_seen_at")
                        },
                        ensure_ascii=False,
                    )
                )
            for cve in entry["cves"]:
                lookup = result["lookups"][cve]
                print(
                    cve
                    + ": "
                    + (
                        "一致あり"
                        if lookup["results"]
                        else "検索範囲内で一致なし（影響なしではありません）"
                    )
                )
                for match in lookup["results"]:
                    print(
                        "資産・担当・配置・元Finding: "
                        + json.dumps(match, ensure_ascii=False)
                    )
        if result.get("next_after_id") is not None:
            print(f"続き: --after-id {result['next_after_id']}（空なら終了）")
    return 0


def _run_refresh(args: argparse.Namespace) -> int:
    try:
        if args.interval_seconds <= 0:
            raise ValueError("interval must be positive")
        interval = timedelta(seconds=args.interval_seconds)
        now = datetime.now(UTC)
        article_count = 0
        with AdvisoryFeedStore(args.db, read_only=not args.execute) as store:
            if args.execute:
                lock = Path(str(Path(args.db).resolve()) + ".advisories.lock")
                with exclusive_run(lock):
                    outcome = refresh_advisories(
                        store,
                        AdvisoryFeedClient(),
                        source_id=args.source,
                        now=now,
                        interval=interval,
                    )
                state = outcome.state
                status = outcome.status
                article_count = len(outcome.items)
            else:
                state = store.poll_state(args.source)
                status = "preview"
        serialized = (
            None
            if state is None
            else {
                key: value.isoformat() if isinstance(value, datetime) else value
                for key, value in asdict(state).items()
            }
        )
        result = {
            "status": status,
            "source_id": args.source,
            "execute": args.execute,
            "interval_seconds": args.interval_seconds,
            "due": state is None or state.due(now),
            "freshness": "unknown" if state is None else state.freshness(now, interval),
            "state": serialized,
            "article_count": article_count,
            "warnings": ["取得成功は速報の網羅や資産への影響を保証しません。"],
        }
    except (ValueError, TypeError, OSError, sqlite3.Error, OverflowError, PocRunBusy):
        print(
            "速報の取得処理を実行できません。DBの移行・取得間隔・他の実行を確認してください。",
            file=sys.stderr,
        )
        return 2
    if args.output == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(
            "速報取得: "
            + {
                "preview": "予定の確認のみ（通信・書込なし）",
                "not_due": "再取得待ち",
                "succeeded": "成功",
                "failed": "失敗（過去の成功情報は保持）",
            }[status]
        )
        print("取得状態: " + json.dumps(result, ensure_ascii=False))
    return 2 if status == "failed" else 0


def _run_list(args: argparse.Namespace) -> int:
    try:
        with AdvisoryFeedStore(args.db, read_only=True) as store:
            rows, state = store.latest_with_state(
                args.source, after_id=args.after_id, limit=args.limit
            )
        result = {
            "source_id": args.source,
            "scope": "latest_saved_revision_per_article",
            "articles": rows,
            "poll": poll_view(
                state,
                now=datetime.now(UTC),
                max_age=timedelta(seconds=args.max_age_seconds),
            ),
            "next_after_id": rows[-1]["record_id"] if len(rows) == args.limit else None,
            "warnings": [
                "保存済みの最新の版です。配信元の全記事を網羅するとは限りません。",
                "ページ間の更新は固定しません。訂正された記事が後のページに再登場する場合があります。",
            ],
        }
    except (ValueError, TypeError, OSError, sqlite3.Error, OverflowError):
        print(
            "保存済み速報を読めません。DBの移行・内容・ページ指定を確認してください。",
            file=sys.stderr,
        )
        return 2
    if args.output == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"保存済み速報: {len(rows)}件（通信・書込なし）")
        print("取得状態・鮮度: " + json.dumps(result["poll"], ensure_ascii=False))
        for warning in result["warnings"]:
            print(warning)
        for row in rows:
            print(json.dumps(row, ensure_ascii=False))
        if result["next_after_id"] is not None:
            print(f"続き: --after-id {result['next_after_id']}（空なら終了）")
    return 0


def _run_history(args: argparse.Namespace) -> int:
    try:
        result = advisory_history(
            Path(args.db), source_id=args.source, item_key=args.item_key
        )
    except (ValueError, TypeError, OSError, sqlite3.Error):
        print(
            "速報の履歴を読めません。DBと記事識別子を確認してください。",
            file=sys.stderr,
        )
        return 2
    if args.output == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"記事の保存履歴: {len(result['revisions'])}件（通信・書込なし）")
        for warning in result["warnings"]:
            print(warning)
        for revision in result["revisions"]:
            print(json.dumps(revision, ensure_ascii=False))
    return 0
