"""Explicit Slack preview/send commands. No DT or GitHub API dependencies."""

import argparse
import json
import os
import sqlite3
from contextlib import nullcontext
from dataclasses import fields
from datetime import UTC, datetime
from pathlib import Path
from time import time
from uuid import uuid4

from sbom_ops.clients.slack import SlackClient
from sbom_ops.domain.slack import SlackPolicy
from sbom_ops.services.lookup_input import read_lookup_document
from sbom_ops.services.sbom_quality_input import read_quality_json
from sbom_ops.services.slack import deliver, journal_report
from sbom_ops.services.slack_input import notifications
from sbom_ops.storage.slack import SlackJournal


def add_slack_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "slack", help="offline notification preview / explicit Slack send"
    )
    actions = parser.add_subparsers(dest="slack_command", required=True)
    for name in ("init", "show", "confirm"):
        command = actions.add_parser(name)
        command.add_argument("--db", required=True)
        if name == "confirm":
            command.add_argument("--intent", required=True)
            command.add_argument("--channel", required=True)
            command.add_argument("--ts", required=True)
            command.add_argument("--actor", required=True)
            command.add_argument("--execute", action="store_true")
    notify = actions.add_parser("notify")
    notify.add_argument("--findings", required=True, help="successful sync JSON")
    notify.add_argument(
        "--observed-at",
        required=True,
        help="actual input observation time, ISO8601 with timezone",
    )
    notify.add_argument(
        "--config", required=True, help="notification JSON config, no credentials"
    )
    notify.add_argument(
        "--db", help="existing persistent Slack journal; optional for preview"
    )
    notify.add_argument("--execute", action="store_true")
    notify.add_argument("--dry-run", action="store_true")
    notify.add_argument(
        "--retry-failed",
        action="store_true",
        help="retry definitive failure only, bounded by policy",
    )
    notify.add_argument("--output", choices=("json", "text"), default="text")


def load_slack_policy(path: str) -> SlackPolicy:
    document, _ = read_quality_json(Path(path), max_bytes=32768, max_depth=8)
    if not isinstance(document, dict) or set(document) - {
        f.name for f in fields(SlackPolicy)
    }:
        raise ValueError(
            "invalid Slack config fields; credentials must use environment"
        )
    for name in ("priorities", "change_fields"):
        if name in document:
            if not isinstance(document[name], list) or any(
                not isinstance(x, str) for x in document[name]
            ):
                raise ValueError("invalid Slack config selection")
            document[name] = tuple(document[name])
    return SlackPolicy(**document)


def run_slack(args: argparse.Namespace) -> int:
    run_id = str(uuid4())
    try:
        if args.slack_command == "init":
            SlackJournal.initialize(args.db)
            print(json.dumps({"status": "initialized"}))
            return 0
        if args.slack_command == "show":
            with SlackJournal(args.db, read_only=True) as journal:
                print(json.dumps(journal_report(journal), ensure_ascii=False))
            return 0
        if args.slack_command == "confirm":
            with SlackJournal(args.db, read_only=not args.execute) as journal:
                matching = [
                    r
                    for r in journal.records()
                    if r.intent_id == args.intent
                    and r.channel == args.channel
                    and r.state in ("pending", "unknown")
                ]
                if len(matching) != 1:
                    raise ValueError("unconfirmed intent/channel not found")
                if args.execute:
                    journal.finish(
                        args.intent,
                        state="confirmed",
                        now=time(),
                        ts=args.ts,
                        actor=args.actor,
                    )
                print(
                    json.dumps(
                        {
                            "status": "confirmed" if args.execute else "preview",
                            "intent_id": args.intent,
                        }
                    )
                )
            return 0
        policy = load_slack_policy(args.config)
        document = read_lookup_document(Path(args.findings))
        items = notifications(
            document, policy, observed_at=args.observed_at, now=datetime.now(UTC)
        )
        writing = args.execute and policy.enabled and not args.dry_run
        if writing and (
            not args.db
            or policy.channel == "C00000000"
            or any(
                ".invalid" in x
                for x in (policy.dt_url, policy.report_url, policy.record_url)
            )
        ):
            raise ValueError(
                "sending requires reviewed destination/references and persistent DB"
            )
        sender = SlackClient(os.environ.get(policy.token_env, "")) if writing else None
        context = (
            SlackJournal(args.db, read_only=not writing)
            if args.db
            else nullcontext(None)
        )
        with context as journal:
            result = deliver(
                items,
                policy,
                journal=journal,
                sender=sender,
                execute=args.execute,
                dry_run=args.dry_run,
                retry_failed=args.retry_failed,
                run_id=run_id,
            )
        if args.output == "json":
            print(json.dumps(result, ensure_ascii=False))
        else:
            print(
                f"Slack {result['mode']}: {len(items)}候補 / "
                f"{result['attempted']}送信試行 / {result['status']}"
            )
            for row in result["notifications"]:
                print(
                    f"\n--- {row['reason']} / {row['state']} / "
                    f"{row['channel']} ---\n{row['text']}"
                )
                if row.get("ts"):
                    print(f"Slack参照: channel={row['channel']} ts={row['ts']}")
            if not items:
                print("通知対象なし。脆弱性の解消・修正完了を意味しません。")
        return 2 if result["status"] == "stopped" else 0
    except (
        OSError,
        sqlite3.Error,
        ValueError,
        TypeError,
        KeyError,
        KeyboardInterrupt,
    ) as exc:
        # Never render raw exceptions: providers and input paths may contain secrets.
        print(
            json.dumps(
                {
                    "status": "failed",
                    "kind": "processing_error",
                    "run_id": run_id,
                    "error_type": type(exc).__name__,
                    "action": (
                        "送信停止。slack showで台帳を確認。"
                        "不明結果を再送せず運用ガイドに従う。"
                    ),
                },
                ensure_ascii=False,
            )
        )
        return 130 if isinstance(exc, KeyboardInterrupt) else 2
