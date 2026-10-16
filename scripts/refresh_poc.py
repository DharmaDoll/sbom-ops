"""Run one scheduled PoC refresh cycle. Default: print the plan without I/O.

Use an external scheduler to invoke --execute. This script never installs one.
DT is accessed only through the existing read-only sync CLI.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import BinaryIO

from sbom_ops.clients.vulnerability_lookup import DEFAULT_BASE_URL, validate_base_url
from sbom_ops.domain.poc import PocRunBusy, select_poc_targets
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.run_lock import exclusive_run, poc_lock_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--db", default="var/assets.sqlite3")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--max-cves", type=int, default=25)
    parser.add_argument("--refresh-seconds", type=int, default=3600)
    parser.add_argument("--stage-timeout", type=int, default=900)
    parser.add_argument("--execute", action="store_true")
    return parser


def event(stage: str, status: str, *, code: int | None = None) -> None:
    print(
        json.dumps(
            {
                "time": datetime.now(UTC).isoformat(),
                "stage": stage,
                "status": status,
                "exit_code": code,
            }
        ),
        flush=True,
    )


def run_stage(
    stage: str, command: list[str], timeout: int, *, stdout: BinaryIO | None = None
) -> int:
    event(stage, "started")
    try:
        completed = subprocess.run(command, stdout=stdout, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        event(stage, "timeout", code=2)
        return 2
    event(stage, "finished", code=completed.returncode)
    return completed.returncode


def run(args: argparse.Namespace) -> int:
    base_url = validate_base_url(args.base_url)
    if not 1 <= args.max_cves <= 1000 or not 1 <= args.refresh_seconds <= 604800:
        raise ValueError("invalid CVE limit or refresh interval")
    if not 1 <= args.stage_timeout <= 3600:
        raise ValueError("stage-timeout must be between 1 and 3600 seconds")
    if not args.execute:
        print(
            json.dumps(
                {
                    "status": "preview",
                    "project": args.project,
                    "db": args.db,
                    "base_url": base_url,
                    "max_cves": args.max_cves,
                    "refresh_seconds": args.refresh_seconds,
                    "stages": ["sync-targets", "poc-fetch", "review"],
                    "github": False,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    db_path = Path(args.db).resolve()
    if not db_path.is_file():
        raise ValueError("register assets and migrate the DB before running this job")
    if not Path(args.config).is_file():
        raise ValueError("config file does not exist")
    with exclusive_run(poc_lock_path(db_path, job=True)):
        with AssetRegistry(db_path, read_only=True) as registry:
            if registry.schema_version < 7:
                raise ValueError("back up and migrate the DB to v7 before scheduling")
        cli = [sys.executable, "-m", "sbom_ops.cli"]
        sync = cli + [
            "sync",
            "--config",
            args.config,
            "--project",
            args.project,
            "--asset-db",
            str(db_path),
            "--dry-run",
            "--no-github",
        ]
        # A new private input every run: failed sync can never reuse yesterday's list.
        with TemporaryDirectory(prefix="poc-job-", dir=db_path.parent) as directory:
            findings = Path(directory) / "findings.json"
            with findings.open("wb") as stream:
                code = run_stage(
                    "sync-targets",
                    sync + ["--output", "json"],
                    args.stage_timeout,
                    stdout=stream,
                )
            if code != 0:
                return 2
            with findings.open("rb") as stream:
                raw = stream.read(20 * 1024 * 1024 + 1)
            if len(raw) > 20 * 1024 * 1024:
                raise ValueError("sync input exceeds 20 MiB")
            select_poc_targets(json.loads(raw), max_cves=args.max_cves)
            code = run_stage(
                "poc-fetch",
                cli
                + [
                    "poc-fetch",
                    "--findings",
                    str(findings),
                    "--db",
                    str(db_path),
                    "--base-url",
                    base_url,
                    "--max-cves",
                    str(args.max_cves),
                    "--refresh-seconds",
                    str(args.refresh_seconds),
                    "--execute",
                ],
                args.stage_timeout,
            )
            if code not in (0, 1):
                return 3 if code == 3 else 2
            # A partial PoC result must not hide the ordinary DT/asset review.
            review = run_stage(
                "review", sync + ["--output", "review"], args.stage_timeout
            )
            return code if review == 0 else 2


def main() -> int:
    args = build_parser().parse_args()
    try:
        return run(args)
    except PocRunBusy:
        event("job", "busy", code=3)
        return 3
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
