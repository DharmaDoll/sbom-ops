from __future__ import annotations

import argparse

from sbom_ops.config import AppConfig, load_config
from sbom_ops.services.orchestrator import Orchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sbom-ops")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sync_parser = subparsers.add_parser("sync")
    sync_parser.add_argument("--config")
    sync_parser.add_argument("--project", dest="project_uuid")
    sync_parser.add_argument("--dry-run", action="store_true")
    sync_parser.add_argument("--log-level")

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--config")
    plan_parser.add_argument("--project", dest="project_uuid")
    plan_parser.add_argument("--dry-run", action="store_true")
    plan_parser.add_argument("--log-level")
    return parser


def run_plan(config: AppConfig) -> int:
    print(config)
    return 0


def run_sync(config: AppConfig) -> int:
    orchestrator = Orchestrator(config=config)
    result = orchestrator.run()
    print(result)
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = load_config(args)
    if args.command == "plan":
        return run_plan(config)
    if args.command == "sync":
        return run_sync(config)
    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
