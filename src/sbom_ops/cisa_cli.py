"""Explicit CISA input commands, independent of DT and remediation writes."""

import argparse
import json
from datetime import UTC, datetime, timedelta

from sbom_ops.clients.vulnrichment import VulnrichmentClient
from sbom_ops.domain.vulnrichment import VULNRICHMENT_SOURCE, validate_request
from sbom_ops.domain.vulnrichment_snapshot import VulnrichmentSnapshot
from sbom_ops.services.vulnrichment import collect_vulnrichment
from sbom_ops.storage.asset_registry import AssetRegistry
from sbom_ops.storage.vulnrichment import VulnrichmentStore


def add_cisa_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("cisa", help="fetch and inspect CISA input")
    commands = parser.add_subparsers(dest="cisa_command", required=True)
    fetch = commands.add_parser("fetch")
    show = commands.add_parser("show")
    for command in (fetch, show):
        command.add_argument("--db", default="var/assets.sqlite3")
        command.add_argument("--cve", required=True)
        command.add_argument("--revision", required=True)
    fetch.add_argument("--max-age-hours", type=int, required=True)
    fetch.add_argument("--execute", action="store_true")
    show.add_argument("--snapshot", type=int, required=True)


def run_cisa(args: argparse.Namespace) -> int:
    validate_request(args.cve, args.revision)
    if args.cisa_command == "show":
        with VulnrichmentStore(args.db, read_only=True) as store:
            snapshot = store.get(args.snapshot, cve=args.cve, revision=args.revision)
        if snapshot is None:
            raise ValueError("CISA snapshot not found")
        result = describe_snapshot(args.snapshot, snapshot, now=datetime.now(UTC))
        result["status"] = "stored"
    else:
        if args.max_age_hours <= 0:
            raise ValueError("max-age-hours must be positive")
        try:
            age = timedelta(hours=args.max_age_hours)
            datetime.now(UTC) + age
        except OverflowError:
            raise ValueError(
                "max-age-hours is outside the supported date range"
            ) from None
        if not args.execute:
            print(
                json.dumps(
                    {
                        "status": "preview",
                        "cve": args.cve,
                        "revision": args.revision,
                        "source": VULNRICHMENT_SOURCE,
                        "max_age_hours": args.max_age_hours,
                        "latest_verified": False,
                        "db": args.db,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        # Validate/initialize storage before network access; never auto-migrate.
        with AssetRegistry(args.db, create_if_missing=True) as registry:
            if registry.schema_version < 10:
                raise ValueError(
                    "CISA storage requires schema v10; back up and migrate"
                )
        with VulnrichmentStore(args.db) as store:
            key, snapshot = collect_vulnrichment(
                VulnrichmentClient(),
                store,
                cve=args.cve,
                revision=args.revision,
                max_age=age,
                clock=lambda: datetime.now(UTC),
            )
        result = describe_snapshot(key, snapshot, now=datetime.now(UTC))
        result["status"] = "saved"
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def describe_snapshot(
    key: int,
    snapshot: VulnrichmentSnapshot,
    *,
    now: datetime,
) -> dict[str, object]:
    report = snapshot.report()
    return {
        "snapshot_id": key,
        "cve": report.cve,
        "revision": report.revision,
        "source": VULNRICHMENT_SOURCE,
        "latest_verified": False,
        "retrieved_at": report.retrieved_at.isoformat(),
        "assessed_at": report.assessed_at.isoformat() if report.assessed_at else None,
        "evaluated_at": now.isoformat(),
        "max_age_seconds": snapshot.max_age.total_seconds(),
        "exploitation": report.exploitation,
        "reasons": list(report.reasons),
        "observations": [
            {
                **item.as_dict(),
                "effective_status": (
                    "future" if report.retrieved_at > now else item.status_at(now).value
                ),
            }
            for item in report.observations
        ],
        "scope": "single_cve_cisa_input",
        "priority_changed": False,
    }
