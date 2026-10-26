"""CLI for offline reverse lookup; no configuration or external clients."""

import argparse
import json
import sys
from pathlib import Path

from sbom_ops.domain.lookup import LookupQuery
from sbom_ops.services.lookup import lookup_file


def add_lookup_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("lookup", help="search a saved sync JSON offline")
    parser.add_argument("--findings", required=True)
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--cve")
    selector.add_argument("--vulnerability-id")
    selector.add_argument("--purl")
    parser.add_argument("--source", help="required with --vulnerability-id only")
    parser.add_argument("--output", choices=("review", "json"), default="review")


def run_lookup(args: argparse.Namespace) -> int:
    try:
        kind, value = (
            ("cve", args.cve)
            if args.cve is not None
            else (
                ("purl", args.purl)
                if args.purl is not None
                else ("vulnerability", args.vulnerability_id)
            )
        )
        result = lookup_file(Path(args.findings), LookupQuery(kind, value, args.source))
    except (ValueError, TypeError, KeyError, OSError):
        print(
            "逆引きに失敗しました。検索条件と成功したsyncの入力JSONを確認してください。",
            file=sys.stderr,
        )
        return 2
    if args.output == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"保存済み結果の逆引き: {result['matched_finding_count']}件")
        print("元run: " + json.dumps(result["source_run_id"], ensure_ascii=False))
        for warning in result["warnings"]:
            print(warning)
        for item in result["results"]:
            row = item["finding"]
            print(
                "\nFinding: "
                + json.dumps(
                    {
                        key: row[key]
                        for key in (
                            "finding_key",
                            "project_uuid",
                            "vulnerability_id",
                            "vulnerability_source",
                            "component_purl",
                        )
                    },
                    ensure_ascii=False,
                )
            )
            print("資産・担当: " + json.dumps(row["asset"], ensure_ascii=False))
            print("紐付け状態: " + json.dumps(row["asset_status"], ensure_ascii=False))
            print("配置申告: " + json.dumps(row["environments"], ensure_ascii=False))
            print(
                "SBOM根拠状態: "
                + json.dumps(item["lifecycle_evidence_status"], ensure_ascii=False)
            )
            print(
                "SBOM根拠: "
                + json.dumps(item["lifecycle_evidence"], ensure_ascii=False)
            )
    return 0
