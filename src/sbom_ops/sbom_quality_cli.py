"""Offline SBOM quality command, independent of runtime integration config."""

import argparse
import json
from pathlib import Path

from sbom_ops.domain.sbom_quality import QualityField, QualityState
from sbom_ops.domain.sbom_quality_input import QualityInputError, QualityInputLimits
from sbom_ops.domain.sbom_quality_report import (
    EVALUATOR_VERSION,
    REPORT_ONLY,
    QualityPolicy,
    QualityRequirement,
)
from sbom_ops.services.sbom_quality import evaluate_sbom_file
from sbom_ops.services.sbom_quality_policy import load_quality_policy


def add_quality_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "sbom-quality", help="report original SBOM quality offline"
    )
    parser.add_argument("bom_path")
    policy_options = parser.add_mutually_exclusive_group()
    policy_options.add_argument(
        "--policy", type=Path, help="explicit quality policy JSON file"
    )
    policy_options.add_argument(
        "--require",
        action="append",
        default=[],
        choices=[field.value for field in QualityField],
        help="require present for this field; repeat for multiple fields",
    )
    parser.add_argument(
        "--policy-version", help="label explicit requirements (requires --require)"
    )
    defaults = QualityInputLimits()
    for name in ("max_bytes", "max_depth", "max_nodes", "max_components"):
        parser.add_argument(
            f"--{name.replace('_', '-')}", type=int, default=getattr(defaults, name)
        )


def run_quality(args: argparse.Namespace) -> int:
    policy = None
    try:
        limits = QualityInputLimits(
            args.max_bytes, args.max_depth, args.max_nodes, args.max_components
        )
        try:
            if args.policy_version is not None and not args.require:
                raise ValueError("policy version requires explicit requirements")
            policy = (
                QualityPolicy(
                    (
                        args.policy_version
                        if args.policy_version is not None
                        else "cli-required-v1"
                    ),
                    tuple(
                        QualityRequirement(QualityField(name), (QualityState.PRESENT,))
                        for name in args.require
                    ),
                )
                if args.require
                else REPORT_ONLY
            )
        except ValueError:
            raise QualityInputError("invalid_policy") from None
        if args.policy is not None:
            # Never identify a failed explicit policy load as the default policy.
            policy = None
            policy = load_quality_policy(args.policy)
        report = evaluate_sbom_file(Path(args.bom_path), policy=policy, limits=limits)
        exit_code = report["exit_code"]
    except (QualityInputError, OSError, ValueError, KeyboardInterrupt) as exc:
        interrupted = isinstance(exc, KeyboardInterrupt)
        exit_code = 130 if interrupted else 2
        code = (
            exc.code
            if isinstance(exc, QualityInputError)
            else ("interrupted" if interrupted else "evaluation_failed")
        )
        report = {
            "schema_version": 1,
            "evaluator_version": EVALUATOR_VERSION,
            "policy_version": policy.version if policy is not None else None,
            "status": "error",
            "exit_code": exit_code,
            "error": {"code": code},
        }
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return exit_code
