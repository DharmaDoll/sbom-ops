"""Read an explicit, bounded quality policy without runtime credentials."""

from pathlib import Path

from sbom_ops.domain.sbom_quality_input import QualityInputError
from sbom_ops.domain.sbom_quality_report import QualityPolicy, parse_quality_policy
from sbom_ops.services.sbom_quality_input import read_quality_json


def load_quality_policy(path: Path) -> QualityPolicy:
    try:
        document, _ = read_quality_json(path, max_bytes=32 * 1024, max_depth=8)
    except QualityInputError as exc:
        raise QualityInputError(f"policy_{exc.code}") from None
    try:
        return parse_quality_policy(document)
    except ValueError:
        raise QualityInputError("invalid_policy") from None
