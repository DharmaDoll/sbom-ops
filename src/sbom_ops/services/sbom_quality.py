"""Offline original-file quality evaluation; no inventory or workflow writes."""

from pathlib import Path

from sbom_ops.domain.sbom_quality_components import evaluate_components
from sbom_ops.domain.sbom_quality_document import evaluate_document
from sbom_ops.domain.sbom_quality_input import QualityInputLimits
from sbom_ops.domain.sbom_quality_report import (
    REPORT_ONLY,
    QualityPolicy,
    build_quality_report,
)
from sbom_ops.services.sbom_quality_input import DEFAULT_LIMITS, read_quality_input


def evaluate_sbom_file(
    path: Path,
    *,
    policy: QualityPolicy = REPORT_ONLY,
    limits: QualityInputLimits = DEFAULT_LIMITS,
) -> dict[str, object]:
    source = read_quality_input(path, limits=limits)
    checks = evaluate_document(source.document) + evaluate_components(source)
    return build_quality_report(source, checks, policy=policy)
