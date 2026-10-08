from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from sbom_ops.config import PriorityConfig
from sbom_ops.domain.advisory import PocReportStatus
from sbom_ops.domain.models import (
    Enrichment,
    Finding,
    FindingAssessment,
    PrioritizedFinding,
    Priority,
    Severity,
)


def prioritize_finding(
    finding: Finding,
    enrichment: Enrichment,
    config: PriorityConfig,
) -> PrioritizedFinding:
    rationale: list[str] = []

    if enrichment.in_kev:
        rationale.append("KEV match")
        return PrioritizedFinding(finding, enrichment, Priority.P0, tuple(rationale))

    if enrichment.has_known_active_exploitation:
        rationale.append("Known active exploitation")
        return PrioritizedFinding(finding, enrichment, Priority.P0, tuple(rationale))

    if finding.severity == Severity.CRITICAL:
        rationale.append("Critical severity")
        return PrioritizedFinding(finding, enrichment, Priority.P1, tuple(rationale))

    if (
        enrichment.epss_score is not None
        and enrichment.epss_score >= config.p1_epss_threshold
    ):
        rationale.append(
            f"EPSS {enrichment.epss_score:.4f} >= {config.p1_epss_threshold:.4f}"
        )
        return PrioritizedFinding(finding, enrichment, Priority.P1, tuple(rationale))

    if (
        finding.cvss_score is not None
        and finding.cvss_score >= config.p2_cvss_threshold
    ):
        cvss_label = finding.cvss_version or "CVSS"
        rationale.append(
            f"{cvss_label} {finding.cvss_score:.1f} >= {config.p2_cvss_threshold:.1f}"
        )
        return PrioritizedFinding(finding, enrichment, Priority.P2, tuple(rationale))

    rationale.append("Default monitoring priority")
    if enrichment.epss_score is None:
        rationale.append("EPSS unavailable")
    else:
        rationale.append(
            f"EPSS {enrichment.epss_score:.4f} < "
            f"{config.p1_epss_threshold:.4f} threshold"
        )

    if finding.cvss_score is None:
        rationale.append(
            "CVSS unavailable; severity label is not used as a score fallback"
        )
    else:
        cvss_label = finding.cvss_version or "CVSS"
        rationale.append(
            f"{cvss_label} {finding.cvss_score:.1f} < "
            f"{config.p2_cvss_threshold:.1f} threshold"
        )
    return PrioritizedFinding(finding, enrichment, Priority.P3, tuple(rationale))


def order_assessments_for_review(
    assessments: Sequence[FindingAssessment],
) -> tuple[FindingAssessment, ...]:
    """Prefer reported PoCs only among otherwise equal risk assessments.

    Keep unrelated assessments and the original DT order in their existing
    positions. This order is for review output, not priority or Issue actions.
    """
    groups: dict[tuple[object, ...], list[FindingAssessment]] = defaultdict(list)
    keys: list[tuple[object, ...]] = []
    for item in assessments:
        key = (
            item.project_uuid,
            item.priority,
            item.in_kev,
            item.severity,
            item.cvss_score,
            item.epss_score,
            item.analysis_state,
            item.is_suppressed,
        )
        keys.append(key)
        groups[key].append(item)
    for values in groups.values():
        values.sort(
            key=lambda item: item.poc_reports.status is not PocReportStatus.REPORTED
        )
    positions = {key: iter(values) for key, values in groups.items()}
    return tuple(next(positions[key]) for key in keys)
