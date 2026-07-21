from __future__ import annotations

from sbom_ops.config import PriorityConfig
from sbom_ops.domain.models import (
    Enrichment,
    Finding,
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
        rationale.append(
            f"CVSS {finding.cvss_score:.1f} >= {config.p2_cvss_threshold:.1f}"
        )
        return PrioritizedFinding(finding, enrichment, Priority.P2, tuple(rationale))

    rationale.append("Default monitoring priority")
    return PrioritizedFinding(finding, enrichment, Priority.P3, tuple(rationale))
