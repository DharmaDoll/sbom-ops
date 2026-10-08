from dataclasses import replace

from sbom_ops.config import PriorityConfig
from sbom_ops.domain.advisory import (
    EvidenceFreshness,
    EvidenceOutcome,
    VulnerabilityEvidenceObservation,
)
from sbom_ops.domain.models import (
    AnalysisState,
    Enrichment,
    Finding,
    FindingAssessment,
    Priority,
    Severity,
)
from sbom_ops.domain.priority import order_assessments_for_review, prioritize_finding


def make_finding(
    severity: Severity = Severity.MEDIUM,
    cvss_score: float | None = None,
) -> Finding:
    return Finding(
        project_uuid="project-1",
        project_name="service-a",
        component_name="openssl",
        component_version="1.0.0",
        vulnerability_id="CVE-2026-0001",
        severity=severity,
        cvss_score=cvss_score,
        cwes=(),
        description=None,
    )


def test_kev_match_is_p0() -> None:
    prioritized = prioritize_finding(
        make_finding(),
        Enrichment(in_kev=True, epss_score=None),
        PriorityConfig(),
    )
    assert prioritized.priority == Priority.P0


def test_critical_is_p1() -> None:
    prioritized = prioritize_finding(
        make_finding(severity=Severity.CRITICAL),
        Enrichment(in_kev=False, epss_score=None),
        PriorityConfig(),
    )
    assert prioritized.priority == Priority.P1


def test_high_epss_is_p1() -> None:
    prioritized = prioritize_finding(
        make_finding(),
        Enrichment(in_kev=False, epss_score=0.9),
        PriorityConfig(p1_epss_threshold=0.7),
    )
    assert prioritized.priority == Priority.P1


def test_high_cvss_is_p2() -> None:
    prioritized = prioritize_finding(
        make_finding(cvss_score=8.2),
        Enrichment(in_kev=False, epss_score=0.1),
        PriorityConfig(p2_cvss_threshold=7.0),
    )
    assert prioritized.priority == Priority.P2


def test_cvss_rationale_names_selected_version() -> None:
    prioritized = prioritize_finding(
        replace(make_finding(cvss_score=8.2), cvss_version="CVSSv4"),
        Enrichment(in_kev=False, epss_score=0.1),
        PriorityConfig(p2_cvss_threshold=7.0),
    )

    assert prioritized.priority == Priority.P2
    assert prioritized.rationale == ("CVSSv4 8.2 >= 7.0",)


def test_default_is_p3() -> None:
    prioritized = prioritize_finding(
        make_finding(severity=Severity.HIGH),
        Enrichment(in_kev=False, epss_score=None),
        PriorityConfig(),
    )
    assert prioritized.priority == Priority.P3
    assert prioritized.rationale == (
        "Default monitoring priority",
        "EPSS unavailable",
        "CVSS unavailable; severity label is not used as a score fallback",
    )


def test_default_rationale_explains_configured_threshold_misses() -> None:
    prioritized = prioritize_finding(
        make_finding(severity=Severity.HIGH, cvss_score=6.4),
        Enrichment(in_kev=False, epss_score=0.2),
        PriorityConfig(p1_epss_threshold=0.8, p2_cvss_threshold=7.5),
    )

    assert prioritized.priority == Priority.P3
    assert prioritized.rationale == (
        "Default monitoring priority",
        "EPSS 0.2000 < 0.8000 threshold",
        "CVSS 6.4 < 7.5 threshold",
    )


def assessment(key: str, *, poc: bool = False, cvss: float = 8.0) -> FindingAssessment:
    observation = (
        VulnerabilityEvidenceObservation(
            vulnerability_id="CVE-2026-0001",
            source="lookup",
            signal="published_poc",
            outcome=EvidenceOutcome.AVAILABLE,
            observed_at="2026-10-07T00:00:00Z",
            source_revision=None,
            freshness=EvidenceFreshness.FRESH,
            record_count=1,
            complete=True,
            expires_at="2099-01-01T00:00:00Z",
        ),
    )
    return FindingAssessment(
        project_uuid="project-1",
        finding_key=key,
        vulnerability_id="CVE-2026-0001",
        vulnerability_source="NVD",
        severity=Severity.HIGH,
        cvss_score=cvss,
        epss_score=0.2,
        priority=Priority.P2,
        analysis_state=AnalysisState.NOT_SET,
        is_suppressed=False,
        rationale=("CVSS 8.0",),
        advisory_observations=observation if poc else (),
    )


def test_review_order_only_promotes_reported_poc_among_equal_risk() -> None:
    no_poc = assessment("no-poc")
    unrelated = assessment("different-cvss", cvss=8.1)
    with_poc = assessment("with-poc", poc=True)
    same_after = assessment("same-after")

    ordered = order_assessments_for_review((no_poc, unrelated, with_poc, same_after))

    assert [item.finding_key for item in ordered] == [
        "with-poc",
        "different-cvss",
        "no-poc",
        "same-after",
    ]
    assert [item.priority for item in ordered] == [Priority.P2] * 4
