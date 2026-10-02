from dataclasses import replace

from sbom_ops.config import PriorityConfig
from sbom_ops.domain.models import Enrichment, Finding, Priority, Severity
from sbom_ops.domain.priority import prioritize_finding


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
