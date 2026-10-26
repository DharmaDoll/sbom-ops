"""Exact read-only lookup must preserve identity and uncertain asset context."""

from dataclasses import replace

import pytest

from sbom_ops.domain.lookup import LookupQuery, lookup_reviews
from sbom_ops.domain.models import AnalysisState, FindingAssessment, Priority, Severity
from sbom_ops.domain.review import FindingReview


def row(key: str = "first") -> FindingReview:
    return FindingReview(
        FindingAssessment(
            project_uuid="project-a",
            finding_key=key,
            vulnerability_id="CVE-2026-1234",
            vulnerability_source="NVD",
            severity=Severity.HIGH,
            cvss_score=8.0,
            epss_score=None,
            priority=Priority.P2,
            analysis_state=AnalysisState.NOT_AFFECTED,
            is_suppressed=True,
            rationale=("existing decision",),
            component_purl="pkg:pypi/example@1.0",
        ),
        "unlinked",
        None,
        (),
    )


def test_exact_lookup_keeps_duplicate_findings_and_unlinked_suppressed_rows() -> None:
    first = row()
    second = replace(
        row("second"),
        assessment=replace(row("second").assessment, project_uuid="project-b"),
    )
    inputs = (first, second, first)
    results = lookup_reviews(inputs, LookupQuery("cve", "CVE-2026-1234"))
    assert results == inputs
    assert all(a is b for a, b in zip(results, inputs, strict=True))
    assert first.asset is None and first.assessment.is_suppressed


def test_source_and_full_purl_are_exact_not_alias_or_name_matches() -> None:
    original = row()
    alias = replace(
        original,
        assessment=replace(
            original.assessment,
            vulnerability_id="GHSA-example",
            vulnerability_aliases=("CVE-2026-1234",),
        ),
    )
    assert lookup_reviews((alias,), LookupQuery("cve", "CVE-2026-1234")) == ()
    assert (
        lookup_reviews(
            (original,), LookupQuery("vulnerability", "CVE-2026-1234", "OSV")
        )
        == ()
    )
    assert lookup_reviews(
        (original,), LookupQuery("vulnerability", "CVE-2026-1234", "NVD")
    ) == (original,)
    assert lookup_reviews((original,), LookupQuery("purl", "pkg:pypi/example@1.0")) == (
        original,
    )
    assert lookup_reviews((original,), LookupQuery("purl", "pkg:pypi/example")) == ()
    assert (
        lookup_reviews((original,), LookupQuery("purl", "pkg:pypi/example@1.0#src"))
        == ()
    )


@pytest.mark.parametrize(
    "kind,value,source",
    [
        ("bad", "value", None),
        ("cve", "cve-2026-1234", None),
        ("cve", "CVE-2026-123", None),
        ("cve", "CVE-2026-1234", "NVD"),
        ("vulnerability", "ID", None),
        ("vulnerability", "ID", " NVD"),
        ("purl", "example", None),
        ("purl", "pkg:pypi/example\n", None),
        ("purl", "pkg:pypi/" + "x" * 2048, None),
    ],
)
def test_invalid_query_is_rejected(kind: str, value: str, source: str | None) -> None:
    with pytest.raises(ValueError):
        LookupQuery(kind, value, source)
