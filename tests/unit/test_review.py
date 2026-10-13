from dataclasses import replace

import pytest

from sbom_ops.domain.asset_registry import (
    RegistryDeploymentObservation,
    RegistryDeploymentStatus,
    RegistryProjectObservation,
    RegistryProjectStatus,
    RegistrySnapshotStatus,
)
from sbom_ops.domain.models import AnalysisState, FindingAssessment, Priority, Severity
from sbom_ops.domain.review import build_review_queue


def assessment(key: str = "finding-1") -> FindingAssessment:
    return FindingAssessment(
        project_uuid="project-1",
        finding_key=key,
        vulnerability_id="GHSA-abcd-1234-5678",
        vulnerability_source="GITHUB",
        severity=Severity.HIGH,
        cvss_score=8.0,
        epss_score=None,
        priority=Priority.P2,
        analysis_state=AnalysisState.NOT_AFFECTED,
        is_suppressed=True,
        rationale=("CVSS 8.0 >= 7.0",),
    )


def project() -> RegistryProjectObservation:
    return RegistryProjectObservation(
        "project-1",
        "checkout/web",
        "v1",
        RegistryProjectStatus.MATCHED,
        service_id="checkout",
        deployable_id="web",
        owner="checkout-team",
    )


@pytest.mark.parametrize("status", list(RegistryDeploymentStatus))
def test_review_preserves_each_environment_status_and_non_cve_finding(status) -> None:
    environments = tuple(
        RegistryDeploymentObservation("project-1", env, "v1", status)
        for env in ("production", "development")
    )
    finding = assessment()
    rows = build_review_queue(
        (finding,), RegistrySnapshotStatus.LOADED, (project(),), environments
    )
    assert len(rows) == 1
    assert rows[0].assessment is finding
    payload = rows[0].as_dict()
    assert payload["asset"]["owner"] == "checkout-team"
    assert payload["vulnerability_id"] == finding.vulnerability_id
    assert payload["is_suppressed"] is True
    assert payload["analysis_state"] == "NOT_AFFECTED"
    assert payload["priority"] == "P2"
    assert len(payload["environments"]) == 2
    assert all(item["status"] == status.value for item in payload["environments"])


@pytest.mark.parametrize(
    "status",
    [
        RegistryProjectStatus.UNLINKED,
        RegistryProjectStatus.IDENTITY_CHANGED,
        RegistryProjectStatus.AMBIGUOUS,
        RegistryProjectStatus.RETIRED,
        RegistryProjectStatus.REVOKED,
    ],
)
def test_unverified_links_never_borrow_owner_or_environment(status) -> None:
    rows = build_review_queue(
        (assessment(),),
        RegistrySnapshotStatus.LOADED,
        (replace(project(), status=status),),
        (
            RegistryDeploymentObservation(
                "project-1", "production", "v1", RegistryDeploymentStatus.REPORTED
            ),
        ),
    )
    assert rows[0].asset_status == status.value
    assert rows[0].asset is None
    assert rows[0].environments == ()


def test_missing_and_ambiguous_observations_fail_closed_without_losing_findings() -> (
    None
):
    findings = (assessment(), replace(assessment("finding-2"), project_uuid="other"))
    rows = build_review_queue(
        findings, RegistrySnapshotStatus.LOADED, (project(), project()), ()
    )
    assert [row.asset_status for row in rows] == ["ambiguous", "unlinked"]
    assert all(row.asset is None for row in rows)
    # Without a requested registry, even observations supplied by a caller are ignored.
    rows = build_review_queue(
        findings, RegistrySnapshotStatus.NOT_REQUESTED, (project(),), ()
    )
    assert [row.asset_status for row in rows] == ["not_requested"] * 2
    assert all(row.asset is None for row in rows)


def test_same_vulnerability_on_different_components_is_not_collapsed() -> None:
    rows = build_review_queue(
        (assessment(), assessment("finding-2")),
        RegistrySnapshotStatus.NOT_REQUESTED,
        (),
        (),
    )
    assert [row.assessment.finding_key for row in rows] == ["finding-1", "finding-2"]
    assert build_review_queue((), RegistrySnapshotStatus.LOADED, (), ()) == ()
