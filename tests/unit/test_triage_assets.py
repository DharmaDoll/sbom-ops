from dataclasses import replace
from datetime import UTC, datetime

import pytest

from sbom_ops.domain.advisory import ExposureStatus
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegistryProjectObservation,
    RegistryProjectStatus,
    ReportedDeployment,
    ReviewedProjectLink,
)
from sbom_ops.domain.assets import DeploymentStatus
from sbom_ops.domain.triage_assets import join_asset_evidence
from sbom_ops.domain.triage_evidence import (
    TriageEvidenceStatus,
    TriageFactor,
    TriageSubject,
    TriageValue,
    VulnerabilityIdentity,
    build_triage_evidence,
)

NOW = datetime(2026, 10, 23, tzinfo=UTC)
IDENTITY = VulnerabilityIdentity("CVE-2026-0001", "CVE")
PROJECT = RegistryProjectObservation(
    "project-1",
    "shop/api",
    "build-1",
    RegistryProjectStatus.MATCHED,
    service_id="shop",
    deployable_id="api",
)
LINK = ReviewedProjectLink(
    "project-1",
    "shop/api",
    "build-1",
    "shop",
    "api",
    "operator",
    "2026-10-20T00:00:00Z",
)
REPORT = ReportedDeployment(
    "shop",
    "api",
    "production",
    "build-1",
    DeploymentStatus.DEPLOYED,
    ExposureStatus.CONFIRMED,
    "operator",
    "synthetic ingress review",
    "2026-10-22T00:00:00Z",
    "2026-10-25T00:00:00Z",
    report_id=1,
)


def test_future_correction_does_not_hide_current_claim() -> None:
    future = replace(
        REPORT,
        report_id=2,
        supersedes_report_id=1,
        observed_at="2026-10-24T00:00:00Z",
        exposure_status=ExposureStatus.REJECTED,
    )
    snapshot = AssetRegistrySnapshot((), (LINK,), (REPORT, future))
    result = join_asset_evidence(
        snapshot, PROJECT, IDENTITY, environment="production", now=NOW
    )
    assert result.reports == (REPORT,)
    assert result.pending_corrections == (future,)
    assert result.observations[0].value is TriageValue.YES


@pytest.mark.parametrize(
    "day,expected",
    [(24, TriageEvidenceStatus.KNOWN), (25, TriageEvidenceStatus.EXPIRED)],
)
def test_correction_never_resurrects_previous(day, expected) -> None:
    successor = replace(
        REPORT,
        report_id=2,
        supersedes_report_id=1,
        observed_at="2026-10-24T00:00:00Z",
        exposure_status=ExposureStatus.REJECTED,
    )
    at = datetime(2026, 10, day, tzinfo=UTC)
    result = join_asset_evidence(
        AssetRegistrySnapshot((), (LINK,), (REPORT, successor)),
        PROJECT,
        IDENTITY,
        environment="production",
        now=at,
    )
    assert result.reports == (successor,)
    assert result.pending_corrections == ()
    context = build_triage_evidence(
        TriageSubject("finding-1", IDENTITY, result.asset, True),
        result.observations,
        now=at,
    )
    factor = next(
        item for item in context.factors if item.factor is TriageFactor.PUBLIC_EXPOSURE
    )
    assert factor.status is expected
    assert factor.value is (TriageValue.NO if day == 24 else TriageValue.UNKNOWN)


@pytest.mark.parametrize(
    "changes",
    [
        {"revoked_project_uuids": ("project-1",)},
        {"retired_services": ("shop",)},
        {"retired_deployables": (("shop", "api"),)},
        {"links": ()},
        {"links": (replace(LINK, project_version="build-other"),)},
        {"links": (replace(LINK, reviewed_at="2026-10-24T00:00:00Z"),)},
        {"links": (LINK, LINK)},
    ],
)
def test_invalid_link_does_not_borrow_claims(changes) -> None:
    snapshot = replace(AssetRegistrySnapshot((), (LINK,), (REPORT,)), **changes)
    result = join_asset_evidence(
        snapshot, PROJECT, IDENTITY, environment="production", now=NOW
    )
    assert result.asset is None and result.observations == ()
    assert result.reasons == ("asset_link_unverified",)


@pytest.mark.parametrize(
    "changes",
    [
        {"environment": "staging"},
        {"artifact_id": "build-other"},
        {"service_id": "other"},
        {"deployable_id": "worker"},
    ],
)
def test_exact_scope_required(changes) -> None:
    report = replace(REPORT, **changes)
    result = join_asset_evidence(
        AssetRegistrySnapshot((), (LINK,), (report,)),
        PROJECT,
        IDENTITY,
        environment="production",
        now=NOW,
    )
    assert result.observations == () and result.reports == ()


@pytest.mark.parametrize(
    "deployment,exposure,reason",
    [
        (
            DeploymentStatus.NOT_DEPLOYED,
            ExposureStatus.REJECTED,
            "deployment_not_confirmed",
        ),
        (DeploymentStatus.UNKNOWN, ExposureStatus.UNKNOWN, "deployment_not_confirmed"),
        (DeploymentStatus.DEPLOYED, ExposureStatus.CONFLICT, "exposure_conflict"),
    ],
)
def test_unconfirmed_is_not_nonpublic(deployment, exposure, reason) -> None:
    report = replace(REPORT, deployment_status=deployment, exposure_status=exposure)
    result = join_asset_evidence(
        AssetRegistrySnapshot((), (LINK,), (report,)),
        PROJECT,
        IDENTITY,
        environment="production",
        now=NOW,
    )
    assert result.observations[0].value is TriageValue.UNKNOWN
    assert reason in result.reasons
    assert result.reports[0].evidence == REPORT.evidence
    assert result.reports[0].reviewer == REPORT.reviewer
    assert result.observations[0].observed_at.isoformat() == "2026-10-22T00:00:00+00:00"


def test_opposing_current_claims_remain_conflict() -> None:
    other = replace(REPORT, report_id=2, exposure_status=ExposureStatus.REJECTED)
    result = join_asset_evidence(
        AssetRegistrySnapshot((), (LINK,), (other, REPORT)),
        PROJECT,
        IDENTITY,
        environment="production",
        now=NOW,
    )
    context = build_triage_evidence(
        TriageSubject("finding-1", IDENTITY, result.asset, True),
        result.observations,
        now=NOW,
    )
    factor = next(
        item for item in context.factors if item.factor is TriageFactor.PUBLIC_EXPOSURE
    )
    assert factor.status is TriageEvidenceStatus.CONFLICT
    assert factor.value is TriageValue.UNKNOWN
    assert result.reports == (REPORT, other)


@pytest.mark.parametrize("report_id", [None, 0, True])
def test_persisted_report_identity_required(report_id) -> None:
    with pytest.raises(ValueError, match="unique positive IDs"):
        join_asset_evidence(
            AssetRegistrySnapshot((), (LINK,), (replace(REPORT, report_id=report_id),)),
            PROJECT,
            IDENTITY,
            environment="production",
            now=NOW,
        )
