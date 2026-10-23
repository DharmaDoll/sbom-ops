import json
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
from sbom_ops.domain.kev import KevSnapshot
from sbom_ops.domain.models import Finding, Severity
from sbom_ops.domain.triage_evidence import (
    TriageEvidenceStatus,
    TriageFactor,
    TriageValue,
)
from sbom_ops.domain.vulnrichment import interpret_vulnrichment
from sbom_ops.services.triage_context import compose_triage_context

NOW = datetime(2026, 10, 23, tzinfo=UTC)


def test_ambiguous_cve_does_not_build_a_reference_context() -> None:
    finding = Finding(
        "project-1",
        "shop/api",
        "app",
        "1",
        "GHSA-synthetic",
        Severity.HIGH,
        8.0,
        (),
        None,
        vulnerability_aliases=("CVE-2026-0001", "CVE-2026-0002"),
    )
    project = RegistryProjectObservation(
        "project-1", "shop/api", "build-1", RegistryProjectStatus.UNLINKED
    )
    result = compose_triage_context(
        finding,
        AssetRegistrySnapshot((), ()),
        project,
        environment="production",
        now=NOW,
    )
    assert result.evidence is None
    assert result.identity.original_id == "GHSA-synthetic"
    assert "multiple_cve_candidates" in result.reasons


@pytest.fixture
def inputs():
    finding = Finding(
        "project-1",
        "shop/api",
        "app",
        "1",
        "GHSA-synthetic",
        Severity.HIGH,
        8.0,
        (),
        None,
        vulnerability_source="GITHUB",
        vulnerability_aliases=("CVE-2026-0001",),
    )
    project = RegistryProjectObservation(
        "project-1",
        "shop/api",
        "build-1",
        RegistryProjectStatus.MATCHED,
        service_id="shop",
        deployable_id="api",
    )
    link = ReviewedProjectLink(
        "project-1",
        "shop/api",
        "build-1",
        "shop",
        "api",
        "operator",
        "2026-10-20T00:00:00Z",
    )
    report = ReportedDeployment(
        "shop",
        "api",
        "production",
        "build-1",
        DeploymentStatus.DEPLOYED,
        ExposureStatus.CONFIRMED,
        "operator",
        "synthetic",
        "2026-10-22T00:00:00Z",
        "2026-10-24T00:00:00Z",
        report_id=1,
    )
    kev = KevSnapshot(
        "https://cisa.example/feed",
        frozenset({"CVE-2026-0001"}),
        NOW - timedelta(hours=1),
        NOW + timedelta(hours=1),
        "fetched",
        "fixture-v1",
        NOW - timedelta(days=1),
        True,
    )
    payload = json.loads(
        (Path(__file__).parents[1] / "fixtures/vulnrichment_synthetic.json").read_text()
    )
    cisa = interpret_vulnrichment(
        payload,
        cve="CVE-2026-0001",
        revision="a" * 40,
        retrieved_at=NOW,
        max_age=timedelta(days=3),
    )
    return dict(
        finding=finding,
        project=project,
        snapshot=AssetRegistrySnapshot((), (link,), (report,)),
        kev=kev,
        cisa=cisa,
        environment="production",
        now=NOW,
    )


def factors(result):
    return {item.factor: item for item in result.evidence.factors}


def test_combines_sources_without_changing_identity_or_clocks(inputs) -> None:
    original = asdict(inputs["finding"])
    result = compose_triage_context(**inputs)
    values = factors(result)
    assert values[TriageFactor.PUBLIC_EXPOSURE].value is TriageValue.YES
    assert values[TriageFactor.KEV].value is TriageValue.YES
    assert values[TriageFactor.AUTOMATABLE].value is TriageValue.YES
    assert values[TriageFactor.TECHNICAL_IMPACT].value is TriageValue.TOTAL
    assert values[TriageFactor.KNOWN_EXPLOITATION].value is TriageValue.UNKNOWN
    assert result.identity.original_id == "GHSA-synthetic"
    assert result.identity.original_source == "GITHUB"
    assert asdict(inputs["finding"]) == original
    assert result.kev is inputs["kev"] and result.cisa is inputs["cisa"]
    assert (
        values[TriageFactor.KEV].observations[0].observed_at == inputs["kev"].checked_at
    )
    assert (
        values[TriageFactor.AUTOMATABLE].observations[0].observed_at
        == inputs["cisa"].assessed_at
    )


@pytest.mark.parametrize(
    "source,factor",
    [
        ("kev", TriageFactor.KEV),
        ("cisa", TriageFactor.AUTOMATABLE),
        ("asset", TriageFactor.PUBLIC_EXPOSURE),
    ],
)
def test_source_expiry_remains_independent(inputs, source, factor) -> None:
    if source == "kev":
        inputs["kev"] = replace(inputs["kev"], expires_at=NOW)
    elif source == "cisa":
        inputs["cisa"] = replace(
            inputs["cisa"],
            observations=tuple(
                replace(item, expires_at=NOW) for item in inputs["cisa"].observations
            ),
        )
    else:
        snapshot = inputs["snapshot"]
        inputs["snapshot"] = replace(
            snapshot,
            deployment_reports=(
                replace(snapshot.deployment_reports[0], expires_at=NOW.isoformat()),
            ),
        )
    values = factors(compose_triage_context(**inputs))
    assert values[factor].status is TriageEvidenceStatus.EXPIRED
    assert values[factor].value is TriageValue.UNKNOWN
    other = TriageFactor.KEV if source != "kev" else TriageFactor.PUBLIC_EXPOSURE
    assert values[other].value is TriageValue.YES


@pytest.mark.parametrize("changes", [{"mode": "stale"}, {"complete": False}])
def test_kev_uncertainty_does_not_become_no(inputs, changes) -> None:
    inputs["kev"] = replace(inputs["kev"], **changes)
    assert (
        factors(compose_triage_context(**inputs))[TriageFactor.KEV].value
        is TriageValue.UNKNOWN
    )


def test_missing_sources_are_unknown(inputs) -> None:
    inputs.update(kev=None, cisa=None)
    result = compose_triage_context(**inputs)
    assert {"kev_unavailable", "cisa_unavailable"} <= set(result.reasons)
    assert factors(result)[TriageFactor.KEV].value is TriageValue.UNKNOWN


def test_cisa_from_future_is_not_applied(inputs) -> None:
    inputs["cisa"] = replace(inputs["cisa"], retrieved_at=NOW + timedelta(seconds=1))
    result = compose_triage_context(**inputs)
    assert "cisa_retrieval_in_future" in result.reasons
    assert factors(result)[TriageFactor.AUTOMATABLE].value is TriageValue.UNKNOWN


@pytest.mark.parametrize("source", ["project", "cisa"])
def test_mismatched_targets_are_rejected(inputs, source) -> None:
    if source == "project":
        inputs[source] = replace(inputs[source], project_uuid="other-project")
    else:
        inputs[source] = replace(inputs[source], cve="CVE-2026-0002")
    with pytest.raises(ValueError):
        compose_triage_context(**inputs)


def test_disabled_kev_validity_is_not_extended(inputs) -> None:
    inputs["kev"] = replace(inputs["kev"], expires_at=inputs["kev"].checked_at)
    result = compose_triage_context(**inputs)
    assert "kev_validity_disabled" in result.reasons
    assert factors(result)[TriageFactor.KEV].value is TriageValue.UNKNOWN


def test_revoked_asset_does_not_hide_valid_vulnerability_evidence(inputs) -> None:
    inputs["snapshot"] = replace(
        inputs["snapshot"], revoked_project_uuids=("project-1",)
    )
    result = compose_triage_context(**inputs)
    assert "asset_link_unverified" in result.reasons
    assert factors(result)[TriageFactor.PUBLIC_EXPOSURE].value is TriageValue.UNKNOWN
    assert factors(result)[TriageFactor.KEV].value is TriageValue.YES


def test_positive_evidence_cannot_resolve_ambiguous_identity(inputs) -> None:
    inputs["finding"] = replace(
        inputs["finding"], vulnerability_aliases=("CVE-2026-0001", "CVE-2026-0002")
    )
    result = compose_triage_context(**inputs)
    assert result.evidence is None
    assert result.identity.candidates == ("CVE-2026-0001", "CVE-2026-0002")
