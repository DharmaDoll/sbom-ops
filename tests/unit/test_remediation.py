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
from sbom_ops.domain.remediation import build_remediation_groups
from sbom_ops.domain.review import FindingReview, build_review_queue


def row(build: str = "v1") -> FindingReview:
    return FindingReview(
        FindingAssessment(
            project_uuid=f"project-{build}",
            finding_key=f"finding-{build}",
            vulnerability_id="CVE-2026-1000",
            vulnerability_source="NVD",
            severity=Severity.HIGH,
            cvss_score=8.0,
            epss_score=None,
            priority=Priority.P2,
            analysis_state=AnalysisState.NOT_SET,
            is_suppressed=False,
            rationale=("CVSS 8.0",),
            component_purl="pkg:npm/example@1.0.0",
            component_name="example",
            component_version="1.0.0",
        ),
        "matched",
        RegistryProjectObservation(
            f"project-{build}",
            "checkout/web",
            build,
            RegistryProjectStatus.MATCHED,
            service_id="checkout",
            deployable_id="web",
            owner="team-checkout",
        ),
        (
            RegistryDeploymentObservation(
                f"project-{build}",
                "production",
                build,
                RegistryDeploymentStatus.EXPIRED,
            ),
        ),
    )


def test_multiple_builds_share_a_stable_repair_key_without_losing_findings() -> None:
    first, second = row(), row("v2")
    groups = build_remediation_groups((first, second))
    assert len(groups) == 1
    group = groups[0]
    assert group.key.startswith("repair-v1:")
    assert group.key == build_remediation_groups((second,))[0].key
    assert group.key == build_remediation_groups((first,))[0].key
    assert build_remediation_groups((second, first)) == groups
    assert group.finding_keys == ("finding-v1", "finding-v2")
    payload = group.as_dict()
    assert payload["finding_count"] == 2
    assert payload["project_uuids"] == ["project-v1", "project-v2"]
    assert payload["members"] == [first.as_dict(), second.as_dict()]
    assert payload["members"][1]["environments"][0]["status"] == "expired"


@pytest.mark.parametrize(
    "field,value",
    [
        ("service_id", "another-service"),
        ("deployable_id", "worker"),
    ],
)
def test_separate_repair_ownership_boundaries(field: str, value: str) -> None:
    first, second = row(), row("v2")
    second = replace(second, asset=replace(second.asset, **{field: value}))
    assert len(build_remediation_groups((first, second))) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("component_purl", "pkg:npm/other@1.0.0"),
        ("component_purl", "pkg:pypi/example@1.0.0"),
        ("component_purl", "pkg:npm/example@2.0.0"),
        ("component_purl", "pkg:npm/example@1.0.0?arch=arm64"),
        ("component_purl", "pkg:npm/example@1.0.0#other/path"),
        ("vulnerability_source", "OSV"),
        ("vulnerability_id", "CVE-2026-2000"),
        ("vulnerability_id", "GHSA-abcd-1234-5678"),
    ],
)
def test_package_and_advisory_identities_must_match_exactly(
    field: str, value: str
) -> None:
    first, second = row(), row("v2")
    second = replace(
        second,
        assessment=replace(
            second.assessment,
            **{field: value},
            vulnerability_aliases=(first.assessment.vulnerability_id,),
        ),
    )
    assert len(build_remediation_groups((first, second))) == 2


@pytest.mark.parametrize("status", [s for s in RegistryProjectStatus if s != "matched"])
def test_unverified_assets_are_never_grouped_across_builds(
    status: RegistryProjectStatus,
) -> None:
    first, second = row(), row("v2")
    rows = build_review_queue(
        (first.assessment, second.assessment),
        RegistrySnapshotStatus.LOADED,
        (replace(first.asset, status=status), replace(second.asset, status=status)),
        (),
    )
    groups = build_remediation_groups(rows)
    assert len(groups) == 2
    assert all(group.basis == "asset_not_verified" for group in groups)
    assert all(group.service_id is None for group in groups)


def test_no_registry_never_uses_names_or_supplied_unrequested_observations() -> None:
    first, second = row(), row("v2")
    rows = build_review_queue(
        (first.assessment, second.assessment),
        RegistrySnapshotStatus.NOT_REQUESTED,
        (first.asset, second.asset),
        (),
    )
    assert len(build_remediation_groups(rows)) == 2


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("component_purl", None, "package_identity_missing"),
        ("component_purl", "", "package_identity_missing"),
        ("component_purl", "pkg:", "package_identity_missing"),
        ("component_purl", "example@1.0.0", "package_identity_missing"),
        ("component_purl", "pkg:npm/example@1.0.0\n", "package_identity_missing"),
        ("vulnerability_source", None, "vulnerability_identity_missing"),
        ("vulnerability_id", " ", "vulnerability_identity_missing"),
    ],
)
def test_incomplete_identity_keeps_each_finding(
    field: str, value: str | None, reason: str
) -> None:
    rows = tuple(
        replace(item, assessment=replace(item.assessment, **{field: value}))
        for item in (row(), row("v2"))
    )
    groups = build_remediation_groups(rows)
    assert len(groups) == 2
    assert all(group.basis == reason for group in groups)
    assert {key for group in groups for key in group.finding_keys} == {
        "finding-v1",
        "finding-v2",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("service_id", None),
        ("deployable_id", ""),
        ("service_id", "bad\nidentifier"),
    ],
)
def test_missing_registry_coordinates_do_not_become_shared_unknown_identity(
    field: str, value: str | None
) -> None:
    rows = tuple(
        replace(item, asset=replace(item.asset, **{field: value}))
        for item in (row(), row("v2"))
    )
    groups = build_remediation_groups(rows)
    assert len(groups) == 2
    assert all(group.basis == "asset_identity_missing" for group in groups)


def test_wrong_project_observation_cannot_supply_a_service() -> None:
    first = row()
    malformed = replace(first, asset=row("v2").asset)
    assert build_remediation_groups((malformed,))[0].basis == "asset_not_verified"


def test_owner_priority_and_analysis_changes_do_not_change_work_identity() -> None:
    first, second = row(), row("v2")
    second = replace(
        second,
        asset=replace(second.asset, owner="new-team"),
        assessment=replace(
            second.assessment,
            priority=Priority.P0,
            analysis_state=AnalysisState.NOT_AFFECTED,
            is_suppressed=True,
        ),
    )
    group = build_remediation_groups((first, second))[0]
    assert group.key == build_remediation_groups((first,))[0].key
    assert group.highest_observed_priority is Priority.P0
    assert group.members == (second, first)
    assert group.members[0].assessment.is_suppressed is True
    assert group.members[1].assessment.priority is Priority.P2


def test_duplicate_observation_does_not_inflate_finding_count_or_erase_evidence() -> (
    None
):
    item = row()
    group = build_remediation_groups((item, item))[0]
    assert group.as_dict()["finding_count"] == 1
    assert len(group.members) == 2
    assert build_remediation_groups(()) == ()
