from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from sbom_ops.domain import lifecycle_evidence as domain
from sbom_ops.domain.asset_registry import (
    AssetRegistrySnapshot,
    RegistryProjectObservation,
    RegistryProjectStatus,
    ReviewedProjectLink,
)

NOW = datetime(2026, 10, 25, tzinfo=UTC)


def context():
    link = ReviewedProjectLink(
        "uuid", "shop-api", "build-a", "shop", "api", "reviewer", NOW.isoformat()
    )
    snapshot = AssetRegistrySnapshot((), (link,))
    project = RegistryProjectObservation(
        "uuid",
        "shop-api",
        "build-a",
        RegistryProjectStatus.MATCHED,
        service_id="shop",
        deployable_id="api",
    )
    item = domain.LifecycleEvidence(
        "shop",
        "api",
        "build",
        "boms/a.json",
        "operator",
        artifact_id="build-a",
        observed_at=NOW,
    )
    return snapshot, project, domain.RecordedEvidence(1, NOW, item)


def test_exact_artifact_matches_without_claiming_runtime() -> None:
    snapshot, project, record = context()
    assert domain.match_lifecycle_evidence(snapshot, project, (record,), now=NOW) == {
        1: "matched"
    }


@pytest.mark.parametrize(
    "change,expected",
    [
        ({"artifact_id": "build-b"}, "different_artifact"),
        ({"observed_at": None}, "observation_unknown"),
        ({"observed_at": NOW + timedelta(seconds=1)}, "future"),
        ({"kind": "unknown"}, "not_build"),
    ],
)
def test_nonmatching_evidence_is_not_silently_used(change, expected) -> None:
    snapshot, project, record = context()
    record = replace(record, evidence=replace(record.evidence, **change))
    assert (
        domain.match_lifecycle_evidence(snapshot, project, (record,), now=NOW)[1]
        == expected
    )


@pytest.mark.parametrize("status", list(RegistryProjectStatus)[1:])
def test_unverified_project_cannot_match(status) -> None:
    snapshot, project, record = context()
    project = replace(project, status=status)
    assert (
        domain.match_lifecycle_evidence(snapshot, project, (record,), now=NOW)[1]
        == "asset_link_unverified"
    )


def test_future_correction_does_not_hide_previous_record() -> None:
    snapshot, project, record = context()
    correction = domain.RecordedEvidence(
        2,
        NOW,
        replace(
            record.evidence,
            supersedes_id=1,
            reason="correction",
            observed_at=NOW + timedelta(days=1),
        ),
    )
    assert domain.match_lifecycle_evidence(
        snapshot, project, (record, correction), now=NOW
    ) == {1: "matched", 2: "future"}
    correction = replace(
        correction, evidence=replace(correction.evidence, observed_at=NOW)
    )
    assert domain.match_lifecycle_evidence(
        snapshot, project, (record, correction), now=NOW
    ) == {1: "superseded", 2: "matched"}


def test_independent_records_are_not_auto_selected() -> None:
    snapshot, project, record = context()
    second = replace(record, record_id=2)
    assert domain.match_lifecycle_evidence(
        snapshot, project, (record, second), now=NOW
    ) == {1: "multiple_candidates", 2: "multiple_candidates"}


def test_correction_chain_is_order_independent() -> None:
    snapshot, project, first = context()
    second = domain.RecordedEvidence(
        2, NOW, replace(first.evidence, supersedes_id=1, reason="first correction")
    )
    third = domain.RecordedEvidence(
        3, NOW, replace(first.evidence, supersedes_id=2, reason="second correction")
    )
    assert domain.match_lifecycle_evidence(
        snapshot, project, (third, second, first), now=NOW
    ) == {1: "superseded", 2: "superseded", 3: "matched"}


@pytest.mark.parametrize(
    "change",
    [
        {"retired_services": ("shop",)},
        {"retired_deployables": (("shop", "api"),)},
        {"revoked_project_uuids": ("uuid",)},
        {"links": ()},
    ],
)
def test_current_snapshot_overrides_stale_matched_observation(change) -> None:
    snapshot, project, record = context()
    assert domain.match_lifecycle_evidence(
        replace(snapshot, **change), project, (record,), now=NOW
    ) == {1: "asset_link_unverified"}
