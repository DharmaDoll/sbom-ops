import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from sbom_ops.domain.triage_evidence import (
    AssetEvidenceScope,
    EvidenceReview,
    TriageEvidenceStatus,
    TriageFactor,
    TriageObservation,
    TriageSubject,
    TriageValue,
    VulnerabilityIdentity,
    build_triage_evidence,
)

NOW = datetime(2026, 10, 22, 0, tzinfo=UTC)
IDENTITY = VulnerabilityIdentity("CVE-2026-0001", "NVD")
ASSET = AssetEvidenceScope("shop", "api", "production", "build-1", "project-1")
SUBJECT = TriageSubject("finding-1", IDENTITY, ASSET, True)
CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/triage_evidence_cases.json").read_text()
)


def observation(
    factor: TriageFactor = TriageFactor.KEV,
    value: TriageValue = TriageValue.YES,
) -> TriageObservation:
    return TriageObservation(
        evidence_id=factor.value,
        vulnerability=IDENTITY,
        factor=factor,
        value=value,
        source="synthetic-source",
        source_record="synthetic-record",
        source_revision="fixture-v1",
        observed_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=1),
        asset=ASSET if factor is TriageFactor.PUBLIC_EXPOSURE else None,
    )


def test_expired_kev_is_not_a_negative_and_keeps_provenance() -> None:
    observation = TriageObservation(
        evidence_id="kev-row-1",
        vulnerability=IDENTITY,
        factor=TriageFactor.KEV,
        value=TriageValue.YES,
        source="synthetic-kev",
        source_record="CVE-2026-0001",
        source_revision="fixture-v1",
        observed_at=NOW - timedelta(days=1),
        expires_at=NOW,
    )
    result = build_triage_evidence(
        TriageSubject("finding-1", IDENTITY), (observation,), now=NOW
    )
    kev = next(item for item in result.factors if item.factor is TriageFactor.KEV)
    assert kev.status is TriageEvidenceStatus.EXPIRED
    assert kev.value is TriageValue.UNKNOWN
    assert kev.observations == (observation,)
    assert kev.reasons == ("expired_observation",)
    payload = result.as_dict()["factors"][1]
    assert payload["observations"][0]["reported_value"] == "yes"
    assert payload["observations"][0]["source_revision"] == "fixture-v1"


@pytest.mark.parametrize("factor", list(TriageFactor))
@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_synthetic_evidence_cases(factor: TriageFactor, case: dict) -> None:
    def value(raw: str) -> TriageValue:
        if factor is TriageFactor.TECHNICAL_IMPACT:
            raw = {"yes": "total", "no": "partial"}.get(raw, raw)
        return TriageValue(raw)

    observations = tuple(
        replace(
            observation(factor, value(raw)),
            evidence_id=f"evidence-{index}",
            source_revision=f"fixture-v{index}",
            observed_at=NOW + timedelta(days=start),
            expires_at=NOW + timedelta(days=end),
        )
        for index, (raw, start, end) in enumerate(case["observations"])
    )
    result = build_triage_evidence(SUBJECT, observations, now=NOW)
    selected = next(item for item in result.factors if item.factor is factor)
    assert selected.status.value == case["status"]
    assert selected.value == value(case["value"])
    assert selected.reasons == tuple(case["reasons"])
    assert selected.observations == observations
    assert len(result.factors) == 5
    assert all(
        item.value is TriageValue.UNKNOWN
        for item in result.factors
        if item.factor is not factor
    )
    assert result == build_triage_evidence(
        SUBJECT, tuple(reversed(observations)), now=NOW
    )
    assert json.loads(json.dumps(result.as_dict())) == result.as_dict()


@pytest.mark.parametrize(
    "field",
    ["service_id", "deployable_id", "environment", "artifact_id", "project_uuid"],
)
def test_public_exposure_cannot_cross_asset_scope(field: str) -> None:
    other_asset = replace(ASSET, **{field: "other"})
    result = build_triage_evidence(
        SUBJECT,
        (replace(observation(TriageFactor.PUBLIC_EXPOSURE), asset=other_asset),),
        now=NOW,
    )
    exposure = result.factors[0]
    assert exposure.value is TriageValue.UNKNOWN
    assert exposure.observations == ()
    assert exposure.reasons == ("no_matching_evidence",)


def test_unverified_asset_keeps_report_but_does_not_adopt_exposure() -> None:
    report = observation(TriageFactor.PUBLIC_EXPOSURE, TriageValue.NO)
    result = build_triage_evidence(
        replace(SUBJECT, asset_link_verified=False), (report,), now=NOW
    )
    assert result.factors[0].status is TriageEvidenceStatus.UNKNOWN
    assert result.factors[0].value is TriageValue.UNKNOWN
    assert result.factors[0].observations == (report,)
    assert result.factors[0].reasons == ("asset_link_unverified",)


@pytest.mark.parametrize(
    "identity",
    [
        VulnerabilityIdentity("CVE-2026-0002", "NVD"),
        VulnerabilityIdentity("CVE-2026-0001", "OTHER"),
        VulnerabilityIdentity("cve-2026-0001", "NVD"),
        VulnerabilityIdentity("GHSA-synthetic", "GITHUB"),
    ],
)
def test_identity_requires_exact_id_and_namespace(
    identity: VulnerabilityIdentity,
) -> None:
    result = build_triage_evidence(
        replace(SUBJECT, vulnerability=identity), (observation(),), now=NOW
    )
    assert result.subject.vulnerability == identity
    assert all(item.value is TriageValue.UNKNOWN for item in result.factors)
    assert all(not item.observations for item in result.factors)


def test_non_cve_identity_is_preserved_without_alias_inference() -> None:
    identity = VulnerabilityIdentity("GHSA-synthetic", "GITHUB")
    result = build_triage_evidence(
        replace(SUBJECT, vulnerability=identity),
        (replace(observation(), vulnerability=identity),),
        now=NOW,
    )
    assert result.as_dict()["vulnerability"] == {
        "identifier": "GHSA-synthetic",
        "namespace": "GITHUB",
    }
    assert result.factors[1].value is TriageValue.YES


@pytest.mark.parametrize(
    ("offset", "expected"),
    [(-1, "future"), (0, "known"), (1, "known"), (2, "expired")],
)
def test_validity_interval_and_timezone(offset: int, expected: str) -> None:
    report = replace(
        observation(), observed_at=NOW, expires_at=NOW + timedelta(seconds=2)
    )
    at = (NOW + timedelta(seconds=offset)).astimezone(timezone(timedelta(hours=9)))
    assert report.status_at(at).value == expected


def test_review_is_metadata_not_a_validity_extension() -> None:
    review = EvidenceReview("synthetic-reviewer", "source report checked", NOW)
    report = replace(observation(), review=review)
    assert report.status_at(NOW - timedelta(seconds=1)) is TriageEvidenceStatus.FUTURE
    assert report.status_at(NOW) is TriageEvidenceStatus.KNOWN
    assert report.status_at(report.expires_at) is TriageEvidenceStatus.EXPIRED
    result = build_triage_evidence(SUBJECT, (report,), now=NOW)
    payload = result.as_dict()
    saved = payload["factors"][1]["observations"][0]
    assert saved["review"] == {
        "reviewer": "synthetic-reviewer",
        "reason": "source report checked",
        "reviewed_at": NOW.isoformat(),
    }
    assert saved["source"] == "synthetic-source"
    assert saved["source_record"] == "synthetic-record"
    assert saved["observed_at"] == report.observed_at.isoformat()
    assert saved["expires_at"] == report.expires_at.isoformat()
    later = build_triage_evidence(SUBJECT, (report,), now=report.expires_at)
    assert later.factors[1].status is TriageEvidenceStatus.EXPIRED
    assert result.as_dict() == payload
    with pytest.raises(FrozenInstanceError):
        report.value = TriageValue.NO


@pytest.mark.parametrize(
    "changes",
    [
        {"source": ""},
        {"source_record": " value"},
        {"source_revision": "a\nb"},
        {"evidence_id": "x" * 2049},
        {"value": "yes"},
        {"value": True},
        {"value": TriageValue.TOTAL},
        {"factor": "published_poc"},
        {"factor": TriageFactor.TECHNICAL_IMPACT},
        {"vulnerability": "CVE-2026-0001"},
        {"observed_at": NOW.replace(tzinfo=None)},
        {"expires_at": "tomorrow"},
        {"expires_at": NOW - timedelta(days=1)},
        {"asset": ASSET},
        {"review": {}},
        {"review": EvidenceReview("reviewer", "reason", NOW + timedelta(days=2))},
    ],
)
def test_invalid_observation_is_rejected(changes: dict) -> None:
    with pytest.raises(ValueError):
        replace(observation(), **changes)


def test_public_exposure_requires_typed_asset() -> None:
    with pytest.raises(ValueError, match="exact asset scope"):
        replace(observation(), factor=TriageFactor.PUBLIC_EXPOSURE)


@pytest.mark.parametrize(
    "changes",
    [
        {"asset_link_verified": "false"},
        {"asset_link_verified": 1},
        {"asset": None},
        {"asset": {}},
        {"vulnerability": "CVE-2026-0001"},
    ],
)
def test_invalid_subject_is_rejected(changes: dict) -> None:
    with pytest.raises(ValueError):
        replace(SUBJECT, **changes)


@pytest.mark.parametrize(
    "reports", [[observation()], (None,), (observation(), observation())]
)
def test_invalid_evidence_collection_is_rejected(reports: object) -> None:
    with pytest.raises(ValueError):
        build_triage_evidence(SUBJECT, reports, now=NOW)


def test_invalid_clock_and_subject_are_rejected() -> None:
    with pytest.raises(ValueError):
        build_triage_evidence(SUBJECT, (), now=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError):
        build_triage_evidence({}, (), now=NOW)


def test_invalid_text_is_not_echoed_in_error() -> None:
    with pytest.raises(ValueError) as error:
        replace(observation(), source="private-value\n")
    assert "private-value" not in str(error.value)


def test_dst_fold_uses_instant_not_repeated_wall_clock() -> None:
    zone = ZoneInfo("America/New_York")
    start = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=0)
    end = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=1)
    report = replace(observation(), observed_at=start, expires_at=end)
    assert report.status_at(start) is TriageEvidenceStatus.KNOWN
    assert report.status_at(end) is TriageEvidenceStatus.EXPIRED
    assert report.status_at(end.replace(fold=0)) is TriageEvidenceStatus.FUTURE
    with pytest.raises(ValueError, match="expiry must follow"):
        replace(report, observed_at=end, expires_at=start)
